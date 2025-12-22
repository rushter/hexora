use ruff_python_ast::token::{TokenKind, Tokens};
use ruff_python_ast::visitor::source_order::*;
use ruff_python_ast::*;
use ruff_python_stdlib::builtins::{MAGIC_GLOBALS, python_builtins};
use ruff_text_size::Ranged;
use std::collections::HashMap;

use crate::indexer::model::{NodeId, SemanticModel};
use crate::indexer::name::QualifiedName;
use crate::indexer::scope::{BindingKind, Scope, ScopeKind, SymbolBinding};

use crate::indexer::taint::{TaintKind, TaintState};
use std::sync::atomic::{AtomicU32, Ordering};

const PYTHON_MINOR_VERSION: u8 = 14;

pub struct NodeIndexer<'a> {
    pub model: SemanticModel<'a>,
    pub(crate) index: AtomicU32,
    pub(crate) scope_stack: Vec<Scope<'a>>,
}

impl<'a> Default for NodeIndexer<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> NodeIndexer<'a> {
    pub fn new() -> Self {
        let mut this = Self {
            index: AtomicU32::new(0),
            model: SemanticModel::new(),
            scope_stack: Vec::with_capacity(32),
        };
        this.push_scope(ScopeKind::Module);
        this.bind_builtins();
        this
    }

    pub(crate) fn current_scope_mut(&mut self) -> &mut Scope<'a> {
        self.scope_stack
            .last_mut()
            .expect("there is always at least one scope")
    }

    fn bind_builtins(&mut self) {
        let mut names: Vec<&str> = python_builtins(PYTHON_MINOR_VERSION, false).collect();
        names.extend(MAGIC_GLOBALS);
        names.push("builtins");

        let global_scope = self
            .scope_stack
            .first_mut()
            .expect("global scope always present");

        for name in names {
            global_scope
                .symbols
                .insert(name.to_string(), SymbolBinding::builtin());
        }

        // Reserve indices <1000 for builtins / special cases.
        self.index.store(1000, Ordering::Relaxed);
    }

    pub fn index_comments(&mut self, tokens: &Tokens) {
        for token in tokens {
            if token.kind() == TokenKind::Comment {
                self.model.comments.push(token.range());
            }
        }
    }

    pub fn clear_state(&mut self) {
        self.model.clear();
        self.scope_stack.clear();
        self.push_scope(ScopeKind::Module);
        self.bind_builtins();
    }

    pub fn handle_stmt_pre(&mut self, stmt: &'a Stmt) {
        self.visit_node(stmt);

        match stmt {
            Stmt::ClassDef(_) => {
                self.push_scope(ScopeKind::Class);
            }
            Stmt::FunctionDef(_) => {
                self.push_scope(ScopeKind::Function);
            }
            Stmt::Import(import_stmt) => {
                self.handle_import_stmt(import_stmt);
            }
            Stmt::ImportFrom(import_from_stmt) => {
                self.handle_import_from_stmt(import_from_stmt);
            }
            _ => {}
        }
    }

    pub fn handle_stmt_post(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::ClassDef(_) => {
                self.pop_scope();
            }
            Stmt::FunctionDef(func) => {
                self.pop_scope();
                let symbols = &mut self.current_scope_mut().symbols;
                symbols.insert(func.name.to_string(), SymbolBinding::function(func));
            }
            Stmt::Assign(assign) => {
                self.handle_assign_stmt(assign);
            }
            Stmt::AugAssign(aug_assign) => {
                self.handle_aug_assign_stmt(aug_assign);
            }
            Stmt::Expr(expr_stmt) => {
                self.handle_expr_stmt(expr_stmt);
            }
            _ => {}
        }
    }

    fn handle_expr_stmt(&mut self, _expr_stmt: &'a StmtExpr) {}

    fn handle_method_call_mutation(&mut self, expr: &'a Expr, call: &ExprCall) {
        if let Some((receiver, taint)) =
            crate::indexer::taint::get_method_mutation_taint(call, |e| self.get_taint(e))
        {
            match receiver {
                Expr::Name(name) => {
                    if let Some(symbol) = self.current_scope_mut().symbols.get_mut(name.id.as_str())
                    {
                        symbol.add_assigned_expression(expr);
                        symbol.taint.extend(taint);
                    }
                }
                Expr::Attribute(base_attr) => {
                    if let Expr::Name(ExprName { id: base_name, .. }) = base_attr.value.as_ref()
                        && base_name.as_str() == "self"
                        && let Some(idx) = self.find_class_scope()
                    {
                        if let Some(symbol) = self.scope_stack[idx]
                            .symbols
                            .get_mut(base_attr.attr.as_str())
                        {
                            symbol.add_assigned_expression(expr);
                            symbol.taint.extend(taint);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    pub fn handle_expr_pre(&mut self, expr: &'a Expr) {
        self.visit_node(expr);
    }

    pub fn handle_expr_post(&mut self, expr: &'a Expr) {
        self.compute_taint(expr);
        self.handle_expr(expr);
    }

    pub fn add_taint(&self, node_id: NodeId, taint: TaintKind) {
        self.model
            .taint_map
            .borrow_mut()
            .entry(node_id)
            .or_default()
            .insert(taint);
    }

    pub fn get_taint(&self, expr: &Expr) -> TaintState {
        expr.node_index()
            .load()
            .as_u32()
            .and_then(|id| self.model.taint_map.borrow().get(&id).cloned())
            .unwrap_or_default()
    }

    pub fn has_taint(&self, expr: &Expr, taint: TaintKind) -> bool {
        expr.node_index()
            .load()
            .as_u32()
            .and_then(|id| {
                self.model
                    .taint_map
                    .borrow()
                    .get(&id)
                    .map(|t| t.contains(&taint))
            })
            .unwrap_or(false)
    }

    fn compute_taint(&mut self, expr: &'a Expr) {
        let Some(node_id) = expr.node_index().load().as_u32() else {
            return;
        };

        let taints = crate::indexer::taint::compute_expr_taint(
            expr,
            |e| self.get_taint(e),
            |e| self.resolve_qualified_name(e),
        );

        if !taints.is_empty() {
            self.model
                .taint_map
                .borrow_mut()
                .entry(node_id)
                .or_default()
                .extend(taints);
        }
    }

    pub fn visit_node<T>(&self, node: &T)
    where
        T: HasNodeIndex,
    {
        if node.node_index().load().as_u32().is_none() {
            node.node_index().set(self.get_index());
        }
    }

    pub fn current_index(&self) -> NodeId {
        self.index.load(Ordering::Relaxed)
    }

    pub fn get_index(&self) -> NodeIndex {
        NodeIndex::from(self.index.fetch_add(1, Ordering::Relaxed) + 1)
    }

    pub fn get_atomic_index(&self) -> AtomicNodeIndex {
        let index = AtomicNodeIndex::NONE;
        index.set(self.get_index());
        index
    }

    pub fn get_exprs_by_index(&self, index: &AtomicNodeIndex) -> Option<&[&Expr]> {
        let id = index.load().as_u32()?;
        self.model.expr_mapping.get(&id).map(|v| &**v)
    }

    pub fn push_scope(&mut self, kind: ScopeKind) {
        let parent = if self.scope_stack.is_empty() {
            None
        } else {
            Some(self.scope_stack.len() - 1)
        };
        self.scope_stack.push(Scope {
            kind,
            symbols: HashMap::with_capacity(32),
            parent_scope: parent,
        });
    }

    pub fn pop_scope(&mut self) {
        self.scope_stack.pop();
    }

    pub(crate) fn lookup_binding(&self, name: &str) -> Option<&SymbolBinding<'a>> {
        if !self.scope_stack.is_empty() {
            let mut index = self.scope_stack.len() - 1;
            loop {
                let scope = &self.scope_stack[index];
                if let Some(binding) = scope.symbols.get(name) {
                    return Some(binding);
                }
                match scope.parent_scope {
                    Some(parent) => index = parent,
                    None => break,
                }
            }
        }
        None
    }

    fn handle_name_assignment(&mut self, name: &ExprName, value: &'a Expr) {
        let taint = self.get_taint(value);
        let symbols = &mut self.current_scope_mut().symbols;
        if let Some(symbol) = symbols.get_mut(name.id.as_str()) {
            symbol.add_assigned_expression(value);
            symbol.taint.extend(taint);
        } else {
            let mut symbol = SymbolBinding::assignment(Some(value));
            symbol.taint = taint;
            symbols.insert(name.id.to_string(), symbol);
        }
    }

    fn handle_self_attribute_assignment(&mut self, attr: &ExprAttribute, value: &'a Expr) {
        if let Expr::Name(ExprName { id: base_name, .. }) = &*attr.value
            && base_name.as_str() == "self"
            && let Some(idx) = self.find_class_scope()
        {
            let taint = self.get_taint(value);
            let symbols = &mut self.scope_stack[idx].symbols;
            if let Some(symbol) = symbols.get_mut(attr.attr.as_str()) {
                symbol.add_assigned_expression(value);
                symbol.taint.extend(taint);
            } else {
                let mut symbol = SymbolBinding::assignment(Some(value));
                symbol.taint = taint;
                symbols.insert(attr.attr.to_string(), symbol);
            }
        }
    }

    fn handle_attribute_assignment(&mut self, attr: &ExprAttribute, value: &'a Expr) {
        self.handle_self_attribute_assignment(attr, value);
    }

    fn handle_sequence_assignment(&mut self, target_elts: &[&'a Expr], value: &'a Expr) {
        if let Some(value_elts) = match value {
            Expr::Tuple(ExprTuple { elts, .. }) | Expr::List(ExprList { elts, .. }) => Some(elts),
            _ => None,
        } {
            if target_elts.len() == value_elts.len() {
                for i in 0..target_elts.len() {
                    self.handle_assignment_target(target_elts[i], &value_elts[i]);
                }
            }
        } else {
            for elt in target_elts.iter() {
                self.handle_assignment_target(elt, value);
            }
        }
    }

    fn handle_assignment_target(&mut self, target: &'a Expr, value: &'a Expr) {
        match target {
            Expr::Name(name) => self.handle_name_assignment(name, value),
            Expr::Attribute(attr) => self.handle_attribute_assignment(attr, value),
            Expr::Tuple(ExprTuple { elts, .. }) | Expr::List(ExprList { elts, .. }) => {
                let target_refs: Vec<&'a Expr> = elts.iter().collect();
                self.handle_sequence_assignment(&target_refs, value)
            }
            _ => {}
        }
    }

    pub fn resolve_expr_import_path(&self, expr: &Expr) -> Option<Vec<String>> {
        self.resolve_expr_import_path_internal(expr, None)
    }

    pub(crate) fn resolve_expr_import_path_internal(
        &self,
        expr: &Expr,
        context: Option<(&'a ExprCall, &'a StmtFunctionDef)>,
    ) -> Option<Vec<String>> {
        let node_id = expr.node_index().load().as_u32()?;
        if context.is_none() {
            if let Some(res) = self.model.resolve_cache.borrow().get(&node_id) {
                return res.clone();
            }
        }

        if !self.model.currently_resolving.borrow_mut().insert(node_id) {
            return None;
        }

        let res = match expr {
            Expr::Name(name) => self.resolve_name_path(name, context),
            Expr::Attribute(attr) => self.resolve_attribute_path(attr, context),
            Expr::BinOp(binop) if matches!(binop.op, Operator::Add) => {
                self.resolve_binop_path(binop, context)
            }
            Expr::StringLiteral(s) => Some(vec![s.value.to_string()]),
            Expr::Call(call) => self.resolve_call_path(call, context),
            _ => None,
        };

        self.model.currently_resolving.borrow_mut().remove(&node_id);

        if context.is_none() {
            self.model
                .resolve_cache
                .borrow_mut()
                .insert(node_id, res.clone());
        }
        res
    }

    fn resolve_name_path(
        &self,
        name: &ExprName,
        context: Option<(&'a ExprCall, &'a StmtFunctionDef)>,
    ) -> Option<Vec<String>> {
        if let Some((call, func)) = context {
            for (i, param) in func.parameters.args.iter().enumerate() {
                if param.name() == name.id.as_str() && i < call.arguments.args.len() {
                    return self.resolve_expr_import_path_internal(&call.arguments.args[i], None);
                }
            }
        }

        let node_id = name.node_index().load().as_u32()?;
        let last_expr = self
            .model
            .expr_mapping
            .get(&node_id)
            .and_then(|exprs| exprs.last());

        if let Some(last_expr) = last_expr {
            self.resolve_expr_import_path_internal(last_expr, context)
        } else {
            self.resolve_binding_import_path(name.id.as_str())
        }
    }

    fn resolve_attribute_path(
        &self,
        attr: &ExprAttribute,
        context: Option<(&'a ExprCall, &'a StmtFunctionDef)>,
    ) -> Option<Vec<String>> {
        let mut base_path = self.resolve_expr_import_path_internal(&attr.value, context)?;
        base_path.push(attr.attr.to_string());
        Some(base_path)
    }

    fn resolve_binop_path(
        &self,
        binop: &ExprBinOp,
        context: Option<(&'a ExprCall, &'a StmtFunctionDef)>,
    ) -> Option<Vec<String>> {
        let l = self.resolve_expr_import_path_internal(&binop.left, context)?;
        let r = self.resolve_expr_import_path_internal(&binop.right, context)?;
        Some(vec![l.join("") + &r.join("")])
    }

    fn resolve_call_path(
        &self,
        call: &ExprCall,
        context: Option<(&'a ExprCall, &'a StmtFunctionDef)>,
    ) -> Option<Vec<String>> {
        let qn = self.resolve_qualified_name_internal(&call.func)?;
        match qn.segments().as_slice() {
            ["importlib", "import_module"] if !call.arguments.args.is_empty() => {
                let arg_path =
                    self.resolve_expr_import_path_internal(&call.arguments.args[0], context)?;
                Some(
                    arg_path
                        .join("")
                        .split('.')
                        .map(|s| s.to_string())
                        .collect(),
                )
            }
            ["getattr"] if call.arguments.args.len() >= 2 => {
                let mut path =
                    self.resolve_expr_import_path_internal(&call.arguments.args[0], context)?;
                let attr_path =
                    self.resolve_expr_import_path_internal(&call.arguments.args[1], context)?;
                path.push(attr_path.join(""));
                Some(path)
            }
            ["globals"] | ["locals"] | ["vars"] => Some(vec![qn.segments()[0].to_string()]),
            _ => self.resolve_function_call_path(call),
        }
    }

    fn resolve_function_call_path(&self, call: &ExprCall) -> Option<Vec<String>> {
        if let Expr::Name(func_name) = call.func.as_ref() {
            if let Some(binding) = self.lookup_binding(func_name.id.as_str())
                && let BindingKind::Function = binding.kind
                && let Some(func) = binding.function_def
            {
                let return_expr: Option<&Expr> = func.body.iter().find_map(|s| {
                    if let Stmt::Return(StmtReturn { value: Some(v), .. }) = s {
                        Some(v.as_ref())
                    } else {
                        None
                    }
                });

                if let Some(ret_expr) = return_expr {
                    return self.resolve_expr_import_path_internal(ret_expr, Some((call, func)));
                }
            }
        }
        None
    }

    fn resolve_import_binding(&self, binding: &SymbolBinding) -> Option<Vec<String>> {
        binding.imported_path.as_ref().cloned()
    }

    fn resolve_builtin_binding(&self, name: &str) -> Option<Vec<String>> {
        Some(vec![name.to_string()])
    }

    fn resolve_assignment_binding(&self, binding: &SymbolBinding) -> Option<Vec<String>> {
        if let Some(value_expr) = binding.value_expr {
            self.resolve_expr_import_path(value_expr)
        } else {
            None
        }
    }

    fn resolve_binding_import_path(&self, name: &str) -> Option<Vec<String>> {
        if let Some(binding) = self.lookup_binding(name) {
            match binding.kind {
                BindingKind::Import => self.resolve_import_binding(binding),
                BindingKind::Builtin => self.resolve_builtin_binding(name),
                BindingKind::Assignment => self.resolve_assignment_binding(binding),
                BindingKind::Function => None,
            }
        } else {
            None
        }
    }

    pub fn resolve_qualified_name<'b>(&'b self, expr: &'b Expr) -> Option<QualifiedName> {
        self.resolve_qualified_name_internal(expr)
    }

    fn resolve_qualified_name_internal<'b>(&'b self, expr: &'b Expr) -> Option<QualifiedName> {
        if let Some(mut path) = self.resolve_expr_import_path(expr) {
            if path.len() == 1 {
                let name = path.remove(0);
                if let Some(binding) = self.lookup_binding(&name)
                    && matches!(binding.kind, BindingKind::Builtin)
                {
                    return Some(QualifiedName::from_segments(vec![name]));
                }
                path.push(name);
            }
            return Some(QualifiedName::from_segments(path));
        }

        let target = match expr {
            Expr::Call(call) => &call.func,
            _ => expr,
        };
        if let Some(mut path) = self.resolve_expr_import_path(target) {
            if path.len() == 1 {
                let name = path.remove(0);
                if let Some(binding) = self.lookup_binding(&name)
                    && matches!(binding.kind, BindingKind::Builtin)
                {
                    return Some(QualifiedName::from_segments(vec![name]));
                }
                path.push(name);
            }
            Some(QualifiedName::from_segments(path))
        } else {
            self.collect_attribute_segments(target)
                .map(QualifiedName::from_segments)
        }
    }

    pub fn collect_attribute_segments(&self, expr: &Expr) -> Option<Vec<String>> {
        let mut segments = Vec::new();
        let mut current = expr;
        while let Expr::Attribute(attr) = current {
            segments.push(attr.attr.to_string());
            current = &attr.value;
        }
        if let Expr::Name(name) = current {
            segments.push(name.id.to_string());
            segments.reverse();
            Some(segments)
        } else {
            None
        }
    }

    pub fn get_call_qualified_name(&self, node_id: NodeId) -> Option<&QualifiedName> {
        self.model.call_qualified_names.get(&node_id)
    }

    pub fn get_qualified_name<T>(&self, node: &T) -> Option<&QualifiedName>
    where
        T: HasNodeIndex,
    {
        node.node_index()
            .load()
            .as_u32()
            .and_then(|id| self.get_call_qualified_name(id))
    }

    fn find_class_scope(&self) -> Option<usize> {
        self.scope_stack
            .iter()
            .enumerate()
            .rfind(|(_, scope)| scope.kind == ScopeKind::Class)
            .map(|(i, _)| i)
    }
}

impl<'a> SourceOrderVisitor<'a> for NodeIndexer<'a> {
    #[inline]
    fn visit_mod(&mut self, module: &'a Mod) {
        self.visit_node(module);
    }

    #[inline]
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        self.handle_stmt_pre(stmt);
        walk_stmt(self, stmt);
        self.handle_stmt_post(stmt);
    }

    #[inline]
    fn visit_annotation(&mut self, expr: &'a Expr) {
        self.visit_node(expr);
        walk_annotation(self, expr);
    }

    #[inline]
    fn visit_expr(&mut self, expr: &'a Expr) {
        self.handle_expr_pre(expr);
        walk_expr(self, expr);
        self.handle_expr_post(expr);
    }

    #[inline]
    fn visit_decorator(&mut self, decorator: &'a Decorator) {
        self.visit_node(decorator);
        walk_decorator(self, decorator);
    }

    #[inline]
    fn visit_comprehension(&mut self, comprehension: &'a Comprehension) {
        self.visit_node(comprehension);
        walk_comprehension(self, comprehension);
    }

    #[inline]
    fn visit_except_handler(&mut self, except_handler: &'a ExceptHandler) {
        self.visit_node(except_handler);
        walk_except_handler(self, except_handler);
    }

    #[inline]
    fn visit_arguments(&mut self, arguments: &'a Arguments) {
        self.visit_node(arguments);
        walk_arguments(self, arguments);
    }

    #[inline]
    fn visit_parameters(&mut self, parameters: &'a Parameters) {
        self.visit_node(parameters);
        walk_parameters(self, parameters);
    }

    #[inline]
    fn visit_parameter(&mut self, arg: &'a Parameter) {
        self.visit_node(arg);
        walk_parameter(self, arg);
    }

    #[inline]
    fn visit_parameter_with_default(&mut self, parameter_with_default: &'a ParameterWithDefault) {
        self.visit_node(parameter_with_default);
        walk_parameter_with_default(self, parameter_with_default);
    }

    #[inline]
    fn visit_keyword(&mut self, keyword: &'a Keyword) {
        self.visit_node(keyword);
        walk_keyword(self, keyword);
    }

    #[inline]
    fn visit_alias(&mut self, alias: &'a Alias) {
        self.visit_node(alias);
        walk_alias(self, alias);
    }

    #[inline]
    fn visit_with_item(&mut self, with_item: &'a WithItem) {
        self.visit_node(with_item);
        walk_with_item(self, with_item);
    }

    #[inline]
    fn visit_type_params(&mut self, type_params: &'a TypeParams) {
        self.visit_node(type_params);
        walk_type_params(self, type_params);
    }

    #[inline]
    fn visit_match_case(&mut self, match_case: &'a MatchCase) {
        self.visit_node(match_case);
        walk_match_case(self, match_case);
    }

    #[inline]
    fn visit_pattern(&mut self, pattern: &'a Pattern) {
        self.visit_node(pattern);
        walk_pattern(self, pattern);
    }

    #[inline]
    fn visit_pattern_arguments(&mut self, pattern_arguments: &'a PatternArguments) {
        self.visit_node(pattern_arguments);
        walk_pattern_arguments(self, pattern_arguments);
    }

    #[inline]
    fn visit_pattern_keyword(&mut self, pattern_keyword: &'a PatternKeyword) {
        self.visit_node(pattern_keyword);
        walk_pattern_keyword(self, pattern_keyword);
    }

    #[inline]
    fn visit_elif_else_clause(&mut self, elif_else_clause: &'a ElifElseClause) {
        self.visit_node(elif_else_clause);
        walk_elif_else_clause(self, elif_else_clause);
    }

    #[inline]
    fn visit_f_string(&mut self, f_string: &'a FString) {
        self.visit_node(f_string);
        walk_f_string(self, f_string);
    }

    #[inline]
    fn visit_interpolated_string_element(
        &mut self,
        interpolated_string_element: &'a InterpolatedStringElement,
    ) {
        self.visit_node(interpolated_string_element);
        walk_interpolated_string_element(self, interpolated_string_element);
    }

    #[inline]
    fn visit_t_string(&mut self, t_string: &'a TString) {
        self.visit_node(t_string);
        walk_t_string(self, t_string);
    }

    #[inline]
    fn visit_string_literal(&mut self, string_literal: &'a StringLiteral) {
        self.visit_node(string_literal);
        walk_string_literal(self, string_literal);
    }

    #[inline]
    fn visit_bytes_literal(&mut self, bytes_literal: &'a BytesLiteral) {
        self.visit_node(bytes_literal);
        walk_bytes_literal(self, bytes_literal);
    }

    #[inline]
    fn visit_identifier(&mut self, identifier: &'a Identifier) {
        self.visit_node(identifier);
        walk_identifier(self, identifier);
    }
}

impl<'a> NodeIndexer<'a> {
    fn handle_assign_stmt(&mut self, assign: &'a StmtAssign) {
        for target in &assign.targets {
            self.handle_assignment_target(target, &assign.value);
        }
    }

    fn handle_aug_assign_stmt(&mut self, aug_assign: &'a StmtAugAssign) {
        self.handle_aug_assign(&aug_assign.target, &aug_assign.value);
    }

    fn add_import_binding(&mut self, local: String, qualified: Vec<String>) {
        let sym = SymbolBinding::import(qualified);
        self.current_scope_mut().symbols.insert(local, sym);
    }

    fn handle_import_stmt(&mut self, import_stmt: &StmtImport) {
        for alias in &import_stmt.names {
            let local = alias
                .asname
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| alias.name.split('.').next().unwrap().to_string());
            let qualified: Vec<String> = alias.name.split('.').map(|s| s.to_string()).collect();
            self.add_import_binding(local, qualified);
        }
    }

    fn handle_import_from_stmt(&mut self, import_from_stmt: &StmtImportFrom) {
        let base = import_from_stmt.module.as_deref().unwrap_or("");
        for alias in &import_from_stmt.names {
            if alias.name.as_str() == "*" {
                continue;
            }
            let local = alias
                .asname
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| alias.name.to_string());
            let mut qualified: Vec<String> = Vec::new();
            if import_from_stmt.level > 0 {
                qualified.push(".".repeat(import_from_stmt.level as usize));
            }
            if !base.is_empty() {
                qualified.extend(base.split('.').map(|s| s.to_string()));
            }
            qualified.push(alias.name.to_string());
            self.add_import_binding(local, qualified);
        }
    }

    fn handle_aug_assign(&mut self, target: &'a Expr, value: &'a Expr) {
        match target {
            Expr::Name(ExprName { id, .. }) => {
                let taint = self.get_taint(value);
                if let Some(symbol) = self.current_scope_mut().symbols.get_mut(id.as_str()) {
                    symbol.add_assigned_expression(value);
                    symbol.taint.extend(taint);
                }
            }
            Expr::Attribute(attr) => {
                self.handle_self_attribute_assignment(attr, value);
            }
            _ => {}
        }
    }

    fn handle_expr(&mut self, expr: &'a Expr) {
        match expr {
            Expr::Call(call) => self.handle_call_expr(call, expr),
            Expr::Name(name) => self.handle_name_expr(name, expr),
            Expr::Attribute(attr) => self.handle_attribute_expr(attr, expr),
            _ => {}
        }
    }

    fn handle_call_expr(&mut self, call: &'a ExprCall, expr: &'a Expr) {
        self.handle_method_call_mutation(expr, call);
        if let Some(qn) = self.resolve_qualified_name(expr)
            && let Some(id) = expr.node_index().load().as_u32()
        {
            self.model.call_qualified_names.insert(id, qn);
        }
    }

    fn handle_name_expr(&mut self, name: &'a ExprName, expr: &'a Expr) {
        if matches!(name.ctx, ExprContext::Load) {
            self.handle_name_load(name.id.as_str(), expr);
        }
    }

    fn handle_attribute_expr(&mut self, attr: &'a ExprAttribute, expr: &'a Expr) {
        if matches!(attr.ctx, ExprContext::Load) {
            self.handle_attribute_load(&attr.value, attr.attr.as_str(), expr);
        }
    }

    fn handle_name_load(&mut self, id: &str, expr: &'a Expr) {
        if let Some(binding) = self.lookup_binding(id)
            && let Some(node_id) = expr.node_index().load().as_u32()
        {
            let exprs = binding.assigned_expressions.clone();
            let taint = binding.taint.clone();

            self.model
                .expr_mapping
                .entry(node_id)
                .or_default()
                .extend(exprs);

            if !taint.is_empty() {
                self.model.taint_map.borrow_mut().insert(node_id, taint);
            }
        }
    }

    fn handle_attribute_load(&mut self, obj: &'a Expr, attr: &str, expr: &'a Expr) {
        if let Expr::Name(ExprName { id: base_name, .. }) = obj
            && base_name.as_str() == "self"
            && let Some(idx) = self.find_class_scope()
            && let Some(binding) = self.scope_stack[idx].symbols.get(attr)
            && let Some(node_id) = expr.node_index().load().as_u32()
        {
            let exprs = binding.assigned_expressions.clone();
            let taint = binding.taint.clone();

            self.model
                .expr_mapping
                .entry(node_id)
                .or_default()
                .extend(exprs);

            if !taint.is_empty() {
                self.model.taint_map.borrow_mut().insert(node_id, taint);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::helpers::get_expression_range;
    use crate::indexer::locator::Locator;
    use ruff_python_ast::PySourceType;
    use ruff_python_ast::visitor::source_order::SourceOrderVisitor;
    use std::collections::HashMap;
    use unindent::unindent;

    fn convert_to_strings<'a>(
        locator: &Locator<'a>,
        mappings: &HashMap<u32, Vec<&Expr>>,
    ) -> HashMap<u32, Vec<&'a str>> {
        let mut result: HashMap<u32, Vec<&'a str>> = HashMap::new();

        for (node_id, exprs) in mappings.iter() {
            let res: Vec<&str> = exprs
                .iter()
                .map(|e| locator.slice(get_expression_range(e)))
                .collect();
            result.insert(*node_id, res);
        }
        result
    }

    fn get_result(source: &str) -> HashMap<u32, Vec<&str>> {
        let parsed = ruff_python_parser::parse_unchecked_source(source, PySourceType::Python);
        let locator = Locator::new(source);
        let python_ast = parsed.suite();
        let mut indexer = NodeIndexer::new();
        indexer.visit_body(python_ast);
        convert_to_strings(&locator, &indexer.model.expr_mapping)
    }

    fn with_indexer<F, R>(source: &str, f: F) -> R
    where
        F: FnOnce(&mut NodeIndexer, &[Stmt]) -> R,
    {
        let parsed = ruff_python_parser::parse_unchecked_source(source, PySourceType::Python);
        let suite = parsed.suite();
        let mut indexer = NodeIndexer::new();
        indexer.visit_body(suite);
        f(&mut indexer, suite)
    }

    fn resolve_call_at_index(
        indexer: &mut NodeIndexer,
        suite: &[Stmt],
        index: usize,
    ) -> Option<String> {
        if let Stmt::Expr(StmtExpr { value, .. }) = &suite[index] {
            if let Expr::Call(_) = &**value {
                indexer.resolve_qualified_name(value).map(|qn| qn.as_str())
            } else {
                None
            }
        } else {
            None
        }
    }

    #[test]
    fn test_simple_case() {
        let source = unindent(
            r#"
            a = "print"+"(123)"+";"+"123"
            b = "".join(["cc", a,"b"])"#,
        );

        let expected = HashMap::from([(1025, vec![r#""print"+"(123)"+";"+"123""#])]);
        let actual = get_result(&source);
        assert_eq!(expected, actual);
    }
    #[test]
    fn test_correct_scoping() {
        let source = unindent(
            r#"
            c = 'first'
            def func():
                c = '10'
                c += '_trials'
                c += '_of_20'
                d = ['a',c,'b']


            def test_func_2():
                e = ['a', c, 'b']
            "#,
        );
        let expected = HashMap::from([
            (1025, vec!["'10'", "'_trials'", "'_of_20'"]),
            (1036, vec!["'first'"]),
        ]);
        let actual = get_result(&source);
        assert_eq!(expected, actual);
    }
    #[test]
    fn test_class_scoping() {
        let source = unindent(
            r#"
            class Test:
                def __init__(self):
                    self.c = 'nope'
                def test_func(self):
                    f = ['a', self.c, 'b']
            "#,
        );
        let expected = HashMap::from([(1026, vec!["'nope'"])]);
        let actual = get_result(&source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_resolve_from_import_call() {
        let source = unindent(
            r#"
            from os import popen
            popen('asd')
            "#,
        );
        with_indexer(&source, |indexer, suite| {
            let resolved = resolve_call_at_index(indexer, suite, 1);
            assert_eq!(resolved.as_deref(), Some("os.popen"));
        });
    }

    #[test]
    fn test_resolve_import_attr_call() {
        let source = unindent(
            r#"
            import os
            os.popen('asd')
            "#,
        );
        with_indexer(&source, |indexer, suite| {
            let resolved = resolve_call_at_index(indexer, suite, 1);
            assert_eq!(resolved.as_deref(), Some("os.popen"));
        });
    }

    #[test]
    fn test_resolve_alias_chain_import_call() {
        let source = unindent(
            r#"
            import subprocess
            s = subprocess
            k = s
            k.check_output(["pinfo -m", ' ', "ABC"])
            "#,
        );
        with_indexer(&source, |indexer, suite| {
            let resolved = resolve_call_at_index(indexer, suite, 3);
            assert_eq!(resolved.as_deref(), Some("subprocess.check_output"));
        });
    }

    #[test]
    fn test_resolve_builtin_direct_and_module() {
        let source = unindent(
            r#"
            eval("1+2")
            import builtins
            builtins.len([1,2,3])
            "#,
        );
        with_indexer(&source, |indexer, suite| {
            let resolved0 = resolve_call_at_index(indexer, suite, 0);
            let got = resolved0.expect("expected qualified name");
            assert_eq!(
                got, "eval",
                "expected builtin eval qualified name to be 'eval', got {got}"
            );

            let resolved2 = resolve_call_at_index(indexer, suite, 2);
            assert_eq!(resolved2.as_deref(), Some("builtins.len"));
        });
    }

    #[test]
    fn test_resolve_unknown_name() {
        let source = unindent(
            r#"
            full_length([1,2,3])
            "#,
        );
        with_indexer(&source, |indexer, suite| {
            let resolved = resolve_call_at_index(indexer, suite, 0);
            assert_eq!(resolved.as_deref(), Some("full_length"));
        });
    }

    #[test]
    fn test_scope_resolution_outside_function() {
        let source = unindent(
            r#"
            import subprocess

            def test():
                s = subprocess.call

            s(["uname -a"])
            "#,
        );
        with_indexer(&source, |indexer, suite| {
            let resolved = resolve_call_at_index(indexer, suite, 2);
            assert_eq!(resolved.as_deref(), Some("s"));
        });
    }

    #[test]
    fn test_contains_builtins() {
        let indexer = NodeIndexer::new();
        let has_eval = indexer
            .scope_stack
            .first()
            .unwrap()
            .symbols
            .contains_key("eval");
        let has_getattr = indexer
            .scope_stack
            .first()
            .unwrap()
            .symbols
            .contains_key("getattr");
        assert!(
            has_eval && has_getattr,
            "Builtins should be bound in NodeIndexer global scope"
        );
    }

    #[test]
    fn test_contains_magic_vars() {
        let indexer = NodeIndexer::new();
        let has_dunder_name = indexer
            .scope_stack
            .first()
            .unwrap()
            .symbols
            .contains_key("__name__");
        assert!(
            has_dunder_name,
            "Magic globals like __name__ should be bound"
        );
    }

    #[test]
    fn test_sequence_unpacking_insufficient_values() {
        let source = "a, b = [1]";
        with_indexer(source, |indexer, _suite| {
            let scope = &indexer.scope_stack[0];
            assert!(!scope.symbols.contains_key("a"));
            assert!(!scope.symbols.contains_key("b"));
        });
    }

    #[test]
    fn test_sequence_unpacking_extra_values() {
        let source = "a, b = [1, 2, 3]";
        with_indexer(source, |indexer, _suite| {
            let scope = &indexer.scope_stack[0];
            assert!(!scope.symbols.contains_key("a"));
            assert!(!scope.symbols.contains_key("b"));
        });
    }

    #[test]
    fn test_sequence_unpacking_exact_match() {
        let source = "a, b = [1, 2]";
        with_indexer(source, |indexer, _suite| {
            let scope = &indexer.scope_stack[0];
            let a_binding = scope.symbols.get("a").unwrap();
            assert_eq!(a_binding.assigned_expressions.len(), 1);
            let b_binding = scope.symbols.get("b").unwrap();
            assert_eq!(b_binding.assigned_expressions.len(), 1);
        });
    }

    #[test]
    fn test_aug_assign_attribute() {
        let source = unindent(
            r#"
            class Test:
                def __init__(self):
                    self.x = 1
                def test_func(self):
                    self.x += 2
                    y = self.x
            "#,
        );
        let expected = HashMap::from([(1027, vec!["1", "2"])]);
        let actual = get_result(&source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_aug_assign_attribute_no_prior() {
        let source = unindent(
            r#"
            class Test:
                def test_func(self):
                    self.x += 2
                    y = self.x
            "#,
        );
        let expected = HashMap::from([(1016, vec!["2"])]);
        let actual = get_result(&source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_clear_state() {
        let source = "a = 1; b = a";
        let parsed = ruff_python_parser::parse_unchecked_source(source, PySourceType::Python);
        let mut indexer = NodeIndexer::new();
        indexer.visit_body(parsed.suite());

        assert!(!indexer.model.expr_mapping.is_empty());
        let old_index = indexer.index.load(Ordering::Relaxed);
        assert!(old_index > 1000);

        indexer.clear_state();
        assert!(indexer.model.expr_mapping.is_empty());
        assert!(indexer.model.call_qualified_names.is_empty());
        assert!(indexer.model.comments.is_empty());
        assert_eq!(indexer.index.load(Ordering::Relaxed), 1000);
        assert_eq!(indexer.scope_stack.len(), 1);
        assert!(indexer.scope_stack[0].symbols.contains_key("print"));
    }
}
