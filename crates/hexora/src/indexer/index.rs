use ruff_python_ast::token::{TokenKind, Tokens};
use ruff_python_ast::visitor::Visitor;
use ruff_python_ast::*;
use ruff_python_stdlib::builtins::{MAGIC_GLOBALS, python_builtins};
use ruff_text_size::Ranged;
use std::collections::HashMap;

use crate::indexer::model::{NodeId, SemanticModel};
use crate::indexer::scope::{Scope, ScopeKind, SymbolBinding};

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
            Stmt::FunctionDef(func) => {
                self.push_scope(ScopeKind::Function);
                for (i, param) in func.parameters.args.iter().enumerate() {
                    let mut binding = SymbolBinding::assignment(None);
                    binding.taint.insert(TaintKind::InternalParameter(i));
                    self.current_scope_mut()
                        .symbols
                        .insert(param.name().to_string(), binding);
                }
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
                let mut return_taint = TaintState::new();
                for ret_expr in collect_returns(&func.body) {
                    return_taint.extend(self.get_taint(ret_expr));
                }

                let leaks = self.scope_stack.last().unwrap().parameter_leaks.clone();

                self.pop_scope();
                let symbols = &mut self.current_scope_mut().symbols;
                let mut binding = SymbolBinding::function(func);
                binding.return_taint = return_taint;
                binding.parameter_leaks = leaks;
                symbols.insert(func.name.to_string(), binding);
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

    pub(crate) fn handle_method_call_mutation(&mut self, expr: &'a Expr, call: &ExprCall) {
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
            |e| self.get_function_return_taint(e),
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

    pub fn get_function_return_taint(&self, expr: &Expr) -> TaintState {
        if let Expr::Call(call) = expr {
            match call.func.as_ref() {
                Expr::Name(func_name) => {
                    if let Some(binding) = self.lookup_binding(func_name.id.as_str()) {
                        if !binding.return_taint.is_empty() {
                            return binding.return_taint.clone();
                        }
                        if let Some(Expr::Lambda(lambda)) = binding.value_expr {
                            return self.get_taint(&lambda.body);
                        }
                    }
                }
                Expr::Lambda(lambda) => {
                    return self.get_taint(&lambda.body);
                }
                _ => {}
            }
        }
        TaintState::new()
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
            parameter_leaks: Vec::new(),
        });
    }

    pub fn pop_scope(&mut self) {
        self.scope_stack.pop();
    }

    pub fn add_parameter_leak(&mut self, parameter_index: usize, sink_name: String) {
        for scope in self.scope_stack.iter_mut().rev() {
            if scope.kind == ScopeKind::Function {
                if !scope
                    .parameter_leaks
                    .iter()
                    .any(|(i, s)| *i == parameter_index && s == &sink_name)
                {
                    scope.parameter_leaks.push((parameter_index, sink_name));
                }
                break;
            }
        }
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

    pub(crate) fn find_class_scope(&self) -> Option<usize> {
        self.scope_stack
            .iter()
            .enumerate()
            .rfind(|(_, scope)| scope.kind == ScopeKind::Class)
            .map(|(i, _)| i)
    }
}

pub(crate) fn collect_returns(body: &[Stmt]) -> Vec<&Expr> {
    let mut visitor = ruff_python_ast::helpers::ReturnStatementVisitor::default();
    visitor.visit_body(body);
    visitor
        .returns
        .into_iter()
        .filter_map(|ret| ret.value.as_deref())
        .collect()
}
