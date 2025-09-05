use ruff_python_ast::HasNodeIndex;
use ruff_python_ast::visitor::source_order::*;
use ruff_python_ast::*;
use std::collections::HashMap;

pub enum ScopeKind {
    Module,
    Class,
    Function,
}

pub struct Scope {
    pub kind: ScopeKind,
    pub symbols: HashMap<String, u32>,
    pub parent_scope: Option<usize>,
}

pub struct NodeIndexer<'a> {
    pub expr_mapping: HashMap<u32, Vec<&'a Expr>>,
    index: u32,
    binding_to_exprs: HashMap<u32, Vec<&'a Expr>>,
    scope_stack: Vec<Scope>,
}

impl<'a> Default for NodeIndexer<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> NodeIndexer<'a> {
    pub fn new() -> Self {
        let mut this = Self {
            index: 0,
            expr_mapping: HashMap::default(),
            binding_to_exprs: HashMap::default(),
            scope_stack: Vec::new(),
        };
        this.push_scope(ScopeKind::Module);
        this
    }
    pub fn visit_node<T>(&mut self, node: &T)
    where
        T: HasNodeIndex,
    {
        node.node_index().set(self.get_index());
    }
    pub fn get_index(&mut self) -> u32 {
        self.index += 1;
        self.index
    }
    pub fn get_index_atomic(&mut self) -> AtomicNodeIndex {
        AtomicNodeIndex::from(self.get_index())
    }
    pub fn get_expr_by_index(&self, index: &AtomicNodeIndex) -> Option<&Expr> {
        let id = index.load().as_u32();
        self.expr_mapping
            .get(&id)
            .and_then(|v| v.first())
            .map(|v| &**v)
    }
}

impl<'a> NodeIndexer<'a> {
    fn push_scope(&mut self, kind: ScopeKind) {
        let parent = if self.scope_stack.is_empty() {
            None
        } else {
            Some(self.scope_stack.len() - 1)
        };
        self.scope_stack.push(Scope {
            kind,
            symbols: HashMap::default(),
            parent_scope: parent,
        });
    }
    fn pop_scope(&mut self) {
        self.scope_stack.pop();
    }
    fn resolve_in_scopes(&self, name: &str) -> Option<u32> {
        if self.scope_stack.is_empty() {
            return None;
        }
        let mut index = self.scope_stack.len() - 1;
        loop {
            let scope = &self.scope_stack[index];
            if let Some(id) = scope.symbols.get(name) {
                return Some(*id);
            }
            match scope.parent_scope {
                Some(parent) => index = parent,
                None => break,
            }
        }
        None
    }
    fn handle_assignment_target(&mut self, target: &'a Expr, value: &'a Expr) {
        match target {
            Expr::Name(ExprName { id, node_index, .. }) => {
                let binding_key = node_index.load().as_u32();
                self.binding_to_exprs
                    .entry(binding_key)
                    .or_default()
                    .push(value);
                if let Some(scope) = self.scope_stack.last_mut() {
                    scope.symbols.insert(id.to_string(), binding_key);
                }
            }
            Expr::Attribute(ExprAttribute {
                value: obj, attr, ..
            }) => {
                if let Expr::Name(ExprName { id: base_name, .. }) = &**obj {
                    if base_name.as_str() == "self" {
                        let mut scope_idx_opt = self.scope_stack.len().checked_sub(1);
                        while let Some(idx) = scope_idx_opt {
                            match self.scope_stack[idx].kind {
                                ScopeKind::Class => {
                                    let binding_key = attr.node_index.load().as_u32();
                                    self.binding_to_exprs
                                        .entry(binding_key)
                                        .or_default()
                                        .push(value);
                                    self.scope_stack[idx]
                                        .symbols
                                        .insert(attr.to_string(), binding_key);
                                    break;
                                }
                                _ => {
                                    scope_idx_opt = self.scope_stack[idx].parent_scope;
                                }
                            }
                        }
                    }
                }
            }
            Expr::Tuple(ExprTuple { elts, .. }) | Expr::List(ExprList { elts, .. }) => {
                for elt in elts.iter() {
                    self.handle_assignment_target(elt, value);
                }
            }
            _ => {}
        }
    }
}

impl<'a> SourceOrderVisitor<'a> for NodeIndexer<'a> {
    #[inline]
    fn visit_mod(&mut self, module: &'a Mod) {
        self.visit_node(module);
    }

    #[inline]
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        self.visit_node(stmt);

        match stmt {
            Stmt::ClassDef(_) => {
                self.push_scope(ScopeKind::Class);
                walk_stmt(self, stmt);
                self.pop_scope();
                return;
            }
            Stmt::FunctionDef(_) => {
                self.push_scope(ScopeKind::Function);
                walk_stmt(self, stmt);
                self.pop_scope();
                return;
            }
            _ => {}
        }

        walk_stmt(self, stmt);

        match stmt {
            Stmt::Assign(StmtAssign { targets, value, .. }) => {
                for target in targets {
                    self.handle_assignment_target(target, value);
                }
            }
            Stmt::AugAssign(StmtAugAssign { target, value, .. }) => {
                if let Expr::Name(ExprName { id, .. }) = &**target {
                    if let Some(binding_id) = self.resolve_in_scopes(id.as_str()) {
                        self.binding_to_exprs
                            .entry(binding_id)
                            .or_default()
                            .push(value);
                    }
                }
            }
            _ => {}
        }
    }

    #[inline]
    fn visit_annotation(&mut self, expr: &'a Expr) {
        self.visit_node(expr);
        walk_annotation(self, expr);
    }

    #[inline]
    fn visit_expr(&mut self, expr: &'a Expr) {
        self.visit_node(expr);

        if let Expr::Name(ExprName { id, ctx, .. }) = expr {
            if matches!(ctx, ExprContext::Load) {
                if let Some(binding_id) = self.resolve_in_scopes(id.as_str()) {
                    if let Some(exprs) = self.binding_to_exprs.get(&binding_id) {
                        let load_node_id = expr.node_index().load().as_u32();
                        self.expr_mapping
                            .entry(load_node_id)
                            .or_default()
                            .extend_from_slice(exprs);
                    }
                }
            }
        }
        if let Expr::Attribute(ExprAttribute {
            value: obj,
            attr,
            ctx,
            ..
        }) = expr
        {
            if matches!(ctx, ExprContext::Load) {
                if let Expr::Name(ExprName { id: base_name, .. }) = &**obj {
                    if base_name.as_str() == "self" {
                        let mut scope_idx_opt = self.scope_stack.len().checked_sub(1);
                        while let Some(idx) = scope_idx_opt {
                            match self.scope_stack[idx].kind {
                                ScopeKind::Class => {
                                    if let Some(binding_id) =
                                        self.scope_stack[idx].symbols.get(attr.as_str())
                                    {
                                        if let Some(exprs) = self.binding_to_exprs.get(binding_id) {
                                            let load_node_id = expr.node_index().load().as_u32();
                                            self.expr_mapping
                                                .entry(load_node_id)
                                                .or_default()
                                                .extend_from_slice(exprs);
                                        }
                                    }
                                    break;
                                }
                                _ => scope_idx_opt = self.scope_stack[idx].parent_scope,
                            }
                        }
                    }
                }
            }
        }

        walk_expr(self, expr);
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
    fn visit_type_param(&mut self, type_param: &'a TypeParam) {
        self.visit_node(type_param);
        walk_type_param(self, type_param);
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

#[cfg(test)]
mod tests {
    use crate::audit::helpers::get_expression_range;
    use crate::indexer::index::NodeIndexer;
    use ruff_linter::Locator;
    use ruff_python_ast::visitor::source_order::SourceOrderVisitor;
    use ruff_python_ast::*;
    use std::collections::HashMap;
    use unindent::unindent;

    fn convert_to_strings<'a>(
        locator: &Locator<'a>,
        mappings: &HashMap<u32, Vec<&Expr>>,
    ) -> HashMap<u32, Vec<&'a str>> {
        let mut result: HashMap<u32, Vec<&str>> = HashMap::new();

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
        convert_to_strings(&locator, &indexer.expr_mapping)
    }

    #[test]
    fn test_simple_case() {
        let source = unindent(
            r#"
            a = "print"+"(123)"+";"+"123"
            b = "".join(["cc", a,"b"])"#,
        );

        let expected = HashMap::from([(25, vec![r#""print"+"(123)"+";"+"123""#])]);
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
            (25, vec!["'10'", "'_trials'", "'_of_20'"]),
            (36, vec!["'first'"]),
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
        let expected = HashMap::from([(26, vec!["'nope'"])]);
        let actual = get_result(&source);
        assert_eq!(expected, actual);
    }
}
