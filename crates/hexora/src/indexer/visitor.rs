use crate::indexer::index::NodeIndexer;
use crate::indexer::scope::SymbolBinding;
use ruff_python_ast::visitor::source_order::*;
use ruff_python_ast::*;

impl<'a> SourceOrderVisitor<'a> for NodeIndexer<'a> {
    #[inline]
    fn visit_mod(&mut self, module: &'a Mod) {
        self.visit_node(module);
    }

    #[inline]
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        self.handle_stmt_pre(stmt);
        match stmt {
            Stmt::For(node) => {
                self.visit_node(node);
                self.visit_expr(&node.target);
                self.visit_expr(&node.iter);
                self.handle_assignment_target(&node.target, &node.iter);
                self.visit_body(&node.body);
                self.visit_body(&node.orelse);
            }
            Stmt::With(node) => {
                self.visit_node(node);
                for item in &node.items {
                    self.visit_node(item);
                    self.visit_expr(&item.context_expr);
                    if let Some(target) = &item.optional_vars {
                        self.visit_expr(target);
                        self.handle_assignment_target(target, &item.context_expr);
                    }
                }
                self.visit_body(&node.body);
            }
            _ => walk_stmt(self, stmt),
        }
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
        self.handle_assignment_target(&comprehension.target, &comprehension.iter);
    }

    #[inline]
    fn visit_except_handler(&mut self, except_handler: &'a ExceptHandler) {
        self.visit_node(except_handler);
        walk_except_handler(self, except_handler);
        let ExceptHandler::ExceptHandler(h) = except_handler;
        if let Some(name) = &h.name {
            let binding = SymbolBinding::assignment(None);
            self.current_scope_mut()
                .symbols
                .insert(name.id.to_string(), binding);
        }
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
