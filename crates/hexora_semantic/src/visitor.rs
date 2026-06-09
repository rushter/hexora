use crate::index::NodeIndexer;
use crate::scope::SymbolBinding;
use ruff_python_ast::visitor::source_order::*;
use ruff_python_ast::*;

impl<'a> SourceOrderVisitor<'a> for NodeIndexer<'a> {
    fn enter_node(&mut self, node: AnyNodeRef<'a>) -> TraversalSignal {
        self.visit_node(&node);
        TraversalSignal::Traverse
    }

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

    fn visit_expr(&mut self, expr: &'a Expr) {
        self.handle_expr_pre(expr);
        walk_expr(self, expr);
        self.handle_expr_post(expr);
    }

    fn visit_comprehension(&mut self, comprehension: &'a Comprehension) {
        self.visit_node(comprehension);
        walk_comprehension(self, comprehension);
        self.handle_assignment_target(&comprehension.target, &comprehension.iter);
    }

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
}
