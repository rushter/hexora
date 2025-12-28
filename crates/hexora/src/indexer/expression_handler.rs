use crate::indexer::index::NodeIndexer;
use ruff_python_ast::*;

impl<'a> NodeIndexer<'a> {
    pub(crate) fn handle_expr(&mut self, expr: &'a Expr) {
        match expr {
            Expr::Call(call) => self.handle_call_expr(call, expr),
            Expr::Name(name) => self.handle_name_expr(name, expr),
            Expr::Attribute(attr) => self.handle_attribute_expr(attr, expr),
            _ => {}
        }
    }

    pub(crate) fn handle_call_expr(&mut self, call: &'a ExprCall, expr: &'a Expr) {
        self.handle_method_call_mutation(expr, call);
        if let Some(qn) = self.resolve_qualified_name(&call.func)
            && let Some(id) = expr.node_index().load().as_u32()
        {
            self.model.call_qualified_names.insert(id, qn);
        }
    }

    pub(crate) fn handle_name_expr(&mut self, name: &'a ExprName, expr: &'a Expr) {
        if matches!(name.ctx, ExprContext::Load) {
            self.handle_name_load(name.id.as_str(), expr);
        }
    }

    pub(crate) fn handle_attribute_expr(&mut self, attr: &'a ExprAttribute, expr: &'a Expr) {
        if matches!(attr.ctx, ExprContext::Load) {
            self.handle_attribute_load(&attr.value, attr.attr.as_str(), expr);
        }
    }

    pub(crate) fn handle_name_load(&mut self, id: &str, expr: &'a Expr) {
        if let Some(binding) = self.lookup_binding(id)
            && let Some(node_id) = expr.node_index().load().as_u32()
        {
            let exprs = binding.assigned_expressions.clone();
            let taint = binding.taint.clone();

            if !exprs.is_empty() {
                self.model
                    .expr_mapping
                    .entry(node_id)
                    .or_default()
                    .extend(exprs);
            }

            if !taint.is_empty() {
                self.model
                    .taint_map
                    .borrow_mut()
                    .entry(node_id)
                    .or_default()
                    .extend(taint);
            }
        }
    }

    pub(crate) fn handle_attribute_load(&mut self, obj: &'a Expr, attr: &str, expr: &'a Expr) {
        if let Expr::Name(ExprName { id: base_name, .. }) = obj
            && base_name.as_str() == "self"
            && let Some(idx) = self.find_class_scope()
            && let Some(binding) = self.scope_stack[idx].symbols.get(attr)
            && let Some(node_id) = expr.node_index().load().as_u32()
        {
            let exprs = binding.assigned_expressions.clone();
            let taint = binding.taint.clone();

            if !exprs.is_empty() {
                self.model
                    .expr_mapping
                    .entry(node_id)
                    .or_default()
                    .extend(exprs);
            }

            if !taint.is_empty() {
                self.model
                    .taint_map
                    .borrow_mut()
                    .entry(node_id)
                    .or_default()
                    .extend(taint);
            }
        }
    }
}
