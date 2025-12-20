use crate::indexer::node_transformer::NodeTransformer;
use ruff_python_ast::visitor::transformer::Transformer;
use ruff_python_ast::{self as ast, HasNodeIndex};

impl<'a> NodeTransformer<'a> {
    pub(crate) fn get_resolved_exprs(&self, expr: &ast::Expr) -> Option<Vec<ast::Expr>> {
        let node_id = expr.node_index().load().as_u32()?;
        let exprs = self.indexer.borrow().expr_mapping.get(&node_id).cloned()?;
        Some(
            exprs
                .iter()
                .map(|&e| {
                    let mut cloned = e.clone();
                    self.visit_expr(&mut cloned);
                    cloned
                })
                .collect(),
        )
    }

    pub(crate) fn resolve_expr_to_string(&self, expr: &ast::Expr) -> Option<String> {
        if let Some(s) = self.extract_string(expr) {
            return Some(s);
        }

        let resolved_exprs = self.get_resolved_exprs(expr)?;

        let mut resolved = String::new();
        for mapped in resolved_exprs.iter() {
            if let Some(s) = self.extract_string(mapped) {
                resolved.push_str(&s);
            } else {
                // N.B.: We currently abort if any part cannot be resolved to a string.
                return None;
            }
        }
        Some(resolved)
    }

    pub(crate) fn collect_string_elements(
        &self,
        elements: &[ast::Expr],
        reverse: bool,
    ) -> Option<Vec<String>> {
        let mut parts = elements
            .iter()
            .map(|e| self.resolve_expr_to_string(e))
            .collect::<Option<Vec<String>>>()?;

        if reverse {
            parts.reverse();
        }

        Some(parts)
    }

    pub(crate) fn sequence_to_parts(&self, expr: &ast::Expr, reverse: bool) -> Option<Vec<String>> {
        if let Some(codepoints) = self.collect_u32s_from_iterable(expr, reverse) {
            return codepoints
                .into_iter()
                .map(|cp| std::char::from_u32(cp).map(|ch| ch.to_string()))
                .collect();
        }

        if let Some(elts) = self.iterable_elts(expr) {
            return self.collect_string_elements(elts, reverse);
        }

        if let ast::Expr::Subscript(sub) = expr
            && self.is_reverse_slice(&sub.slice)
        {
            return self.sequence_to_parts(&sub.value, !reverse);
        }

        if let ast::Expr::Call(inner_call) = expr {
            if let Some(arg) = self.call_is_simple_reversed(inner_call) {
                return self.sequence_to_parts(arg, !reverse);
            } else {
                return None;
            }
        }

        if let Some(s) = self.extract_string(expr) {
            let mut parts: Vec<String> = s.chars().map(|c| c.to_string()).collect();
            if reverse {
                parts.reverse();
            }
            return Some(parts);
        }

        self.resolve_variable_to_parts(expr, reverse)
    }

    pub(crate) fn collect_u32s_from_iterable(
        &self,
        expr: &ast::Expr,
        reverse: bool,
    ) -> Option<Vec<u32>> {
        if let Some(elts) = self.iterable_elts(expr) {
            return self.collect_u32s_from_elts(elts, reverse);
        }

        match expr {
            ast::Expr::Subscript(sub) if self.is_reverse_slice(&sub.slice) => {
                self.collect_u32s_from_iterable(&sub.value, !reverse)
            }
            ast::Expr::Call(inner_call) => {
                if let Some(arg) = self.call_is_simple_reversed(inner_call) {
                    return self.collect_u32s_from_iterable(arg, !reverse);
                }

                // Support: map(chr, iterable)
                let is_map = matches!(inner_call.func.as_ref(), ast::Expr::Name(name) if name.id.as_str() == "map");
                if is_map
                    && inner_call.arguments.keywords.is_empty()
                    && inner_call.arguments.args.len() == 2
                    && matches!(&inner_call.arguments.args[0], ast::Expr::Name(name) if name.id.as_str() == "chr")
                {
                    let iter_expr = &inner_call.arguments.args[1];
                    return self.collect_u32s_from_iterable(iter_expr, reverse);
                }

                None
            }

            // Handle (chr(x) for x in data)
            // Only supports single generator without ifs for now
            ast::Expr::Generator(generator) => {
                if generator.generators.len() != 1 {
                    return None;
                }
                let ast::Expr::Call(elt_call) = generator.elt.as_ref() else {
                    return None;
                };
                let is_chr_call = matches!(
                    elt_call.func.as_ref(),
                    ast::Expr::Name(name) if name.id.as_str() == "chr"
                );
                if !is_chr_call || elt_call.arguments.len() != 1 {
                    return None;
                }
                let comp = &generator.generators[0];
                if !comp.ifs.is_empty() || comp.is_async {
                    return None;
                }
                self.collect_u32s_from_iterable(&comp.iter, reverse)
            }
            _ => {
                if let Some(resolved_exprs) = self.get_resolved_exprs(expr) {
                    for e in resolved_exprs {
                        if let Some(v) = self.collect_u32s_from_iterable(&e, reverse) {
                            return Some(v);
                        }
                    }
                }
                None
            }
        }
    }

    pub(crate) fn resolve_variable_to_parts(
        &self,
        expr: &ast::Expr,
        reverse: bool,
    ) -> Option<Vec<String>> {
        let resolved_exprs = self.get_resolved_exprs(expr)?;
        for resolved in resolved_exprs {
            if let Some(parts) = self.sequence_to_parts(&resolved, reverse) {
                return Some(parts);
            }
        }
        None
    }
}
