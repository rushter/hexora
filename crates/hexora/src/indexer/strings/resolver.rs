use crate::indexer::node_transformer::NodeTransformer;
use ruff_python_ast::visitor::transformer::Transformer;
use ruff_python_ast::{self as ast, HasNodeIndex};

impl<'a> NodeTransformer<'a> {
    pub(crate) fn get_resolved_exprs(&self, expr: &ast::Expr) -> Option<Vec<ast::Expr>> {
        let node_id = expr.node_index().load().as_u32()?;

        if let Some(cached) = self
            .indexer
            .model
            .transformed_exprs_cache
            .borrow()
            .get(&node_id)
        {
            return Some(cached.clone());
        }

        if !self
            .indexer
            .model
            .currently_resolving
            .borrow_mut()
            .insert(node_id)
        {
            return None;
        }

        let res = self
            .indexer
            .model
            .expr_mapping
            .get(&node_id)
            .cloned()
            .map(|exprs| {
                exprs
                    .iter()
                    .map(|&e| {
                        let mut cloned = e.clone();
                        self.visit_expr(&mut cloned);
                        cloned
                    })
                    .collect::<Vec<ast::Expr>>()
            });

        self.indexer
            .model
            .currently_resolving
            .borrow_mut()
            .remove(&node_id);

        if let Some(ref r) = res {
            self.indexer
                .model
                .transformed_exprs_cache
                .borrow_mut()
                .insert(node_id, r.clone());
        }

        res
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
        if matches!(expr, ast::Expr::Name(_)) {
            return self.resolve_variable_to_parts(expr, reverse);
        }

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

        if let Some(s) = self.extract_string(expr) {
            let mut out: Vec<u32> = s.chars().map(|c| c as u32).collect();
            if reverse {
                out.reverse();
            }
            return Some(out);
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

            // Handle (chr(x + 1) for x in data)
            // Only supports single generator without ifs for now
            ast::Expr::Generator(generator) => self.handle_comprehension_u32s(
                generator.elt.as_ref(),
                &generator.generators,
                reverse,
            ),
            ast::Expr::ListComp(list_comp) => self.handle_comprehension_u32s(
                list_comp.elt.as_ref(),
                &list_comp.generators,
                reverse,
            ),
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

    pub(crate) fn handle_comprehension_u32s(
        &self,
        elt: &ast::Expr,
        generators: &[ast::Comprehension],
        reverse: bool,
    ) -> Option<Vec<u32>> {
        if generators.len() != 1 {
            return None;
        }

        let comp = &generators[0];
        if !comp.ifs.is_empty() || comp.is_async {
            return None;
        }

        let target_name = if let ast::Expr::Name(name) = &comp.target {
            Some(name.id.as_str())
        } else {
            return None;
        };

        let base_values = self.collect_u32s_from_iterable(&comp.iter, reverse)?;
        let name = target_name.unwrap();

        let ast::Expr::Call(elt_call) = elt else {
            return None;
        };

        let is_chr_call = matches!(
            elt_call.func.as_ref(),
            ast::Expr::Name(name) if name.id.as_str() == "chr"
        );
        if !is_chr_call || elt_call.arguments.args.len() != 1 {
            return None;
        }

        let arg = &elt_call.arguments.args[0];
        base_values
            .into_iter()
            .map(|v| {
                self.evaluate_int_expr_with_var(arg, Some(name), v as i32)
                    .map(|v| v as u32)
            })
            .collect()
    }

    pub(crate) fn resolve_variable_to_parts(
        &self,
        expr: &ast::Expr,
        reverse: bool,
    ) -> Option<Vec<String>> {
        let resolved_exprs = self.get_resolved_exprs(expr)?;
        let mut final_parts: Option<Vec<String>> = None;

        for resolved in resolved_exprs {
            if let ast::Expr::Call(call) = &resolved {
                let Some(attr) = call.func.as_attribute_expr() else {
                    continue;
                };

                let method = attr.attr.as_str();
                match method {
                    "append" if !call.arguments.args.is_empty() => {
                        if let Some(parts) = final_parts.as_mut() {
                            if let Some(s) = self.resolve_expr_to_string(&call.arguments.args[0]) {
                                parts.push(s);
                            }
                        }
                    }
                    "extend" if !call.arguments.args.is_empty() => {
                        if let Some(parts) = final_parts.as_mut() {
                            if let Some(elts) =
                                self.sequence_to_parts(&call.arguments.args[0], false)
                            {
                                parts.extend(elts);
                            }
                        }
                    }
                    "insert" if call.arguments.args.len() >= 2 => {
                        if let Some(parts) = final_parts.as_mut() {
                            let idx = self.extract_int_literal_u32(&call.arguments.args[0]);
                            let val = self.resolve_expr_to_string(&call.arguments.args[1]);
                            if let (Some(idx), Some(val)) = (idx, val) {
                                let idx = (idx as usize).min(parts.len());
                                parts.insert(idx, val);
                            }
                        }
                    }
                    "reverse" => {
                        if let Some(parts) = final_parts.as_mut() {
                            parts.reverse();
                        }
                    }
                    _ => {}
                }
            } else if let Some(parts) = self.sequence_to_parts(&resolved, false) {
                if final_parts.is_none() {
                    final_parts = Some(parts);
                }
            } else if let ast::Expr::List(list) = resolved {
                if final_parts.is_none() && list.elts.is_empty() {
                    final_parts = Some(Vec::new());
                }
            }
        }

        if reverse {
            if let Some(parts) = final_parts.as_mut() {
                parts.reverse();
            }
        }

        final_parts
    }
}
