use crate::indexer::model::Transformation;
use crate::indexer::node_transformer::NodeTransformer;
use crate::indexer::taint::TaintKind;
use ruff_python_ast::str::raw_contents;
use ruff_python_ast::{self as ast, AtomicNodeIndex, HasNodeIndex, StringLiteralFlags};
use ruff_text_size::{Ranged, TextRange};

impl<'a> NodeTransformer<'a> {
    #[inline]
    pub(crate) fn iterable_elts<'e>(&self, expr: &'e ast::Expr) -> Option<&'e [ast::Expr]> {
        match expr {
            ast::Expr::List(l) => Some(&l.elts),
            ast::Expr::Tuple(t) => Some(&t.elts),
            _ => None,
        }
    }

    #[inline]
    pub(crate) fn call_is_simple_reversed<'e>(
        &self,
        call: &'e ast::ExprCall,
    ) -> Option<&'e ast::Expr> {
        let is_reversed =
            matches!(call.func.as_ref(), ast::Expr::Name(name) if name.id.as_str() == "reversed");
        if is_reversed && call.arguments.keywords.is_empty() && call.arguments.args.len() == 1 {
            Some(&call.arguments.args[0])
        } else {
            None
        }
    }

    #[inline]
    pub(crate) fn collect_u32s_from_elts(
        &self,
        elts: &[ast::Expr],
        reverse: bool,
    ) -> Option<Vec<u32>> {
        let mut out: Vec<u32> = elts
            .iter()
            .map(|e| self.extract_int_literal_u32(e))
            .collect::<Option<Vec<u32>>>()?;
        if reverse {
            out.reverse();
        }
        Some(out)
    }

    #[inline]
    pub(crate) fn append_interpolated_elements(
        &self,
        elements: &ast::InterpolatedStringElements,
        out: &mut String,
    ) {
        for element in elements {
            if let Some(literal) = element.as_literal() {
                out.push_str(literal);
                continue;
            }

            if let Some(interp) = element.as_interpolation() {
                // Try to resolve the expression into a concrete string, preserver original syntax
                // if resolution fails.
                if let Some(resolved) = self.resolve_expr_to_string(interp.expression.as_ref()) {
                    out.push_str(&resolved);
                } else if let ast::Expr::Name(name) = interp.expression.as_ref() {
                    out.push_str(&format!("{{{}}}", name.id.as_str()));
                }
            }
        }
    }

    #[inline]
    pub(crate) fn render_fstring_value(&self, value: &ast::FStringValue) -> String {
        let mut out = String::new();
        for part in value.iter() {
            match part {
                ast::FStringPart::Literal(lit) => out.push_str(lit.as_str()),
                ast::FStringPart::FString(fstring) => {
                    self.append_interpolated_elements(&fstring.elements, &mut out);
                }
            }
        }
        out
    }

    pub(crate) fn collect_raw(&self, ranges: impl Iterator<Item = TextRange>) -> String {
        ranges
            .filter(|r| r.start() < r.end() && (r.end() - r.start()).to_usize() > 1)
            .filter_map(|r| raw_contents(self.locator.slice(r)))
            .collect()
    }

    pub(crate) fn get_transformation(&self, expr: &ast::Expr) -> Option<Transformation> {
        if let Some(id) = expr.node_index().load().as_u32() {
            return self.indexer.model.decoded_nodes.borrow().get(&id).copied();
        }
        None
    }

    pub(crate) fn add_deobfuscated_taint(&self, node_index: &AtomicNodeIndex) {
        if let Some(id) = node_index.load().as_u32() {
            self.indexer.add_taint(id, TaintKind::Deobfuscated);
        }
    }

    pub(crate) fn make_string_expr(
        &self,
        range: TextRange,
        value: String,
        transformation: Option<Transformation>,
    ) -> ast::Expr {
        let string_id = self.indexer.get_atomic_index();
        let sid_u32 = string_id.load().as_u32();

        self.updated_strings
            .borrow_mut()
            .insert(self.indexer.current_index());

        let inner_id = self.indexer.get_atomic_index();

        if let Some(t) = transformation {
            if let Some(id) = sid_u32 {
                self.indexer.model.decoded_nodes.borrow_mut().insert(id, t);
                // N.B. We should not treat simple string modifications as deobfuscation,
                // this results in many false positives.
                if matches!(
                    t,
                    Transformation::Base64 | Transformation::Hex | Transformation::Other
                ) {
                    self.indexer.add_taint(id, TaintKind::Decoded);
                    self.indexer.add_taint(id, TaintKind::Deobfuscated);
                }
            }
        }

        ast::Expr::StringLiteral(ast::ExprStringLiteral {
            node_index: string_id,
            range,
            value: ast::StringLiteralValue::single(ast::StringLiteral {
                value: Box::from(value),
                range,
                flags: StringLiteralFlags::empty(),
                node_index: inner_id,
            }),
        })
    }

    pub(crate) fn make_module_expr(
        &self,
        range: TextRange,
        module_name: &str,
    ) -> Option<ast::Expr> {
        let mut parts = module_name.split('.');
        let first = parts.next()?;
        let mut expr = ast::Expr::Name(ast::ExprName {
            node_index: self.indexer.get_atomic_index(),
            range,
            id: first.into(),
            ctx: ast::ExprContext::Load,
        });

        for part in parts {
            let node_index = self.indexer.get_atomic_index();
            let attr_node_index = self.indexer.get_atomic_index();
            expr = ast::Expr::Attribute(ast::ExprAttribute {
                node_index,
                range,
                value: Box::new(expr),
                attr: ast::Identifier {
                    id: part.into(),
                    range,
                    node_index: attr_node_index,
                },
                ctx: ast::ExprContext::Load,
            });
        }
        Some(expr)
    }

    pub(crate) fn extract_string(&self, expr: &ast::Expr) -> Option<String> {
        match expr {
            ast::Expr::StringLiteral(s) => {
                let sid = s.node_index.load().as_u32()?;
                if self.updated_strings.borrow().contains(&sid) {
                    return s.value.iter().next().map(|seg| seg.value.to_string());
                }
                Some(self.collect_raw(s.value.iter().map(|r| r.range)))
            }
            _ => None,
        }
    }

    pub(crate) fn extract_int_literal_u32(&self, expr: &ast::Expr) -> Option<u32> {
        self.evaluate_int_expr(expr)
    }

    pub(crate) fn evaluate_int_expr(&self, expr: &ast::Expr) -> Option<u32> {
        self.evaluate_int_expr_with_var(expr, None, 0)
            .map(|v| v as u32)
    }

    pub(crate) fn evaluate_int_expr_with_var(
        &self,
        expr: &ast::Expr,
        var_name: Option<&str>,
        var_val: i32,
    ) -> Option<i32> {
        match expr {
            ast::Expr::NumberLiteral(num) => Some(num.value.as_int()?.as_u32()? as i32),
            ast::Expr::Name(name) if var_name == Some(name.id.as_str()) => Some(var_val),
            ast::Expr::Call(call) => {
                let name = matches!(call.func.as_ref(), ast::Expr::Name(name) if name.id.as_str() == "ord");
                if name && call.arguments.args.len() == 1 {
                    return self.evaluate_int_expr_with_var(
                        &call.arguments.args[0],
                        var_name,
                        var_val,
                    );
                }
                None
            }
            ast::Expr::BinOp(bin) => {
                let left = self.evaluate_int_expr_with_var(&bin.left, var_name, var_val)?;
                let right = self.evaluate_int_expr_with_var(&bin.right, var_name, var_val)?;
                match bin.op {
                    ast::Operator::Add => left.checked_add(right),
                    ast::Operator::Sub => left.checked_sub(right),
                    ast::Operator::Mult => left.checked_mul(right),
                    ast::Operator::Div => {
                        if right == 0 {
                            None
                        } else {
                            left.checked_div(right)
                        }
                    }
                    ast::Operator::Mod => {
                        if right == 0 {
                            None
                        } else {
                            Some(left.rem_euclid(right))
                        }
                    }
                    _ => None,
                }
            }
            _ => {
                if let Some(resolved_exprs) = self.get_resolved_exprs(expr) {
                    for e in resolved_exprs {
                        if let Some(val) = self.evaluate_int_expr_with_var(&e, var_name, var_val) {
                            return Some(val);
                        }
                    }
                }
                None
            }
        }
    }

    #[inline]
    pub(crate) fn is_reverse_slice(&self, slice_expr: &ast::Expr) -> bool {
        if let ast::Expr::Slice(slc) = slice_expr
            && slc.lower.is_none()
            && slc.upper.is_none()
            && let Some(step) = &slc.step
        {
            let text = self.locator.slice(step.range());
            return text.trim() == "-1";
        }
        false
    }
}
