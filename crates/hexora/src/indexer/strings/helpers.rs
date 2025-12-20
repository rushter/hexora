use crate::indexer::node_transformer::NodeTransformer;
use ruff_python_ast::str::raw_contents;
use ruff_python_ast::{self as ast, StringLiteralFlags};
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

    pub(crate) fn make_string_expr(&self, range: TextRange, value: String) -> ast::Expr {
        let string_id = self.indexer.borrow_mut().get_atomic_index();
        self.updated_strings
            .borrow_mut()
            .insert(self.indexer.borrow().current_index());

        let inner_id = self.indexer.borrow_mut().get_atomic_index();

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
        let ast::Expr::NumberLiteral(num) = expr else {
            return None;
        };
        let int_ref = num.value.as_int()?;
        int_ref.as_u32()
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
