use crate::indexer::encoding::{decode_bytes, unescape_to_bytes};
use crate::indexer::node_transformer::NodeTransformer;
use ruff_python_ast::{
    self as ast, AtomicNodeIndex, ExprContext, HasNodeIndex, NodeIndex, Operator,
    StringLiteralFlags,
};
use ruff_text_size::TextRange;

impl<'a> NodeTransformer<'a> {
    /// "".join(...)
    #[inline]
    pub(crate) fn handle_join_operation(
        &self,
        sep: &str,
        seq_expr: &ast::Expr,
        call_range: TextRange,
    ) -> Option<ast::Expr> {
        self.sequence_to_parts(seq_expr, false)
            .map(|parts| parts.join(sep))
            .map(|joined| self.make_string_expr(call_range, joined))
    }

    /// "a"+"b"+"c"
    #[inline]
    pub(crate) fn transform_binop(&self, binop: &mut ast::ExprBinOp) -> Option<ast::Expr> {
        // Children are already visited by the outer traversal.
        if let Operator::Add = binop.op
            && let (Some(l), Some(r)) = (
                self.extract_string(&binop.left),
                self.extract_string(&binop.right),
            )
        {
            return Some(self.make_string_expr(binop.range, l + &r));
        }
        None
    }

    // "x"[::-1]
    #[inline]
    pub(crate) fn transform_subscript(&self, sub: &mut ast::ExprSubscript) -> Option<ast::Expr> {
        // Children are already visited by the outer traversal.
        if self.is_reverse_slice(&sub.slice)
            && let Some(s) = self.extract_string(&sub.value)
        {
            let rev: String = s.chars().rev().collect();
            return Some(self.make_string_expr(sub.range, rev));
        }
        None
    }

    #[inline]
    pub(crate) fn transform_call(&self, call: &mut ast::ExprCall) -> Option<ast::Expr> {
        // Children are already visited by the outer traversal.
        if let ast::Expr::Attribute(attr) = call.func.as_ref() {
            // b"x".decode(...)
            if attr.attr.as_str() == "decode" {
                let s = self.extract_string(&attr.value)?;
                let mut encoding = "utf-8";
                if !call.arguments.args.is_empty() {
                    if let Some(enc) = self.extract_string(&call.arguments.args[0]) {
                        encoding = enc.leak();
                    }
                }

                if let Some(bytes) = unescape_to_bytes(&s) {
                    if let Some(res) = decode_bytes(&bytes, encoding) {
                        return Some(self.make_string_expr(call.range, res));
                    }
                }

                return Some(self.make_string_expr(call.range, s));
            }

            // "".join(...)
            if attr.attr.as_str() == "join"
                && call.arguments.keywords.is_empty()
                && call.arguments.args.len() == 1
            {
                if let Some(sep) = self.extract_string(&attr.value) {
                    let seq_expr = &call.arguments.args[0];
                    return self.handle_join_operation(&sep, seq_expr, call.range);
                }
                return None;
            }
        }

        let qualified = self.indexer.borrow().resolve_qualified_name(&call.func);

        if let Some(name) = qualified.as_ref()
            && (name.as_str() == "getattr"
                || name.as_str() == "builtins.getattr"
                || name.as_str() == "__builtins__.getattr")
            && call.arguments.keywords.is_empty()
            && call.arguments.args.len() == 2
        {
            let arg_name_res = self
                .indexer
                .borrow()
                .resolve_qualified_name(&call.arguments.args[0]);
            if let Some(arg_name) = arg_name_res
                && (arg_name.as_str() == "builtins" || arg_name.as_str() == "__builtins__")
            {
                if let Some(attr_name) = self.resolve_expr_to_string(&call.arguments.args[1]) {
                    let (name_id, attr_id, ident_id) = {
                        let mut indexer = self.indexer.borrow_mut();
                        (
                            indexer.get_atomic_index(),
                            indexer.get_atomic_index(),
                            indexer.get_atomic_index(),
                        )
                    };

                    let arg_name_str = arg_name.as_str();
                    return Some(ast::Expr::Attribute(ast::ExprAttribute {
                        node_index: attr_id,
                        range: call.range,
                        value: Box::new(ast::Expr::Name(ast::ExprName {
                            node_index: name_id,
                            range: call.range,
                            id: arg_name_str.into(),
                            ctx: ExprContext::Load,
                        })),
                        attr: ast::Identifier {
                            id: attr_name.into(),
                            range: call.range,
                            node_index: ident_id,
                        },
                        ctx: ExprContext::Load,
                    }));
                }
            }
        }

        // binascii.unhexlify(..) or bytes.fromhex(..)
        // Just extract them for now
        // TODO: handle it in a better way
        if let Some(name) = qualified.as_ref()
            && call.arguments.keywords.is_empty()
            && call.arguments.args.len() == 1
            && (name.as_str() == "binascii.unhexlify" || name.as_str() == "bytes.fromhex")
        {
            if let Some(arg_str) = self.extract_string(&call.arguments.args[0])
                && let Some(escaped) = hex_to_escaped(&arg_str)
            {
                return Some(self.make_string_expr(call.range, escaped));
            }
            return None;
        }

        // Handle os.path.expanduser
        if let Some(name) = qualified.as_ref()
            && name.as_str() == "os.path.expanduser"
            && call.arguments.keywords.is_empty()
            && call.arguments.args.len() == 1
        {
            if let Some(s) = self.extract_string(&call.arguments.args[0])
                && s == "~"
            {
                return Some(self.make_string_expr(call.range, "~".to_string()));
            }
            return None;
        }

        // Handle os.path.join
        if let Some(name) = qualified.as_ref()
            && name.as_str() == "os.path.join"
            && call.arguments.keywords.is_empty()
            && !call.arguments.args.is_empty()
        {
            if let Some(parts) = self.collect_string_elements(&call.arguments.args, false) {
                let joined = parts.join("/");
                return Some(self.make_string_expr(call.range, joined));
            }
            return None;
        }

        // Handle bytes([10,20, ..])
        if let ast::Expr::Name(name) = &*call.func
            && name.id.as_str() == "bytes"
            && call.arguments.keywords.is_empty()
            && call.arguments.args.len() == 1
            && let Some(codepoints) =
                self.collect_u32s_from_iterable(&call.arguments.args[0], false)
        {
            let s: String = codepoints
                .into_iter()
                .filter_map(std::char::from_u32)
                .collect();
            return Some(self.make_string_expr(call.range, s));
        }

        // Handle chr(100)
        if let ast::Expr::Name(name) = &*call.func
            && name.id.as_str() == "chr"
            && call.arguments.keywords.is_empty()
            && call.arguments.args.len() == 1
        {
            if let Some(cp) = self.extract_int_literal_u32(&call.arguments.args[0]) {
                if let Some(ch) = std::char::from_u32(cp) {
                    return Some(self.make_string_expr(call.range, ch.to_string()));
                }
            }
        }

        None
    }

    pub fn transform_strings(&self, expr: &mut ast::Expr) {
        let Some(node_id) = expr.node_index().load().as_u32() else {
            return;
        };

        if self.updated_strings.borrow().contains(&node_id) {
            return;
        }

        match expr {
            ast::Expr::StringLiteral(s) => {
                let Some(node_id) = s.node_index().load().as_u32() else {
                    return;
                };
                let content = self.collect_raw(s.value.iter().map(|r| r.range));
                let index = AtomicNodeIndex::NONE;
                index.set(NodeIndex::from(node_id));
                s.value = ast::StringLiteralValue::single(ast::StringLiteral {
                    value: Box::from(content),
                    range: s.range,
                    flags: StringLiteralFlags::empty(),
                    node_index: index,
                });
            }

            ast::Expr::BytesLiteral(b) => {
                let content = self.collect_raw(b.value.iter().map(|r| r.range));
                *expr = self.make_string_expr(b.range, content);
            }

            ast::Expr::FString(f) => {
                // Render f-string by resolving simple interpolations and preserving {name}
                // placeholders when resolution isn't possible.
                let rendered = self.render_fstring_value(&f.value);
                *expr = self.make_string_expr(f.range, rendered);
            }

            ast::Expr::BinOp(binop) => {
                if let Some(new_expr) = self.transform_binop(binop) {
                    *expr = new_expr;
                }
            }

            ast::Expr::Subscript(sub) => {
                if let Some(new_expr) = self.transform_subscript(sub) {
                    *expr = new_expr;
                }
            }

            ast::Expr::Call(call) => {
                if let Some(new_expr) = self.transform_call(call) {
                    *expr = new_expr;
                }
            }

            _ => {}
        }
    }
}

#[inline]
pub(crate) fn hex_to_escaped(input: &str) -> Option<String> {
    let filtered: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if filtered.is_empty() || !filtered.len().is_multiple_of(2) {
        return None;
    }
    filtered
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let h = chunk[0] as char;
            let l = chunk[1] as char;
            if h.is_ascii_hexdigit() && l.is_ascii_hexdigit() {
                Some(format!(
                    "\\x{}{}",
                    h.to_ascii_lowercase(),
                    l.to_ascii_lowercase()
                ))
            } else {
                None
            }
        })
        .collect()
}
