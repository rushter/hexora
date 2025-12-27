use crate::indexer::model::Transformation;
use crate::indexer::node_transformer::NodeTransformer;
use crate::indexer::taint::TaintState;
use hexora_io::encoding::{
    base64_decode, bytes_to_escaped, decode_bytes, hex_to_escaped, unescape_to_bytes,
};
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
        let transformation = self.get_transformation(seq_expr).or_else(|| {
            self.iterable_elts(seq_expr)
                .and_then(|elts| elts.iter().find_map(|e| self.get_transformation(e)))
                .or(Some(Transformation::Join))
        });

        self.sequence_to_parts(seq_expr, false)
            .map(|parts| parts.join(sep))
            .map(|joined| self.make_string_expr(call_range, joined, transformation))
    }

    /// "a"+"b"+"c"
    #[inline]
    pub(crate) fn transform_binop(&self, binop: &mut ast::ExprBinOp) -> Option<ast::Expr> {
        // Children are already visited by the outer traversal.
        if !matches!(binop.op, Operator::Add) {
            return None;
        }

        let transformation = self
            .get_transformation(&binop.left)
            .or_else(|| self.get_transformation(&binop.right))
            .or(Some(Transformation::Concat));

        let l = self.extract_string(&binop.left)?;
        let r = self.extract_string(&binop.right)?;

        Some(self.make_string_expr(binop.range, l + &r, transformation))
    }

    // "x"[::-1]
    #[inline]
    pub(crate) fn transform_subscript(&self, sub: &mut ast::ExprSubscript) -> Option<ast::Expr> {
        // Children are already visited by the outer traversal.
        if self.is_reverse_slice(&sub.slice)
            && let Some(s) = self.extract_string(&sub.value)
        {
            let transformation = self
                .get_transformation(&sub.value)
                .or(Some(Transformation::Subscript));
            let rev: String = s.chars().rev().collect();
            return Some(self.make_string_expr(sub.range, rev, transformation));
        }

        let base_exprs = self
            .get_resolved_exprs(&sub.value)
            .unwrap_or_else(|| vec![sub.value.as_ref().clone()]);
        for base in base_exprs {
            // Handle [a, b, c][1]
            if let Some(elts) = self.iterable_elts(&base) {
                if let Some(idx) = self.extract_int_literal_u32(&sub.slice) {
                    if (idx as usize) < elts.len() {
                        let res = elts[idx as usize].clone();
                        if let Some(id) = res.node_index().load().as_u32() {
                            self.indexer
                                .model
                                .decoded_nodes
                                .borrow_mut()
                                .insert(id, Transformation::Subscript);
                        }
                        self.add_deobfuscated_taint(res.node_index());
                        return Some(res);
                    }
                }
            }

            // Handle {"a": b}["a"]
            if let ast::Expr::Dict(d) = &base {
                if let Some(key_str) = self.resolve_expr_to_string(&sub.slice) {
                    for item in &d.items {
                        if let Some(k) = &item.key
                            && let Some(k_str) = self.resolve_expr_to_string(k)
                            && k_str == key_str
                        {
                            let res = item.value.clone();
                            if let Some(id) = res.node_index().load().as_u32() {
                                self.indexer
                                    .model
                                    .decoded_nodes
                                    .borrow_mut()
                                    .insert(id, Transformation::Subscript);
                            }
                            self.add_deobfuscated_taint(res.node_index());
                            return Some(res);
                        }
                    }
                }
            }
        }

        // Handle sys.modules["os"]
        let qualified = self.indexer.resolve_qualified_name(&sub.value);
        if let Some(name) = qualified
            && name.as_str() == "sys.modules"
        {
            let module_name = self.resolve_expr_to_string(&sub.slice)?;
            let res = self.make_module_expr(sub.range, &module_name);
            if let Some(expr) = &res {
                self.add_deobfuscated_taint(expr.node_index());
            }
            return res;
        }
        None
    }

    #[inline]
    pub(crate) fn transform_call(&self, call: &mut ast::ExprCall) -> Option<ast::Expr> {
        let qualified = self.indexer.resolve_qualified_name(&call.func);
        let segments = qualified.as_ref().map(|q| q.segments_slice());

        if let Some(res) = match segments {
            Some([name]) => match name.as_str() {
                "getattr" => self.handle_getattr_call(call, None),
                "bytes" => self.handle_bytes_constructor(call),
                "chr" => self.handle_chr_constructor(call),
                _ => None,
            },
            Some([m, name]) => match (m.as_str(), name.as_str()) {
                ("builtins" | "__builtins__", "getattr") => self.handle_getattr_call(call, None),
                ("importlib", "import_module") => self.handle_import_module_call(call),
                ("binascii", "unhexlify" | "a2b_base64") => self.handle_encoding_call(call, name),
                ("bytes", "fromhex") => self.handle_encoding_call(call, name),
                ("base64", "b64decode" | "urlsafe_b64decode") => {
                    self.handle_base64_call(call, name)
                }
                _ => None,
            },
            Some([m, p, name]) => match (m.as_str(), p.as_str(), name.as_str()) {
                ("os", "path", "expanduser") => self.handle_os_path_expanduser(call),
                ("os", "path", "join") => self.handle_os_path_join(call),
                _ => None,
            },
            _ => None,
        } {
            return Some(res);
        }

        // Handle method calls (e.g., "".join(), b"".decode())
        let attr = call.func.as_attribute_expr()?;
        let method = attr.attr.as_str();
        match method {
            "decode" => self.handle_decode_call(attr, call),
            "join" => self.handle_join_call(attr, call),
            "__getattr__" | "__getattribute__" | "getattr" => {
                self.handle_getattr_call(call, Some(attr.value.as_ref()))
            }
            "replace" | "strip" | "lower" | "upper" => {
                self.handle_string_method_call(method, attr, call)
            }
            _ => None,
        }
    }

    #[inline]
    fn handle_string_method_call(
        &self,
        method: &str,
        attr: &ast::ExprAttribute,
        call: &ast::ExprCall,
    ) -> Option<ast::Expr> {
        let s = self.extract_string(&attr.value)?;
        let result = match method {
            "replace" if call.arguments.args.len() >= 2 => {
                let old = self.resolve_expr_to_string(&call.arguments.args[0])?;
                let new = self.resolve_expr_to_string(&call.arguments.args[1])?;
                s.replace(&old, &new)
            }
            "strip" => s.trim().to_string(),
            "lower" => s.to_lowercase(),
            "upper" => s.to_uppercase(),
            _ => return None,
        };
        Some(self.make_string_expr(call.range, result, self.get_transformation(&attr.value)))
    }

    #[inline]
    fn handle_decode_call(
        &self,
        attr: &ast::ExprAttribute,
        call: &ast::ExprCall,
    ) -> Option<ast::Expr> {
        let s = self.extract_string(&attr.value)?;
        let encoding = call
            .arguments
            .args
            .first()
            .and_then(|arg| self.extract_string(arg))
            .unwrap_or_else(|| "utf-8".to_string());

        if let Some(bytes) = unescape_to_bytes(&s)
            && let Some(res) = decode_bytes(&bytes, &encoding)
        {
            return Some(self.make_string_expr(call.range, res, Some(Transformation::Other)));
        }

        Some(self.make_string_expr(call.range, s, None))
    }

    #[inline]
    fn handle_join_call(
        &self,
        attr: &ast::ExprAttribute,
        call: &ast::ExprCall,
    ) -> Option<ast::Expr> {
        if !call.arguments.keywords.is_empty() || call.arguments.args.len() != 1 {
            return None;
        }
        let sep = self.extract_string(&attr.value)?;
        let seq_expr = &call.arguments.args[0];
        self.handle_join_operation(&sep, seq_expr, call.range)
    }

    #[inline]
    fn handle_getattr_call(
        &self,
        call: &ast::ExprCall,
        base: Option<&ast::Expr>,
    ) -> Option<ast::Expr> {
        if !call.arguments.keywords.is_empty() || call.arguments.args.is_empty() {
            return None;
        }

        let (base_expr, attr_arg_idx) = if let Some(b) = base {
            (b, 0)
        } else {
            if call.arguments.args.len() < 2 {
                return None;
            }
            (&call.arguments.args[0], 1)
        };

        let attr_name = self.resolve_expr_to_string(&call.arguments.args[attr_arg_idx])?;
        let (attr_id, ident_id) = (
            self.indexer.get_atomic_index(),
            self.indexer.get_atomic_index(),
        );

        self.add_deobfuscated_taint(&attr_id);

        Some(ast::Expr::Attribute(ast::ExprAttribute {
            node_index: attr_id,
            range: call.range,
            value: Box::new(base_expr.clone()),
            attr: ast::Identifier {
                id: attr_name.into(),
                range: call.range,
                node_index: ident_id,
            },
            ctx: ExprContext::Load,
        }))
    }

    #[inline]
    fn handle_import_module_call(&self, call: &ast::ExprCall) -> Option<ast::Expr> {
        if !call.arguments.keywords.is_empty() || call.arguments.args.len() != 1 {
            return None;
        }

        let module_name = self.resolve_expr_to_string(&call.arguments.args[0])?;
        let res = self.make_module_expr(call.range, &module_name);
        if let Some(expr) = &res {
            self.add_deobfuscated_taint(expr.node_index());
        }
        res
    }

    #[inline]
    fn handle_encoding_call(&self, call: &ast::ExprCall, name: &str) -> Option<ast::Expr> {
        if !call.arguments.keywords.is_empty() || call.arguments.args.len() != 1 {
            return None;
        }

        let arg_str = self.extract_string(&call.arguments.args[0])?;
        if name == "a2b_base64" {
            let bytes = base64_decode(&arg_str, false)?;
            return Some(self.make_string_expr(
                call.range,
                bytes_to_escaped(&bytes),
                Some(Transformation::Base64),
            ));
        }

        let escaped = hex_to_escaped(&arg_str)?;
        Some(self.make_string_expr(call.range, escaped, Some(Transformation::Hex)))
    }

    #[inline]
    fn handle_os_path_expanduser(&self, call: &ast::ExprCall) -> Option<ast::Expr> {
        let arg = if call.arguments.args.len() == 1 {
            &call.arguments.args[0]
        } else if call.arguments.args.is_empty() {
            call.arguments
                .keywords
                .iter()
                .find(|kw| kw.arg.as_ref().is_some_and(|arg| arg.as_str() == "path"))
                .map(|kw| &kw.value)?
        } else {
            return None;
        };

        let s = self.resolve_expr_to_string(arg)?;
        let transformation = self.get_transformation(arg);
        Some(self.make_string_expr(call.range, s, transformation))
    }

    #[inline]
    fn handle_os_path_join(&self, call: &ast::ExprCall) -> Option<ast::Expr> {
        if !call.arguments.keywords.is_empty() || call.arguments.args.is_empty() {
            return None;
        }

        let parts = self.collect_string_elements(&call.arguments.args, false)?;
        let transformation = call
            .arguments
            .args
            .iter()
            .find_map(|e| self.get_transformation(e));
        let joined = parts.join("/");
        Some(self.make_string_expr(call.range, joined, transformation))
    }

    #[inline]
    fn handle_base64_call(&self, call: &ast::ExprCall, name: &str) -> Option<ast::Expr> {
        if !call.arguments.keywords.is_empty() || call.arguments.args.is_empty() {
            return None;
        }

        let arg_str = self.extract_string(&call.arguments.args[0])?;
        let bytes = base64_decode(&arg_str, name == "urlsafe_b64decode")?;

        let escaped = bytes_to_escaped(&bytes);
        Some(self.make_string_expr(call.range, escaped, Some(Transformation::Base64)))
    }

    #[inline]
    fn handle_bytes_constructor(&self, call: &ast::ExprCall) -> Option<ast::Expr> {
        if !call.arguments.keywords.is_empty() || call.arguments.args.len() != 1 {
            return None;
        }

        let codepoints = self.collect_u32s_from_iterable(&call.arguments.args[0], false)?;
        let s: String = codepoints
            .into_iter()
            .filter_map(std::char::from_u32)
            .collect();
        Some(self.make_string_expr(call.range, s, Some(Transformation::Other)))
    }

    #[inline]
    fn handle_chr_constructor(&self, call: &ast::ExprCall) -> Option<ast::Expr> {
        if !call.arguments.keywords.is_empty() || call.arguments.args.len() != 1 {
            return None;
        }

        let cp = self.extract_int_literal_u32(&call.arguments.args[0])?;
        let ch = std::char::from_u32(cp)?;
        Some(self.make_string_expr(call.range, ch.to_string(), Some(Transformation::Other)))
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
                self.updated_strings.borrow_mut().insert(node_id);
            }

            ast::Expr::BytesLiteral(b) => {
                let content = self.collect_raw(b.value.iter().map(|r| r.range));
                *expr = self.make_string_expr(b.range, content, None);
            }

            ast::Expr::FString(f) => {
                let mut taints = TaintState::new();
                for part in &f.value {
                    if let ast::FStringPart::FString(inner) = part {
                        for element in &inner.elements {
                            if let ast::InterpolatedStringElement::Interpolation(interp) = element {
                                taints.extend(self.indexer.get_taint(&interp.expression));
                            }
                        }
                    }
                }

                // Render f-string by resolving simple interpolations and preserving {name}
                // placeholders when resolution isn't possible.
                let rendered = self.render_fstring_value(&f.value);
                let new_expr =
                    self.make_string_expr(f.range, rendered, Some(Transformation::FString));
                if let Some(id) = new_expr.node_index().load().as_u32() {
                    self.indexer
                        .model
                        .taint_map
                        .borrow_mut()
                        .entry(id)
                        .or_default()
                        .extend(taints);
                }
                *expr = new_expr;
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
