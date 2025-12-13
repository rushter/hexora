use crate::indexer::node_transformer::NodeTransformer;
use itertools::Itertools;
use ruff_python_ast::str::raw_contents;
use ruff_python_ast::visitor::transformer::Transformer;
use ruff_python_ast::{
    self as ast, AtomicNodeIndex, HasNodeIndex, NodeIndex, Operator, StringLiteralFlags,
};
use ruff_text_size::{Ranged, TextRange};

impl<'a> NodeTransformer<'a> {
    fn collect_raw(&self, ranges: impl Iterator<Item = TextRange>) -> String {
        ranges
            .filter_map(|r| raw_contents(self.locator.slice(r)))
            .collect()
    }

    fn make_string_expr(&self, range: TextRange, value: String) -> ast::Expr {
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

    fn extract_string(&self, expr: &ast::Expr) -> Option<String> {
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

    fn get_resolved_exprs(&self, expr: &ast::Expr) -> Option<Vec<ast::Expr>> {
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

    fn resolve_expr_to_string(&self, expr: &ast::Expr) -> Option<String> {
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

    #[inline]
    fn is_reverse_slice(&self, slice_expr: &ast::Expr) -> bool {
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

    fn collect_string_elements(
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

    fn sequence_to_parts(&self, expr: &ast::Expr, reverse: bool) -> Option<Vec<String>> {
        match expr {
            ast::Expr::List(_) | ast::Expr::Tuple(_) => {
                let elts = match expr {
                    ast::Expr::List(l) => &l.elts,
                    ast::Expr::Tuple(t) => &t.elts,
                    _ => unreachable!(),
                };
                self.collect_string_elements(elts, reverse)
            }
            ast::Expr::Subscript(sub) if self.is_reverse_slice(&sub.slice) => {
                self.sequence_to_parts(&sub.value, !reverse)
            }
            ast::Expr::Call(inner_call) => {
                let is_reversed = matches!(inner_call.func.as_ref(), ast::Expr::Name(name) if name.id.as_str() == "reversed");
                if is_reversed
                    && inner_call.arguments.keywords.is_empty()
                    && inner_call.arguments.args.len() == 1
                {
                    self.sequence_to_parts(&inner_call.arguments.args[0], !reverse)
                } else {
                    None
                }
            }
            _ => {
                if let Some(s) = self.extract_string(expr) {
                    let mut parts: Vec<String> = s.chars().map(|c| c.to_string()).collect();
                    if reverse {
                        parts.reverse();
                    }
                    Some(parts)
                } else {
                    self.resolve_variable_to_parts(expr, reverse)
                }
            }
        }
    }

    fn resolve_variable_to_parts(&self, expr: &ast::Expr, reverse: bool) -> Option<Vec<String>> {
        let resolved_exprs = self.get_resolved_exprs(expr)?;
        for resolved in resolved_exprs {
            if let Some(parts) = self.sequence_to_parts(&resolved, reverse) {
                return Some(parts);
            }
        }
        None
    }

    /// "".join(...)
    #[inline]
    fn handle_join_operation(
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
    fn transform_binop(&self, binop: &mut ast::ExprBinOp) -> Option<ast::Expr> {
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
    fn transform_subscript(&self, sub: &mut ast::ExprSubscript) -> Option<ast::Expr> {
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
    fn transform_call(&self, call: &mut ast::ExprCall) -> Option<ast::Expr> {
        // Children are already visited by the outer traversal.
        if let ast::Expr::Attribute(attr) = call.func.as_ref() {
            // b"x".decode(...)
            if attr.attr.as_str() == "decode"
                && let Some(s) = self.extract_string(&attr.value)
            {
                return Some(self.make_string_expr(call.range, s));
            }

            // "".join(...)
            if attr.attr.as_str() == "join"
                && call.arguments.keywords.is_empty()
                && call.arguments.args.len() == 1
                && let Some(sep) = self.extract_string(&attr.value)
            {
                let seq_expr = &call.arguments.args[0];
                if let Some(result) = self.handle_join_operation(&sep, seq_expr, call.range) {
                    return Some(result);
                }
            }
        }

        // binascii.unhexlify(..) or bytes.fromhex(..)
        // Just extract them for now
        // TODO: handle it in a better way
        if let Some(name) = resolve_qualified_name(&call.func)
            && call.arguments.keywords.is_empty()
            && call.arguments.args.len() == 1
        {
            if (name == "binascii.unhexlify" || name == "bytes.fromhex")
                && let Some(arg_str) = self.extract_string(&call.arguments.args[0])
            {
                if let Some(escaped) = hex_to_escaped(&arg_str) {
                    return Some(self.make_string_expr(call.range, escaped));
                }
            }
        }

        // Handle os.path.expanduser
        if let Some(name) = resolve_qualified_name(&call.func)
            && name == "os.path.expanduser"
            && call.arguments.keywords.is_empty()
            && call.arguments.args.len() == 1
            && let Some(s) = self.extract_string(&call.arguments.args[0])
            && s == "~"
        {
            return Some(self.make_string_expr(call.range, "~".to_string()));
        }

        // Handle os.path.join
        if let Some(name) = resolve_qualified_name(&call.func)
            && name == "os.path.join"
            && call.arguments.keywords.is_empty()
            && !call.arguments.args.is_empty()
        {
            if let Some(parts) = self.collect_string_elements(&call.arguments.args, false) {
                let joined = parts.join("/");
                return Some(self.make_string_expr(call.range, joined));
            }
            return None;
        }

        None
    }

    pub fn transform_strings(&self, expr: &mut ast::Expr) {
        let Some(node_id) = expr.node_index().load().as_u32() else {
            return;
        };

        if self.updated_strings.borrow_mut().contains(&node_id) {
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
                // TODO: better interpolation in the future
                let content = f
                    .value
                    .iter()
                    .filter_map(|r| raw_contents(self.locator.slice(r)))
                    .join("");
                *expr = self.make_string_expr(f.range, content);
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

fn resolve_qualified_name(expr: &ast::Expr) -> Option<String> {
    match expr {
        ast::Expr::Name(name) => Some(name.id.to_string()),
        ast::Expr::Attribute(attr) => {
            resolve_qualified_name(&attr.value).map(|base| format!("{}.{}", base, attr.attr))
        }
        _ => None,
    }
}
#[inline]
fn hex_to_escaped(input: &str) -> Option<String> {
    let filtered: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if filtered.len() < 2 || !filtered.len().is_multiple_of(2) {
        return None;
    }
    let mut out = String::new();
    let bytes = filtered.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let h = bytes[i] as char;
        let l = bytes[i + 1] as char;
        if !(h.is_ascii_hexdigit() && l.is_ascii_hexdigit()) {
            return None;
        }
        out.push_str("\\x");
        out.push(h.to_ascii_lowercase());
        out.push(l.to_ascii_lowercase());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use crate::indexer::index::NodeIndexer;
    use crate::indexer::locator::Locator;
    use crate::indexer::strings::NodeTransformer;
    use ruff_python_ast::visitor::source_order::*;
    use ruff_python_ast::visitor::transformer::Transformer;
    use ruff_python_ast::*;
    use ruff_text_size::TextRange;
    use unindent::unindent;

    macro_rules! string_item {
        ($string:expr, $start:expr, $end:expr) => {
            StringItem {
                string: $string.to_string(),
                location: TextRange::new($start.into(), $end.into()),
            }
        };
    }

    #[derive(Debug, PartialEq)]
    pub struct StringItem {
        pub string: String,
        pub location: TextRange,
    }
    pub struct StringVisitor {
        pub strings: Vec<StringItem>,
    }
    impl StringVisitor {
        pub fn new() -> Self {
            Self { strings: vec![] }
        }
    }
    impl<'a> SourceOrderVisitor<'a> for StringVisitor {
        fn visit_string_literal(&mut self, string_literal: &'a StringLiteral) {
            self.strings.push(StringItem {
                string: string_literal.value.to_string(),
                location: string_literal.range,
            });
            walk_string_literal(self, string_literal);
        }
    }

    fn get_strings(source: &str) -> Vec<StringItem> {
        let parsed = ruff_python_parser::parse_unchecked_source(source, PySourceType::Python);
        let locator = Locator::new(source);
        let python_ast = parsed.suite();

        let mut indexer = NodeIndexer::new();
        indexer.visit_body(python_ast);
        let mut transformed_ast = python_ast.to_vec();
        let transformer = NodeTransformer::new(&locator, indexer);
        transformer.visit_body(&mut transformed_ast);
        let mut visitor = StringVisitor::new();
        visitor.visit_body(&transformed_ast);
        visitor.strings
    }

    #[test]
    fn test_string_concatenation() {
        let source = r#"a = "print"+"(123)"+";"+"123""#;
        let expected = vec![string_item!("print(123);123", 4, 29)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_string_interpolation() {
        let source = r#"a = f"print({a},{b})""#;
        let expected = vec![string_item!("print({a},{b})", 4, 21)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_on_list() {
        let source = r#"a = "".join(["te","st"])"#;
        let expected = vec![string_item!("test", 4, 24)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }
    #[test]
    fn test_join_on_tuple() {
        let source = r#"a = "".join(("te","st", "ing"))"#;
        let expected = vec![string_item!("testing", 4, 31)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_with_space_delimiter() {
        let source = r#"a = " ".join(["te","st"])"#;
        let expected = vec![string_item!("te st", 4, 25)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_with_dash_delimiter_tuple() {
        let source = r#"a = "-".join(("a","b","c"))"#;
        let expected = vec![string_item!("a-b-c", 4, 27)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_reverse_slice_on_string() {
        let source = r#"a = "abc"[::-1]"#;
        let expected = vec![string_item!("cba", 4, 15)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_reversed_list() {
        let source = r#"a = "".join(reversed(["tion","mo"]))"#;
        let expected = vec![string_item!("motion", 4, 36)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_list_slice_reverse() {
        let source = r#"a = "".join(["a","b","c"][::-1])"#;
        let expected = vec![string_item!("cba", 4, 32)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_reversed_tuple_with_delim() {
        let source = r#"a = "-".join(reversed(("a","b","c")))"#;
        let expected = vec![string_item!("c-b-a", 4, 37)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_reversed_string_with_delim() {
        let source = r#"a = ".".join(reversed("ab"))"#;
        let expected = vec![string_item!("b.a", 4, 28)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_string_slice_reverse_with_delim() {
        let source = r#"a = ".".join("ab"[::-1])"#;
        let expected = vec![string_item!("b.a", 4, 24)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_decode_on_string_literal() {
        let source = r#"a = "hello".decode("utf-8")"#;
        let expected = vec![string_item!("hello", 4, 27)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_decode_on_concatenated_string() {
        let source = r#"a = ("he"+"llo").decode("utf-8")"#;
        let expected = vec![string_item!("hello", 4, 32)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_decode_with_no_args() {
        let source = r#"a = b"x".decode()"#;
        let expected = vec![string_item!("x", 4, 17)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_with_variables() {
        let source = unindent(
            r#"
             a = "cool"
             c = "".join(["the_",a, "_string"])
        "#,
        );
        let expected = vec![
            string_item!("cool", 4, 10),
            string_item!("the_cool_string", 15, 45),
        ];
        let actual = get_strings(&source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_var() {
        let source = unindent(
            r#"
             a = ["the_", "cool", "_string"]
             c = "".join(a)
        "#,
        );
        let expected = vec![
            string_item!("the_", 5, 11),
            string_item!("cool", 13, 19),
            string_item!("_string", 21, 30),
            string_item!("the_cool_string", 36, 46),
        ];
        let actual = get_strings(&source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_os_path_join() {
        let source = r#"a = os.path.join("~/.ssh", "id_rsa")"#;
        let expected = vec![string_item!("~/.ssh/id_rsa", 4, 36)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_os_path_expanduser() {
        let source = r#"a = os.path.expanduser("~")"#;
        let expected = vec![string_item!("~", 4, 27)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_os_path_join_with_expanduser() {
        let source = r#"a = os.path.join(os.path.expanduser("~"), ".aws", "credentials")"#;
        let expected = vec![string_item!("~/.aws/credentials", 4, 64)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_binascii_unhexlify() {
        let source = r#"a = binascii.unhexlify("414243")"#;
        let actual = get_strings(source);
        assert!(actual.iter().any(|it| it.string == "\\x41\\x42\\x43"));
    }

    #[test]
    fn test_bytes_fromhex_with_spaces() {
        let source = r#"a = bytes.fromhex("41 42 43")"#;
        let actual = get_strings(source);
        assert!(actual.iter().any(|it| it.string == "\\x41\\x42\\x43"));
    }
}
