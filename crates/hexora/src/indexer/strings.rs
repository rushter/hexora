use crate::indexer::node_transformer::NodeTransformer;
use ruff_python_ast::str::raw_contents;
use ruff_python_ast::visitor::transformer::Transformer;
use ruff_python_ast::{
    self as ast, AtomicNodeIndex, HasNodeIndex, NodeIndex, Operator, StringLiteralFlags,
};
use ruff_text_size::{Ranged, TextRange};

impl<'a> NodeTransformer<'a> {
    #[inline]
    fn iterable_elts<'e>(&self, expr: &'e ast::Expr) -> Option<&'e [ast::Expr]> {
        match expr {
            ast::Expr::List(l) => Some(&l.elts),
            ast::Expr::Tuple(t) => Some(&t.elts),
            _ => None,
        }
    }

    #[inline]
    fn call_is_simple_reversed<'e>(&self, call: &'e ast::ExprCall) -> Option<&'e ast::Expr> {
        let is_reversed =
            matches!(call.func.as_ref(), ast::Expr::Name(name) if name.id.as_str() == "reversed");
        if is_reversed && call.arguments.keywords.is_empty() && call.arguments.args.len() == 1 {
            Some(&call.arguments.args[0])
        } else {
            None
        }
    }

    #[inline]
    fn collect_u32s_from_elts(&self, elts: &[ast::Expr], reverse: bool) -> Option<Vec<u32>> {
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
    fn append_interpolated_elements(
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
    fn render_fstring_value(&self, value: &ast::FStringValue) -> String {
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
    fn collect_raw(&self, ranges: impl Iterator<Item = TextRange>) -> String {
        ranges
            .filter(|r| r.start() < r.end() && (r.end() - r.start()).to_usize() > 1)
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

    fn extract_int_literal_u32(&self, expr: &ast::Expr) -> Option<u32> {
        let ast::Expr::NumberLiteral(num) = expr else {
            return None;
        };
        let int_ref = num.value.as_int()?;
        int_ref.as_u32()
    }

    fn collect_u32s_from_iterable(&self, expr: &ast::Expr, reverse: bool) -> Option<Vec<u32>> {
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
            if attr.attr.as_str() == "decode" {
                if let Some(s) = self.extract_string(&attr.value) {
                    return Some(self.make_string_expr(call.range, s));
                }
                return None;
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

        let qualified = resolve_qualified_name(&call.func);

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
    fn test_fstring_variable_replacement_simple() {
        let source = unindent(
            r#"
            a = "world"
            s = f"hello {a}"
        "#,
        );
        let actual = get_strings(&source);
        assert!(actual.iter().any(|it| it.string == "world"));
        assert!(actual.iter().any(|it| it.string == "hello world"));
    }

    #[test]
    fn test_fstring_multiple_variable_replacement() {
        let source = unindent(
            r#"
            a = "A"
            b = "B"
            s = f"{a}-{b}"
        "#,
        );
        let actual = get_strings(&source);
        assert!(actual.iter().any(|it| it.string == "A"));
        assert!(actual.iter().any(|it| it.string == "B"));
        assert!(actual.iter().any(|it| it.string == "A-B"));
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

    #[test]
    fn test_join_map_chr_list() {
        let source = r#"a = "".join(map(chr, [97, 98, 99]))"#;
        let expected = vec![string_item!("abc", 4, 35)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_generator_chr_tuple() {
        let source = r#"a = "".join(chr(x) for x in (65, 66))"#;
        let expected = vec![string_item!("AB", 4, 37)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_bytes_decode() {
        let source = r#"a = bytes([98, 97, 115, 104]).decode()"#;
        let expected = vec![string_item!("bash", 4, 38)];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }
}
