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

    #[inline]
    fn is_reverse_slice(&self, slice_expr: &ast::Expr) -> bool {
        if let ast::Expr::Slice(slc) = slice_expr {
            if slc.lower.is_none() && slc.upper.is_none() {
                if let Some(step) = &slc.step {
                    let text = self.locator.slice(step.range());
                    return text.trim() == "-1";
                }
            }
        }
        false
    }

    fn collect_string_elements(
        &self,
        elements: &[ast::Expr],
        reverse: bool,
    ) -> Option<Vec<String>> {
        let mut parts: Vec<String> = Vec::with_capacity(elements.len());

        for element in elements {
            if let Some(s) = self.extract_string(element) {
                parts.push(s);
            } else {
                // Try to resolve through expression mapping
                let node_id = element.node_index().load().as_u32()?;
                let exprs_opt: Option<Vec<&ast::Expr>> = {
                    let indexer = self.indexer.borrow();
                    indexer.expr_mapping.get(&node_id).cloned()
                };
                if let Some(exprs) = exprs_opt {
                    let mut resolved = String::new();
                    let mut any = false;
                    for mapped in exprs.iter() {
                        let mut mapped_clone = (*mapped).clone();
                        self.visit_expr(&mut mapped_clone);
                        if let Some(s) = self.extract_string(&mapped_clone) {
                            resolved.push_str(&s);
                            any = true;
                        } else {
                            any = false;
                            resolved.clear();
                            break;
                        }
                    }
                    if any {
                        parts.push(resolved);
                        continue;
                    }
                }
                return None;
            }
        }

        if reverse {
            parts.reverse();
        }

        Some(parts)
    }

    fn sequence_to_parts(&self, expr: &ast::Expr, reverse: bool) -> Option<Vec<String>> {
        match expr {
            ast::Expr::List(list) => self.collect_string_elements(&list.elts, reverse),
            ast::Expr::Tuple(tuple) => self.collect_string_elements(&tuple.elts, reverse),
            ast::Expr::Subscript(sub) if self.is_reverse_slice(&sub.slice) => {
                self.sequence_to_parts(&sub.value, !reverse)
            }
            ast::Expr::Call(inner_call) => {
                // reversed(x)
                let is_reversed = matches!(inner_call.func.as_ref(), ast::Expr::Name(name) if name.id.as_str() == "reversed");
                if is_reversed
                    && inner_call.arguments.keywords.is_empty()
                    && inner_call.arguments.args.len() == 1
                {
                    return self.sequence_to_parts(&inner_call.arguments.args[0], !reverse);
                }
                None
            }
            _ => {
                if let Some(s) = self.extract_string(expr) {
                    let mut parts: Vec<String> = s.chars().map(|c| c.to_string()).collect();
                    if reverse {
                        parts.reverse();
                    }
                    return Some(parts);
                }

                // Resolve variable
                let node_id = expr.node_index().load().as_u32()?;
                let exprs_opt: Option<Vec<&ast::Expr>> = {
                    let indexer = self.indexer.borrow();
                    indexer.expr_mapping.get(&node_id).cloned()
                };
                if let Some(exprs) = exprs_opt {
                    for mapped in exprs.iter() {
                        let mut mapped_clone = (*mapped).clone();
                        // Normalize nested constructs
                        self.visit_expr(&mut mapped_clone);
                        if let Some(parts) = self.sequence_to_parts(&mapped_clone, reverse) {
                            return Some(parts);
                        }
                    }
                }
                None
            }
        }
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
        if let Operator::Add = binop.op {
            if let (Some(l), Some(r)) = (
                self.extract_string(&binop.left),
                self.extract_string(&binop.right),
            ) {
                return Some(self.make_string_expr(binop.range, l + &r));
            }
        }
        None
    }

    // "x"[::-1]
    #[inline]
    fn transform_subscript(&self, sub: &mut ast::ExprSubscript) -> Option<ast::Expr> {
        // Children are already visited by the outer traversal.
        if self.is_reverse_slice(&sub.slice) {
            if let Some(s) = self.extract_string(&sub.value) {
                let rev: String = s.chars().rev().collect();
                return Some(self.make_string_expr(sub.range, rev));
            }
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
            }

            // "".join(...)
            if attr.attr.as_str() == "join"
                && call.arguments.keywords.is_empty()
                && call.arguments.args.len() == 1
            {
                if let Some(sep) = self.extract_string(&attr.value) {
                    let seq_expr = &call.arguments.args[0];
                    if let Some(result) = self.handle_join_operation(&sep, seq_expr, call.range) {
                        return Some(result);
                    }
                }
            }
        }

        // Handle os.path.join
        if let Some(name) = resolve_qualified_name(&call.func) {
            if name == "os.path.join"
                && call.arguments.keywords.is_empty()
                && !call.arguments.args.is_empty()
            {
                let mut parts = Vec::new();
                for arg in &call.arguments.args {
                    if let Some(s) = self.extract_string(arg) {
                        parts.push(s);
                    } else {
                        return None;
                    }
                }
                let joined = parts.join("/");
                return Some(self.make_string_expr(call.range, joined));
            }
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
        let expected = vec![StringItem {
            string: "print(123);123".to_string(),
            location: TextRange::new(4.into(), 29.into()),
        }];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_string_interpolation() {
        let source = r#"a = f"print({a},{b})""#;
        let expected = vec![StringItem {
            string: "print({a},{b})".to_string(),
            location: TextRange::new(4.into(), 21.into()),
        }];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_on_list() {
        let source = r#"a = "".join(["te","st"])"#;
        let expected = vec![StringItem {
            string: "test".to_string(),
            location: TextRange::new(4.into(), 24.into()),
        }];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }
    #[test]
    fn test_join_on_tuple() {
        let source = r#"a = "".join(("te","st", "ing"))"#;
        let expected = vec![StringItem {
            string: "testing".to_string(),
            location: TextRange::new(4.into(), 31.into()),
        }];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_with_space_delimiter() {
        let source = r#"a = " ".join(["te","st"])"#;
        let expected = vec![StringItem {
            string: "te st".to_string(),
            location: TextRange::new(4.into(), 25.into()),
        }];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_with_dash_delimiter_tuple() {
        let source = r#"a = "-".join(("a","b","c"))"#;
        let expected = vec![StringItem {
            string: "a-b-c".to_string(),
            location: TextRange::new(4.into(), 27.into()),
        }];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_reverse_slice_on_string() {
        let source = r#"a = "abc"[::-1]"#;
        let expected = vec![StringItem {
            string: "cba".to_string(),
            location: TextRange::new(4.into(), 15.into()),
        }];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_reversed_list() {
        let source = r#"a = "".join(reversed(["a","b"]))"#;
        let expected = vec![StringItem {
            string: "ba".to_string(),
            location: TextRange::new(4.into(), 32.into()),
        }];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_list_slice_reverse() {
        let source = r#"a = "".join(["a","b","c"][::-1])"#;
        let expected = vec![StringItem {
            string: "cba".to_string(),
            location: TextRange::new(4.into(), 32.into()),
        }];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_reversed_tuple_with_delim() {
        let source = r#"a = "-".join(reversed(("a","b","c")))"#;
        let expected = vec![StringItem {
            string: "c-b-a".to_string(),
            location: TextRange::new(4.into(), 37.into()),
        }];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_reversed_string_with_delim() {
        let source = r#"a = ".".join(reversed("ab"))"#;
        let expected = vec![StringItem {
            string: "b.a".to_string(),
            location: TextRange::new(4.into(), 28.into()),
        }];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_join_string_slice_reverse_with_delim() {
        let source = r#"a = ".".join("ab"[::-1])"#;
        let expected = vec![StringItem {
            string: "b.a".to_string(),
            location: TextRange::new(4.into(), 24.into()),
        }];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_decode_on_string_literal() {
        let source = r#"a = "hello".decode("utf-8")"#;
        let expected = vec![StringItem {
            string: "hello".to_string(),
            location: TextRange::new(4.into(), 27.into()),
        }];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_decode_on_concatenated_string() {
        let source = r#"a = ("he"+"llo").decode("utf-8")"#;
        let expected = vec![StringItem {
            string: "hello".to_string(),
            location: TextRange::new(4.into(), 32.into()),
        }];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_decode_with_no_args() {
        let source = r#"a = b"x".decode()"#;
        let expected = vec![StringItem {
            string: "x".to_string(),
            location: TextRange::new(4.into(), 17.into()),
        }];
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
            StringItem {
                string: "cool".to_string(),
                location: TextRange::new(4.into(), 10.into()),
            },
            StringItem {
                string: "the_cool_string".to_string(),
                location: TextRange::new(15.into(), 45.into()),
            },
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
            StringItem {
                string: "the_".to_string(),
                location: TextRange::new(5.into(), 11.into()),
            },
            StringItem {
                string: "cool".to_string(),
                location: TextRange::new(13.into(), 19.into()),
            },
            StringItem {
                string: "_string".to_string(),
                location: TextRange::new(21.into(), 30.into()),
            },
            StringItem {
                string: "the_cool_string".to_string(),
                location: TextRange::new(36.into(), 46.into()),
            },
        ];
        let actual = get_strings(&source);
        assert_eq!(expected, actual);
    }

    #[test]
    fn test_os_path_join() {
        let source = r#"a = os.path.join("~/.ssh", "id_rsa")"#;
        let expected = vec![StringItem {
            string: "~/.ssh/id_rsa".to_string(),
            location: TextRange::new(4.into(), 36.into()),
        }];
        let actual = get_strings(source);
        assert_eq!(expected, actual);
    }
}
