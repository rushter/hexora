use crate::indexer::index::NodeIndexer;
use crate::indexer::transformer;
use itertools::Itertools;
use ruff_linter::Locator;
use ruff_python_ast::str::raw_contents;
use ruff_python_ast::{self as ast, AtomicNodeIndex, HasNodeIndex, Operator, StringLiteralFlags};
use ruff_text_size::{Ranged, TextRange};
use std::collections::HashSet;

/// This module rewrites string literals to their raw contents.
/// We want to have string values unchanged.
pub struct StringTransformer<'a> {
    pub locator: &'a Locator<'a>,
    pub indexer: &'a mut NodeIndexer,
    pub updated_strings: HashSet<u32>,
}

impl<'a> StringTransformer<'a> {
    pub fn new(locator: &'a Locator, indexer: &'a mut NodeIndexer) -> Self {
        Self {
            locator,
            indexer,
            updated_strings: HashSet::new(),
        }
    }

    fn collect_raw(&self, ranges: impl Iterator<Item = TextRange>) -> String {
        ranges
            .filter_map(|r| raw_contents(self.locator.slice(r)))
            .collect()
    }

    fn make_string_expr(&mut self, range: TextRange, value: String) -> ast::Expr {
        let node_id = self.indexer.get_index_atomic();
        self.updated_strings.insert(node_id.load().as_u32());

        ast::Expr::StringLiteral(ast::ExprStringLiteral {
            node_index: node_id,
            range,
            value: ast::StringLiteralValue::single(ast::StringLiteral {
                value: Box::from(value),
                range,
                flags: StringLiteralFlags::empty(),
                node_index: self.indexer.get_index_atomic(),
            }),
        })
    }

    fn extract_string(&self, expr: &ast::Expr) -> Option<String> {
        match expr {
            ast::Expr::StringLiteral(s) => {
                let sid = s.node_index.load().as_u32();
                if self.updated_strings.contains(&sid) {
                    return s.value.iter().next().map(|seg| seg.value.to_string());
                }
                Some(self.collect_raw(s.value.iter().map(|r| r.range)))
            }
            _ => None,
        }
    }
}

impl<'a> transformer::Transformer for StringTransformer<'a> {
    fn visit_expr(&mut self, expr: &mut ast::Expr) {
        let node_id = expr.node_index().load().as_u32();
        if self.updated_strings.contains(&node_id) {
            return;
        }

        match expr {
            ast::Expr::StringLiteral(s) => {
                let content = self.collect_raw(s.value.iter().map(|r| r.range));
                let node_id = s.node_index.load().as_u32();
                self.updated_strings.insert(node_id);
                s.value = ast::StringLiteralValue::single(ast::StringLiteral {
                    value: Box::from(content),
                    range: s.range,
                    flags: StringLiteralFlags::empty(),
                    node_index: AtomicNodeIndex::from(node_id),
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
                self.visit_expr(&mut binop.left);
                self.visit_operator(&mut binop.op);
                self.visit_expr(&mut binop.right);

                if let Operator::Add = binop.op {
                    if let (Some(l), Some(r)) = (
                        self.extract_string(&binop.left),
                        self.extract_string(&binop.right),
                    ) {
                        *expr = self.make_string_expr(binop.range, l + &r);
                        return;
                    }
                }
            }

            ast::Expr::Subscript(sub) => {
                // Handle "string"[::-1] reversal
                self.visit_expr(&mut sub.value);
                self.visit_expr(&mut sub.slice);
                let is_reverse_slice = |slice_expr: &ast::Expr| -> bool {
                    if let ast::Expr::Slice(slc) = slice_expr {
                        if slc.lower.is_none() && slc.upper.is_none() {
                            if let Some(step) = &slc.step {
                                let text = self.locator.slice(step.range());
                                return text.trim() == "-1";
                            }
                        }
                    }
                    false
                };
                if is_reverse_slice(&sub.slice) {
                    if let Some(s) = self.extract_string(&sub.value) {
                        let rev: String = s.chars().rev().collect();
                        *expr = self.make_string_expr(sub.range, rev);
                        return;
                    }
                }
            }

            ast::Expr::Call(call) => {
                //  "".join([...]) where all elements are constant strings,
                //  reversed() or [::-1]
                self.visit_expr(&mut call.func);
                for arg in &mut call.arguments.args {
                    self.visit_expr(arg);
                }
                for kw in &mut call.arguments.keywords {
                    self.visit_expr(&mut kw.value);
                }

                let is_reverse_slice = |slice_expr: &ast::Expr| -> bool {
                    if let ast::Expr::Slice(slc) = slice_expr {
                        if slc.lower.is_none() && slc.upper.is_none() {
                            if let Some(step) = &slc.step {
                                let text = self.locator.slice(step.range());
                                return text.trim() == "-1";
                            }
                        }
                    }
                    false
                };

                if let ast::Expr::Attribute(attr) = call.func.as_ref() {
                    // Handle "string".decode("...") -> "string"
                    if attr.attr.as_str() == "decode" {
                        if let Some(s) = self.extract_string(&attr.value) {
                            *expr = self.make_string_expr(call.range, s);
                            return;
                        }
                    }
                    if attr.attr.as_str() == "join"
                        && call.arguments.keywords.is_empty()
                        && call.arguments.args.len() == 1
                    {
                        if let Some(sep) = self.extract_string(&attr.value) {
                            let seq_expr = &call.arguments.args[0];
                            let collect_elems = |elts: &Vec<ast::Expr>| -> Option<String> {
                                let mut parts: Vec<String> = Vec::with_capacity(elts.len());
                                for e in elts.iter() {
                                    if let Some(s) = self.extract_string(e) {
                                        parts.push(s);
                                    } else {
                                        return None;
                                    }
                                }
                                Some(parts.join(&sep))
                            };
                            let collect_elems_rev = |elts: &Vec<ast::Expr>| -> Option<String> {
                                let mut parts: Vec<String> = Vec::with_capacity(elts.len());
                                for e in elts.iter() {
                                    if let Some(s) = self.extract_string(e) {
                                        parts.push(s);
                                    } else {
                                        return None;
                                    }
                                }
                                parts.reverse();
                                Some(parts.join(&sep))
                            };

                            // Direct list/tuple
                            match seq_expr {
                                ast::Expr::List(list) => {
                                    if let Some(joined) = collect_elems(&list.elts) {
                                        *expr = self.make_string_expr(call.range, joined);
                                        return;
                                    }
                                }
                                ast::Expr::Tuple(tuple) => {
                                    if let Some(joined) = collect_elems(&tuple.elts) {
                                        *expr = self.make_string_expr(call.range, joined);
                                        return;
                                    }
                                }
                                _ => {}
                            }

                            // Direct string argument: join characters
                            if let Some(s) = self.extract_string(seq_expr) {
                                let joined = s.chars().map(|c| c.to_string()).join(&sep);
                                *expr = self.make_string_expr(call.range, joined);
                                return;
                            }

                            // list/tuple/string with [::-1]
                            if let ast::Expr::Subscript(sub) = seq_expr {
                                if is_reverse_slice(&sub.slice) {
                                    match sub.value.as_ref() {
                                        ast::Expr::List(list) => {
                                            if let Some(joined) = collect_elems_rev(&list.elts) {
                                                *expr = self.make_string_expr(call.range, joined);
                                                return;
                                            }
                                        }
                                        ast::Expr::Tuple(tuple) => {
                                            if let Some(joined) = collect_elems_rev(&tuple.elts) {
                                                *expr = self.make_string_expr(call.range, joined);
                                                return;
                                            }
                                        }
                                        _ => {
                                            if let Some(s) = self.extract_string(&sub.value) {
                                                let parts: Vec<String> = s
                                                    .chars()
                                                    .rev()
                                                    .map(|c| c.to_string())
                                                    .collect();
                                                let joined = parts.join(&sep);
                                                *expr = self.make_string_expr(call.range, joined);
                                                return;
                                            }
                                        }
                                    }
                                }
                            }

                            // reversed(...)
                            if let ast::Expr::Call(inner_call) = seq_expr {
                                let is_reversed = matches!(inner_call.func.as_ref(), ast::Expr::Name(name) if name.id.as_str() == "reversed");
                                if is_reversed
                                    && inner_call.arguments.keywords.is_empty()
                                    && inner_call.arguments.args.len() == 1
                                {
                                    let target = &inner_call.arguments.args[0];
                                    match target {
                                        ast::Expr::List(list) => {
                                            if let Some(joined) = collect_elems_rev(&list.elts) {
                                                *expr = self.make_string_expr(call.range, joined);
                                                return;
                                            }
                                        }
                                        ast::Expr::Tuple(tuple) => {
                                            if let Some(joined) = collect_elems_rev(&tuple.elts) {
                                                *expr = self.make_string_expr(call.range, joined);
                                                return;
                                            }
                                        }
                                        _ => {
                                            if let Some(s) = self.extract_string(target) {
                                                let parts: Vec<String> = s
                                                    .chars()
                                                    .rev()
                                                    .map(|c| c.to_string())
                                                    .collect();
                                                let joined = parts.join(&sep);
                                                *expr = self.make_string_expr(call.range, joined);
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            _ => {}
        }

        transformer::walk_expr(self, expr);
    }
}

#[cfg(test)]
mod tests {
    use crate::indexer::index::NodeIndexer;
    use crate::indexer::strings::StringTransformer;
    use crate::indexer::transformer::Transformer;
    use ruff_linter::Locator;
    use ruff_python_ast::visitor::source_order::*;
    use ruff_python_ast::*;
    use ruff_text_size::TextRange;

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
        let mut transformer = StringTransformer::new(&locator, &mut indexer);
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
}
