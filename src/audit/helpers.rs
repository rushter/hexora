use crate::audit::parse::Checker;
use itertools::Itertools;
use ruff_python_ast as ast;
use ruff_python_ast::str::raw_contents;
use ruff_text_size::TextRange;

/// Returns the range of an expression.
#[inline]
pub fn get_expression_range(expr: &ast::Expr) -> TextRange {
    match expr {
        ast::Expr::BoolOp(node) => node.range,
        ast::Expr::Named(node) => node.range,
        ast::Expr::BinOp(node) => node.range,
        ast::Expr::UnaryOp(node) => node.range,
        ast::Expr::Lambda(node) => node.range,
        ast::Expr::If(node) => node.range,
        ast::Expr::Dict(node) => node.range,
        ast::Expr::Set(node) => node.range,
        ast::Expr::ListComp(node) => node.range,
        ast::Expr::SetComp(node) => node.range,
        ast::Expr::DictComp(node) => node.range,
        ast::Expr::Generator(node) => node.range,
        ast::Expr::Await(node) => node.range,
        ast::Expr::Yield(node) => node.range,
        ast::Expr::YieldFrom(node) => node.range,
        ast::Expr::Compare(node) => node.range,
        ast::Expr::Call(node) => node.range,
        ast::Expr::FString(node) => node.range,
        ast::Expr::TString(node) => node.range,
        ast::Expr::StringLiteral(node) => node.range,
        ast::Expr::BytesLiteral(node) => node.range,
        ast::Expr::NumberLiteral(node) => node.range,
        ast::Expr::BooleanLiteral(node) => node.range,
        ast::Expr::NoneLiteral(node) => node.range,
        ast::Expr::EllipsisLiteral(node) => node.range,
        ast::Expr::Attribute(node) => node.range,
        ast::Expr::Subscript(node) => node.range,
        ast::Expr::Starred(node) => node.range,
        ast::Expr::Name(node) => node.range,
        ast::Expr::List(node) => node.range,
        ast::Expr::Tuple(node) => node.range,
        ast::Expr::Slice(node) => node.range,
        ast::Expr::IpyEscapeCommand(node) => node.range,
    }
}

#[allow(clippy::len_without_is_empty)]
pub trait ListLike {
    fn elements(&self) -> &Vec<ast::Expr>;
    fn range(&self) -> TextRange;
    fn len(&self) -> usize {
        self.elements().len()
    }
}

impl ListLike for ast::ExprList {
    fn elements(&self) -> &Vec<ast::Expr> {
        &self.elts
    }
    fn range(&self) -> TextRange {
        self.range
    }
}

impl ListLike for ast::ExprTuple {
    fn elements(&self) -> &Vec<ast::Expr> {
        &self.elts
    }
    fn range(&self) -> TextRange {
        self.range
    }
}

/// Returns the raw string contents of an expression.
/// This is useful because we don't want to parse escape sequences.
/// We need to get strings the same way they are defined in Python code.
pub(crate) fn raw_string_from_expr(expr: &ast::Expr, checker: &Checker) -> Option<String> {
    match expr {
        ast::Expr::StringLiteral(ast::ExprStringLiteral { value, .. }) => {
            if value.is_empty() {
                return None;
            }
            Some(
                value
                    .iter()
                    .map(|r| r.range)
                    .filter_map(|range| raw_contents(checker.locator.slice(range)))
                    .collect::<String>(),
            )
        }
        ast::Expr::BytesLiteral(ast::ExprBytesLiteral { value, .. }) => {
            if value.is_empty() {
                return None;
            }
            Some(
                value
                    .iter()
                    .map(|r| r.range)
                    .filter_map(|range| raw_contents(checker.locator.slice(range)))
                    .collect::<String>(),
            )
        }
        ast::Expr::FString(ast::ExprFString { value, .. }) => Some(
            value
                .iter()
                .filter_map(|range| raw_contents(checker.locator.slice(range)))
                .join(""),
        ),
        _ => None,
    }
}

fn is_reverse_subscript(slice: &ast::Expr) -> Option<()> {
    let slice = slice.as_slice_expr()?;
    if slice.lower.is_some() || slice.upper.is_some() {
        return None;
    }
    let Some(ast::ExprUnaryOp {
        operand,
        op: ast::UnaryOp::USub,
        ..
    }) = slice.step.as_ref()?.as_unary_op_expr()
    else {
        return None;
    };
    let ast::Number::Int(int) = &operand.as_number_literal_expr()?.value else {
        return None;
    };
    if *int == 1 {
        return Some(());
    }
    None
}

fn reverse_str(s: &str) -> String {
    s.chars().rev().collect()
}

fn concat_list_like<T: ListLike>(checker: &Checker, list: &T, reversed: bool) -> Option<String> {
    let iter: Box<dyn Iterator<Item = &ast::Expr>> = if reversed {
        Box::new(list.elements().iter().rev())
    } else {
        Box::new(list.elements().iter())
    };

    let mut out = String::new();
    for elt in iter {
        out.push_str(&eval_const_str(checker, elt)?);
    }
    Some(out)
}

fn is_empty_separator(checker: &Checker, expr: &ast::Expr) -> bool {
    match expr {
        ast::Expr::StringLiteral(ast::ExprStringLiteral { value, .. }) if value.is_empty() => true,
        ast::Expr::BytesLiteral(ast::ExprBytesLiteral { value, .. }) if value.is_empty() => true,
        _ => raw_string_from_expr(expr, checker)
            .map(|s| s.is_empty())
            .unwrap_or(false),
    }
}

fn eval_join_call(
    checker: &Checker,
    attr: &ast::ExprAttribute,
    arguments: &ast::Arguments,
) -> Option<String> {
    if attr.attr.as_str() != "join" {
        return None;
    }

    if !is_empty_separator(checker, &attr.value) {
        return None;
    }

    if !arguments.keywords.is_empty() || arguments.args.len() != 1 {
        return None;
    }

    let seq_expr = &arguments.args[0];

    if let ast::Expr::List(list) = seq_expr {
        return concat_list_like(checker, list, false);
    }
    if let ast::Expr::Tuple(tuple) = seq_expr {
        return concat_list_like(checker, tuple, false);
    }

    // [ ... ][::-1]
    if let ast::Expr::Subscript(ast::ExprSubscript { value, slice, .. }) = seq_expr {
        if is_reverse_subscript(slice).is_some() {
            match value.as_ref() {
                ast::Expr::List(list) => return concat_list_like(checker, list, true),
                ast::Expr::Tuple(tuple) => return concat_list_like(checker, tuple, true),
                _ => {
                    if let Some(s) = eval_const_str(checker, value) {
                        return Some(reverse_str(&s));
                    }
                }
            }
        }
    }

    // reversed("...")
    if let ast::Expr::Call(inner_call) = seq_expr {
        let is_reversed = matches!(inner_call.func.as_ref(), ast::Expr::Name(name) if name.id.as_str() == "reversed");
        if is_reversed
            && inner_call.arguments.keywords.is_empty()
            && inner_call.arguments.args.len() == 1
        {
            let target = &inner_call.arguments.args[0];
            if let ast::Expr::List(list) = target {
                return concat_list_like(checker, list, true);
            }
            if let ast::Expr::Tuple(tuple) = target {
                return concat_list_like(checker, tuple, true);
            }
            if let Some(s) = eval_const_str(checker, target) {
                return Some(reverse_str(&s));
            }
        }
    }

    None
}

/// Evaluate an expression to a constant string if it can be safely determined without executing code.
/// Supported patterns:
/// - String/bytes/f-string literals (raw source)
/// - Concatenation with `+` where both sides evaluate to strings
/// - "".join([...]) with a single positional list/tuple of constant strings
pub fn eval_const_str(checker: &Checker, expr: &ast::Expr) -> Option<String> {
    // Fast path: direct literal
    if let Some(s) = raw_string_from_expr(expr, checker) {
        return Some(s);
    }

    match expr {
        // "ex" + "ec" -> "exec"
        ast::Expr::BinOp(ast::ExprBinOp {
            left,
            op: ast::Operator::Add,
            right,
            ..
        }) => {
            let ls = eval_const_str(checker, left)?;
            let rs = eval_const_str(checker, right)?;
            Some([ls, rs].concat())
        }

        // "".join([...]) and "".join(reversed(...))
        ast::Expr::Call(ast::ExprCall {
            func, arguments, ..
        }) => {
            if let ast::Expr::Attribute(attr) = func.as_ref() {
                return eval_join_call(checker, attr, arguments);
            }
            None
        }

        // s[::-1] -> reverse string
        ast::Expr::Subscript(ast::ExprSubscript { value, slice, .. }) => {
            if is_reverse_subscript(slice).is_some() {
                let s = eval_const_str(checker, value)?;
                return Some(reverse_str(&s));
            }
            None
        }

        // bytes literal like b"...".decode(...) -> treat as underlying raw string
        ast::Expr::Attribute(attr) if attr.attr.as_str() == "decode" => {
            eval_const_str(checker, &attr.value)
        }

        _ => None,
    }
}
