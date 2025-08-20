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

    fn concat_list_like<T: ListLike>(checker: &Checker, list: &T) -> Option<String> {
        let mut out = String::new();
        for elt in list.elements() {
            out.push_str(&eval_const_str(checker, elt)?);
        }
        Some(out)
    }

    match expr {
        // "ex" + "ec" -> "exec"
        ast::Expr::BinOp(ast::ExprBinOp {
            left, op, right, ..
        }) if matches!(op, ast::Operator::Add) => {
            let ls = eval_const_str(checker, left)?;
            let rs = eval_const_str(checker, right)?;
            Some([ls, rs].concat())
        }

        // "".join(["ex", "ec"]) -> "exec"
        ast::Expr::Call(ast::ExprCall {
            func, arguments, ..
        }) => {
            if let ast::Expr::Attribute(attr) = func.as_ref() {
                if attr.attr.as_str() == "join" {
                    let sep_is_empty = match attr.value.as_ref() {
                        ast::Expr::StringLiteral(ast::ExprStringLiteral { value, .. })
                            if value.is_empty() =>
                        {
                            true
                        }
                        ast::Expr::BytesLiteral(ast::ExprBytesLiteral { value, .. })
                            if value.is_empty() =>
                        {
                            true
                        }
                        _ => raw_string_from_expr(&attr.value, checker)
                            .map(|s| s.is_empty())
                            .unwrap_or(false),
                    };
                    if sep_is_empty && arguments.keywords.is_empty() && arguments.args.len() == 1 {
                        let seq_expr = &arguments.args[0];
                        return match seq_expr {
                            ast::Expr::List(list) => concat_list_like(checker, list),
                            ast::Expr::Tuple(tuple) => concat_list_like(checker, tuple),
                            _ => None,
                        };
                    }
                }
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
