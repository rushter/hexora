use crate::indexer::checker::Checker;
use ruff_python_ast as ast;

pub fn matches_builtin_functions<'a>(
    checker: &'a Checker,
    expr: &'a ast::Expr,
    names: &'a [&str],
) -> Option<&'a str> {
    checker
        .indexer
        .resolve_qualified_name(expr)
        .map(|qn| {
            let segments = qn.segments();
            if segments.len() != 2 {
                return None;
            }
            if !matches!(segments[0], "builtins" | "") {
                return None;
            };
            if names.contains(&segments[1]) {
                return Some(segments[1]);
            }
            None
        })
        .unwrap_or(None)
}
