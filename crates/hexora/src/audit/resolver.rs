use crate::indexer::checker::Checker;

use ruff_python_ast as ast;

pub fn matches_builtin_functions(
    checker: &Checker,
    expr: &ast::Expr,
    names: &[&str],
) -> Option<String> {
    checker
        .indexer
        .resolve_qualified_name(expr)
        .map(|qn| {
            let parts = qn.segments();
            if parts.len() == 1 {
                let name = parts[0];
                return names.contains(&name).then_some(name.to_string());
            }
            if parts[0] != "builtins" && !parts[0].is_empty() {
                return None;
            }
            let name = parts[1];
            if names.contains(&name) {
                return Some(name.to_string());
            }
            None
        })
        .unwrap_or(None)
}
