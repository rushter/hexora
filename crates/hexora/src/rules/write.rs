use crate::indexer::resolver::string_from_expr;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
use ruff_python_ast as ast;

fn is_open_for_writing(checker: &Checker, call: &ast::ExprCall) -> bool {
    let mut mode = "r".to_string();

    if let Some(arg) = call.arguments.args.get(1) {
        if let Some(m) = string_from_expr(arg, &checker.indexer) {
            mode = m;
        }
    }

    for kw in &call.arguments.keywords {
        if matches!(kw.arg.as_ref().map(|a| a.as_str()), Some("mode")) {
            if let Some(m) = string_from_expr(&kw.value, &checker.indexer) {
                mode = m;
            }
        }
    }

    mode.chars().any(|c| matches!(c, 'w' | 'a' | 'x' | '+'))
}

fn get_filename(checker: &Checker, expr: &ast::Expr) -> Option<String> {
    if let Some(s) = string_from_expr(expr, &checker.indexer) {
        return Some(s);
    }

    match expr {
        ast::Expr::Call(call) => {
            let qn = checker.indexer.resolve_qualified_name(expr)?;
            if qn.segments() == ["pathlib", "Path"] {
                string_from_expr(call.arguments.args.first()?, &checker.indexer)
            } else {
                None
            }
        }
        ast::Expr::Name(name) => {
            let exprs = checker.indexer.get_exprs_by_index(&name.node_index)?;
            exprs.iter().find_map(|&e| get_filename(checker, e))
        }
        _ => None,
    }
}

pub fn suspicious_write(checker: &mut Checker, call: &ast::ExprCall) {
    let Some(qualified_name) = checker.indexer.get_qualified_name(call) else {
        return;
    };

    let filename = match qualified_name.segments().as_slice() {
        ["open"] | ["builtins", "open"] if is_open_for_writing(checker, call) => call
            .arguments
            .args
            .first()
            .and_then(|arg| get_filename(checker, arg)),
        ["pathlib", "Path", "write_text" | "write_bytes"] => call
            .func
            .as_attribute_expr()
            .and_then(|attr| get_filename(checker, &attr.value)),
        _ => None,
    };

    if let Some(filename) = filename
        && (filename.ends_with(".exe") || filename.ends_with(".py"))
    {
        checker.audit_results.push(AuditItem {
            label: filename,
            rule: Rule::SuspiciousWrite,
            description: "Suspicious write to the filesystem.".to_string(),
            confidence: AuditConfidence::High,
            location: Some(call.range),
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("write_01.py", Rule::SuspiciousWrite, vec!["payload.exe", "script.py", "bad.exe", "other_bad.py"])]
    fn test_write(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
