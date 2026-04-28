use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
use crate::indexer::resolver::string_from_expr;
use once_cell::sync::Lazy;
use ruff_python_ast as ast;

static SUSPICIOUS_WRITE_EXTENSIONS: Lazy<Vec<&'static str>> =
    Lazy::new(|| vec![".exe", ".py", ".pyw", ".ps1", ".bat", ".cmd", ".sh"]);

fn is_open_for_writing(checker: &Checker, call: &ast::ExprCall, mode_arg_index: usize) -> bool {
    let mut mode = "r".to_string();

    if let Some(arg) = call.arguments.args.get(mode_arg_index) {
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
            if qn.is_exact(&["pathlib", "Path"]) || qn.is_exact(&["Path"]) {
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

fn get_path_constructor_filename(checker: &Checker, expr: &ast::Expr) -> Option<String> {
    let qn = checker.indexer.resolve_qualified_name(expr)?;
    if qn.is_exact(&["pathlib", "Path"]) || qn.is_exact(&["Path"]) {
        if let ast::Expr::Call(call) = expr {
            return call
                .arguments
                .args
                .first()
                .and_then(|arg| string_from_expr(arg, &checker.indexer));
        }
    }
    None
}

pub fn suspicious_write(checker: &mut Checker, call: &ast::ExprCall) {
    let Some(qualified_name) = checker.indexer.resolve_qualified_name(&call.func) else {
        return;
    };

    let filename = if (qualified_name.is_exact(&["open"])
        || qualified_name.is_exact(&["builtins", "open"]))
        && is_open_for_writing(checker, call, 1)
    {
        call.arguments
            .args
            .first()
            .and_then(|arg| get_filename(checker, arg))
    } else if qualified_name.is_pathlib_write() {
        call.func
            .as_attribute_expr()
            .and_then(|attr| get_filename(checker, &attr.value))
    } else if (qualified_name.is_exact(&["pathlib", "Path", "open"])
        || qualified_name.is_exact(&["Path", "open"]))
        && is_open_for_writing(checker, call, 0)
    {
        call.func
            .as_attribute_expr()
            .and_then(|attr| get_path_constructor_filename(checker, &attr.value))
            .or_else(|| {
                call.func
                    .as_attribute_expr()
                    .and_then(|attr| get_filename(checker, &attr.value))
            })
    } else {
        None
    };

    if let Some(filename) = filename {
        let lowered = filename.to_ascii_lowercase();
        if !SUSPICIOUS_WRITE_EXTENSIONS
            .iter()
            .any(|ext| lowered.ends_with(ext))
        {
            return;
        }

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

    #[test]
    fn test_suspicious_write_uppercase_extension() {
        let source = r#"open("PAYLOAD.EXE", "wb").write("x")
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::SuspiciousWrite)
            .map(|item| item.label)
            .collect();
        assert_eq!(matches, vec!["PAYLOAD.EXE"]);
    }

    #[test]
    fn test_suspicious_write_path_open() {
        let source = r#"from pathlib import Path
with Path("payload.exe").open("wb") as f:
    f.write(b"x")
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::SuspiciousWrite)
            .map(|item| item.label)
            .collect();
        assert_eq!(matches, vec!["payload.exe"]);
    }
}
