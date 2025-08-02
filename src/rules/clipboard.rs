use crate::audit::parse::Checker;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use ruff_python_ast as ast;
use ruff_python_ast::name::QualifiedName;

pub fn clipboard_read(checker: &mut Checker, call: &ast::ExprCall) {
    let clipboard_name: Option<QualifiedName> = checker
        .semantic()
        .resolve_qualified_name(&call.func)
        .filter(|qualified_name| {
            matches!(
                qualified_name.segments(),
                ["pyperclip", "paste"] | ["win32clipboard", "GetClipboardData"]
            )
        });

    if let Some(clipboard_name) = clipboard_name {
        checker.audit_results.push(AuditItem {
            label: clipboard_name.to_string(),
            rule: Rule::ClipboardRead,
            description: "Reading from the clipboard can be used to exfiltrate sensitive data."
                .to_string(),
            confidence: AuditConfidence::High,
            location: Some(call.range),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("clipboard_01.py", Rule::ClipboardRead, vec!["pyperclip.paste"])]
    fn test_env(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
