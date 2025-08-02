use crate::audit::parse::Checker;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use once_cell::sync::Lazy;
use ruff_python_ast as ast;
use ruff_python_ast::Expr;

static EXTENSIONS: Lazy<Vec<&'static str>> =
    Lazy::new(|| vec![".exe", ".dll", ".so", ".dylib", ".bin"]);

fn contains_download_extension(call: &ast::ExprCall) -> Option<&str> {
    if let Some(Expr::StringLiteral(val)) = &call.arguments.args.first() {
        let text = val.value.to_str();
        for ext in EXTENSIONS.iter() {
            if text.ends_with(ext) {
                return Some(text);
            }
        }
    }
    if let Some(kw) = &call.arguments.keywords.first()
        && let Expr::StringLiteral(val) = &kw.value
    {
        let text = val.value.to_str();
        for ext in EXTENSIONS.iter() {
            if text.ends_with(ext) {
                return Some(text);
            }
        }
    }
    None
}
fn is_download_request(segments: &[&str]) -> bool {
    match segments {
        &[module, submodule] => match module {
            "requests" => matches!(submodule, "get"),
            "urllib2" => matches!(submodule, "urlopen"),
            _ => false,
        },
        _ => false,
    }
}
pub fn binary_download(checker: &mut Checker, call: &ast::ExprCall) {
    let qualified_name = checker.semantic().resolve_qualified_name(&call.func);
    if let Some(qualified_name) = qualified_name
        && is_download_request(qualified_name.segments())
        && let Some(text) = contains_download_extension(call)
    {
        checker.audit_results.push(AuditItem {
            label: text.to_string(),
            rule: Rule::BinaryDownload,
            description: "Suspicious binary download.".to_string(),
            confidence: AuditConfidence::Medium,
            location: Some(call.range),
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("download_01.py", Rule::BinaryDownload, vec!["https://www.example.com/beacon.exe",])]
    fn test_exec(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
