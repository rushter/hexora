use crate::indexer::resolver::string_from_expr;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
use crate::rules::exec::get_call_suspicious_taint;
use once_cell::sync::Lazy;
use ruff_python_ast as ast;

static EXTENSIONS: Lazy<Vec<&'static str>> =
    Lazy::new(|| vec![".exe", ".dll", ".so", ".dylib", ".bin"]);

fn contains_download_extension(checker: &Checker, call: &ast::ExprCall) -> Option<String> {
    for arg in &call.arguments.args {
        if let Some(text) = string_from_expr(arg, &checker.indexer) {
            for ext in EXTENSIONS.iter() {
                if text.ends_with(ext) {
                    return Some(text);
                }
            }
        }
    }
    for kw in &call.arguments.keywords {
        if let Some(text) = string_from_expr(&kw.value, &checker.indexer) {
            for ext in EXTENSIONS.iter() {
                if text.ends_with(ext) {
                    return Some(text);
                }
            }
        }
    }
    None
}
fn is_download_request(segments: &[&str]) -> bool {
    match segments {
        &[module, submodule] => match module {
            "requests" => matches!(submodule, "get" | "post" | "request"),
            "urllib" | "urllib2" => matches!(submodule, "urlopen"),
            "urllib.request" => matches!(submodule, "urlopen"),
            _ => false,
        },
        _ => false,
    }
}
pub fn binary_download(checker: &mut Checker, call: &ast::ExprCall) {
    let qualified_name = checker.indexer.get_qualified_name(call);
    if let Some(qualified_name) = qualified_name
        && is_download_request(&qualified_name.segments())
    {
        if let Some(label) = contains_download_extension(checker, call) {
            let suspicious_taint = get_call_suspicious_taint(checker, call);
            let confidence = if suspicious_taint.is_some() {
                AuditConfidence::High
            } else {
                AuditConfidence::Medium
            };

            checker.audit_results.push(AuditItem {
                label,
                rule: Rule::BinaryDownload,
                description: "Suspicious binary download.".to_string(),
                confidence,
                location: Some(call.range),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("download_01.py", Rule::BinaryDownload, vec!["https://www.example.com/beacon.exe",])]
    #[test_case("download_02.py", Rule::BinaryDownload, vec![])]
    fn test_exec(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
