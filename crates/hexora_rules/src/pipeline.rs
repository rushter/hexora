use crate::checker::Checker;
use crate::result::{AuditConfidence, AuditItem, Rule};
use crate::rules::dunder::collect_importlib_imports;
use hexora_semantic::analysis::{PreparedAnalysis, prepare_source};
use std::path::Path;

pub fn audit_source(source: &str, file_path: Option<&Path>) -> Result<Vec<AuditItem>, String> {
    let prepared = prepare_source(source)?;
    audit_prepared(&prepared, file_path)
}

pub fn audit_prepared(
    prepared: &PreparedAnalysis<'_>,
    file_path: Option<&Path>,
) -> Result<Vec<AuditItem>, String> {
    let indexer = prepared.original_indexer();
    let mut audit_results = collect_importlib_imports(prepared.original_ast(), &indexer);

    let mut checker = Checker::new(&prepared.locator, prepared.checker_indexer());
    checker.check_comments();
    checker.visit_body(&prepared.transformed_ast);

    audit_results.extend(checker.audit_results);
    elevate_setup_py_confidence(&mut audit_results, file_path);
    Ok(audit_results)
}

fn elevate_setup_py_confidence(items: &mut [AuditItem], file_path: Option<&Path>) {
    let is_setup_py = file_path
        .and_then(|path| path.file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.eq_ignore_ascii_case("setup.py"));

    if !is_setup_py {
        return;
    }

    for item in items {
        if matches!(
            item.rule,
            Rule::CodeExec
                | Rule::ShellExec
                | Rule::DangerousExec
                | Rule::ObfuscatedShellExec
                | Rule::ObfuscatedCodeExec
                | Rule::OSFingerprint
                | Rule::DataExfiltration
        ) {
            item.confidence = match item.confidence {
                AuditConfidence::VeryLow => AuditConfidence::Low,
                AuditConfidence::Low => AuditConfidence::Medium,
                AuditConfidence::Medium => AuditConfidence::High,
                _ => item.confidence,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruff_text_size::TextRange;
    use std::path::Path;

    #[test]
    fn test_setup_py_confidence_elevation() {
        let mut items = vec![
            AuditItem {
                label: "os.getlogin".to_string(),
                rule: Rule::OSFingerprint,
                description: "desc".to_string(),
                confidence: AuditConfidence::Medium,
                location: Some(TextRange::default()),
            },
            AuditItem {
                label: "requests.post".to_string(),
                rule: Rule::DataExfiltration,
                description: "desc".to_string(),
                confidence: AuditConfidence::Low,
                location: Some(TextRange::default()),
            },
            AuditItem {
                label: "socket".to_string(),
                rule: Rule::SocketImport,
                description: "desc".to_string(),
                confidence: AuditConfidence::Low,
                location: Some(TextRange::default()),
            },
        ];

        elevate_setup_py_confidence(&mut items, Some(Path::new("tmp/setup.py")));

        assert_eq!(items[0].confidence, AuditConfidence::High);
        assert_eq!(items[1].confidence, AuditConfidence::Medium);
        assert_eq!(items[2].confidence, AuditConfidence::Low);
    }

    #[test]
    fn test_non_setup_py_does_not_elevate_confidence() {
        let mut items = vec![AuditItem {
            label: "os.getlogin".to_string(),
            rule: Rule::OSFingerprint,
            description: "desc".to_string(),
            confidence: AuditConfidence::Medium,
            location: Some(TextRange::default()),
        }];

        elevate_setup_py_confidence(&mut items, Some(Path::new("tmp/main.py")));

        assert_eq!(items[0].confidence, AuditConfidence::Medium);
    }
}
