use crate::audit::result::{AuditConfidence, AuditItem, AuditResult, Rule};
use crate::indexer::checker::Checker;
use crate::indexer::index::NodeIndexer;
use crate::indexer::node_transformer::NodeTransformer;
use crate::rules::dunder::collect_importlib_imports;
use hexora_io::list_python_files;
use hexora_io::locator::Locator;
use log::{debug, error};
use ruff_python_ast::visitor::source_order::SourceOrderVisitor;
use ruff_python_ast::visitor::transformer::Transformer;
use ruff_python_ast::{self as ast};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Parse a Python file and perform an audit.
pub fn audit_file(file_path: &Path) -> Result<AuditResult, String> {
    debug!("Auditing file: {}", file_path.display());
    let source_code = std::fs::read_to_string(file_path).map_err(|e| e.to_string())?;
    audit_file_with_content(file_path.to_path_buf(), None, source_code)
}

fn audit_file_with_content(
    file_path: PathBuf,
    archive_path: Option<PathBuf>,
    source_code: String,
) -> Result<AuditResult, String> {
    let audit_items = audit_source(&source_code, Some(&file_path))?;
    Ok(AuditResult {
        path: file_path,
        archive_path,
        items: audit_items,
        source_code,
    })
}

/// Audit multiple files in the provided directory or a file
pub fn audit_path(
    file_path: &Path,
    exclude_names: Option<&HashSet<String>>,
) -> Result<impl Iterator<Item = AuditResult>, &'static str> {
    let files: Vec<_> = list_python_files(file_path, exclude_names).collect();
    if files.is_empty() {
        Err("No Python files found")
    } else {
        Ok(files.into_iter().filter_map(|file| {
            debug!("Auditing file: {}", file.full_path());
            match audit_file_with_content(file.file_path, file.archive_path, file.content) {
                Ok(result) => Some(result),
                Err(e) => {
                    error!("Error auditing file: {}", e);
                    None
                }
            }
        }))
    }
}

pub fn audit_source(source: &str, file_path: Option<&Path>) -> Result<Vec<AuditItem>, String> {
    let parsed = ruff_python_parser::parse_unchecked_source(source, ast::PySourceType::Python);
    let locator = Locator::new(source);
    let python_ast = parsed.suite();

    let mut indexer = NodeIndexer::new();
    indexer.visit_body(python_ast);
    indexer.index_comments(parsed.tokens());
    let mut audit_results = collect_importlib_imports(python_ast, &indexer);

    let mut transformed_ast = python_ast.to_vec();
    let transformer = NodeTransformer::new(&locator, indexer);
    transformer.visit_body(&mut transformed_ast);

    let mut indexer = transformer.indexer;
    indexer.clear_state();
    let mut checker = Checker::new(&locator, indexer);
    checker.check_comments();
    checker.visit_body(&transformed_ast);

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
