use crate::audit::result::{AuditItem, AuditResult};
use crate::indexer::checker::Checker;
use crate::indexer::index::NodeIndexer;
use crate::indexer::node_transformer::NodeTransformer;
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
    let audit_items = audit_source(source_code.clone())?;
    Ok(AuditResult {
        path: file_path,
        archive_path,
        items: audit_items,
        source_code,
    })
}

/// Audit multiple files in parallel
pub fn audit_path(
    file_path: &Path,
    exclude_names: Option<&HashSet<String>>,
) -> Result<impl Iterator<Item = AuditResult>, &'static str> {
    let files = list_python_files(file_path, exclude_names);
    let results: Vec<AuditResult> = files
        .into_iter()
        .filter_map(|file| {
            debug!("Auditing file: {}", file.full_path());
            match audit_file_with_content(file.file_path, file.archive_path, file.content) {
                Ok(result) => Some(result),
                Err(e) => {
                    error!("Error auditing file: {}", e);
                    None
                }
            }
        })
        .collect();
    if results.is_empty() {
        Err("No Python files found")
    } else {
        Ok(results.into_iter())
    }
}

fn audit_source(source: String) -> Result<Vec<AuditItem>, String> {
    let parsed = ruff_python_parser::parse_unchecked_source(&source, ast::PySourceType::Python);
    let locator = Locator::new(&source);
    let python_ast = parsed.suite();

    let mut indexer = NodeIndexer::new();
    indexer.visit_body(python_ast);
    indexer.index_comments(parsed.tokens());

    let mut transformed_ast = python_ast.to_vec();
    let transformer = NodeTransformer::new(&locator, indexer);
    transformer.visit_body(&mut transformed_ast);

    let mut indexer = transformer.indexer;
    indexer.clear_state();
    let mut checker = Checker::new(&locator, indexer);
    checker.check_comments();
    checker.visit_body(&transformed_ast);
    Ok(checker.audit_results)
}
