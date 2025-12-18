use crate::audit::result::{AuditItem, AuditResult};
use crate::indexer::checker::Checker;
use crate::indexer::index::NodeIndexer;
use crate::indexer::locator::Locator;
use crate::indexer::node_transformer::NodeTransformer;
use crate::io::list_python_files;
use log::{debug, error};
use rayon::prelude::*;
use ruff_python_ast::visitor::source_order::SourceOrderVisitor;
use ruff_python_ast::visitor::transformer::Transformer;
use ruff_python_ast::{self as ast};
use std::path::Path;

/// Parse a Python file and perform an audit.
pub fn audit_file(file_path: &Path) -> Result<AuditResult, String> {
    debug!("Auditing file: {}", file_path.display());
    let source_code = std::fs::read_to_string(file_path).map_err(|e| e.to_string())?;
    let audit_items = audit_source(source_code.clone())?;
    Ok(AuditResult {
        path: file_path.to_path_buf(),
        items: audit_items,
        source_code,
    })
}

/// Audit multiple files in parallel
pub fn audit_path(file_path: &Path) -> Result<impl Iterator<Item = AuditResult>, &str> {
    if let Some(files) = list_python_files(file_path) {
        let results: Vec<AuditResult> = files
            .par_iter()
            .filter_map(|path_buf| match audit_file(path_buf) {
                Ok(result) => Some(result),
                Err(e) => {
                    error!("Error auditing file {}: {}", path_buf.display(), e);
                    None
                }
            })
            .collect();
        Ok(results.into_iter())
    } else {
        Err("No Python files found")
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

    let mut checker = Checker::new(&locator, transformer.indexer.into_inner());
    checker.check_comments();
    checker.visit_body(&transformed_ast);
    Ok(checker.audit_results)
}
