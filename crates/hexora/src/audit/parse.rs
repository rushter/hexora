use crate::audit::result::AuditResult;
use hexora_io::list_python_files;
use hexora_ml::{ScoreModel, extract_features};
use log::{debug, error};
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
    let prepared = hexora_semantic::analysis::prepare_source(&source_code)?;
    let audit_items = hexora_rules::audit_prepared(&prepared, Some(&file_path))?;

    let features = prepared.with_original_indexed(|analyzed| {
        extract_features(&analyzed, &source_code, &audit_items)
    });
    let score = ScoreModel::default().predict(&features).unwrap_or(0.0);

    Ok(AuditResult {
        path: file_path,
        archive_path,
        items: audit_items,
        features,
        score,
        source_code,
    })
}

/// Audit files in the provided directory or a file
/// Automatically discovers Python files in .tar.gz, .zip files or in folders
pub fn audit_path(
    file_path: &Path,
    exclude_names: Option<&HashSet<String>>,
) -> Result<impl Iterator<Item = AuditResult>, String> {
    let files: Vec<_> = list_python_files(file_path, exclude_names).collect();
    if files.is_empty() {
        return Err("No Python files found".to_string());
    }
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
