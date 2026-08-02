use crate::audit::result::AuditResult;
use hexora_io::list_python_files;
use hexora_ml::{FeatureRecord, ScoreModel, extract_features};
use hexora_rules::result::AuditItem;
use log::{debug, error};
use rayon::prelude::*;
use std::any::Any;
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
    let (audit_items, features, score): (Vec<AuditItem>, FeatureRecord, f64) = prepared
        .with_indexed(|analyzed| {
            let audit_items = hexora_rules::audit_analyzed(&analyzed, Some(&file_path))?;

            let features = extract_features(&analyzed, &source_code, &audit_items);
            let score = ScoreModel::cached().predict(&features).unwrap_or(0.0);

            Ok::<_, String>((audit_items, features, score))
        })?;

    Ok(AuditResult {
        path: file_path,
        archive_path,
        items: audit_items,
        features,
        score,
        source_code,
    })
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "unknown panic".to_string()
    }
}

/// Audit a single file, isolating panics so a malformed input cannot abort the whole run.
fn audit_file_checked(file: hexora_io::PythonFile) -> Option<AuditResult> {
    debug!("Auditing file: {}", file.full_path());
    let full_path = file.full_path();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        audit_file_with_content(file.file_path, file.archive_path, file.content)
    }));
    match result {
        Ok(Ok(result)) => Some(result),
        Ok(Err(e)) => {
            error!("Error auditing file: {}", e);
            None
        }
        Err(panic) => {
            error!(
                "Panic while auditing file: {}. Panic message: {}",
                full_path,
                panic_message(&*panic)
            );
            None
        }
    }
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
    let results: Vec<_> = files
        .into_par_iter()
        .filter_map(audit_file_checked)
        .collect();
    Ok(results.into_iter())
}
