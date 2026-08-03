use crate::audit::result::AuditResult;
use hexora_io::PythonFileStream;
use hexora_ml::{FeatureRecord, ScoreModel, extract_features};
use hexora_rules::result::AuditItem;
use log::{debug, error};

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

/// Maximum number of files audited concurrently. Bounds peak memory: only
/// this many source buffers, ASTs and semantic indices are in flight at once,
/// plus what is buffered in the extraction stream's channel.
const MAX_IN_FLIGHT_AUDITS: usize = 48;

/// Audit files in the provided directory or a file.
/// Automatically discovers Python files in .tar.gz, .zip files or in folders.
///
/// A dispatcher thread pulls files from the extraction stream and hands each
/// one to the rayon pool, so the next file starts as soon as a core frees
/// up. Dispatch stops once `MAX_IN_FLIGHT_AUDITS` results are still
/// unforwarded, which bounds memory. Results are reordered by discovery
/// sequence and yielded in order. Dropping the iterator early closes the
/// output channel; the dispatcher and any running audit tasks exit cleanly.
pub fn audit_path(
    file_path: &Path,
    exclude_names: Option<&HashSet<String>>,
) -> Result<impl Iterator<Item = AuditResult>, String> {
    let stream: PythonFileStream = hexora_io::spawn_python_files(file_path, exclude_names)?;
    let (out_tx, out_rx) = std::sync::mpsc::channel::<AuditResult>();

    std::thread::Builder::new()
        .name("hexora-audit".to_string())
        .spawn(move || {
            let (res_tx, res_rx) = std::sync::mpsc::channel::<(usize, Option<AuditResult>)>();
            // Finished results that arrived ahead of earlier sequence numbers.
            let mut pending: std::collections::HashMap<usize, Option<AuditResult>> =
                std::collections::HashMap::new();
            let mut next = 0usize;

            // Forward as many in-order results as possible.
            let forward = |pending: &mut std::collections::HashMap<usize, Option<AuditResult>>,
                           next: &mut usize|
             -> bool {
                while let Some(entry) = pending.remove(next) {
                    if let Some(result) = entry {
                        if out_tx.send(result).is_err() {
                            return false;
                        }
                    }
                    *next += 1;
                }
                true
            };

            for (seq, file) in stream.enumerate() {
                // At least one dispatched task is still running whenever this
                // bound is reached, so a result eventually arrives to unblock.
                while seq - next >= MAX_IN_FLIGHT_AUDITS {
                    match res_rx.recv() {
                        Ok((s, result)) => {
                            pending.insert(s, result);
                            if !forward(&mut pending, &mut next) {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let res_tx = res_tx.clone();
                rayon::spawn(move || {
                    let result = audit_file_checked(file);
                    let _ = res_tx.send((seq, result));
                });
            }
            drop(res_tx);
            for (s, result) in res_rx {
                pending.insert(s, result);
                if !forward(&mut pending, &mut next) {
                    return;
                }
            }
        })
        .map_err(|e| e.to_string())?;

    Ok(out_rx.into_iter())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_resources() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/test")
    }

    #[test]
    fn test_audit_path_yields_all_files_in_discovery_order() {
        let path = test_resources();
        let expected: Vec<String> = hexora_io::list_python_files(&path, None)
            .map(|f| f.full_path())
            .collect();
        assert!(expected.len() > 50, "test corpus should be sizable");

        let results: Vec<AuditResult> = audit_path(&path, None).unwrap().collect();
        let actual: Vec<String> = results
            .iter()
            .map(|r| match &r.archive_path {
                Some(archive) => format!("{}:{}", archive.display(), r.path.display()),
                None => r.path.display().to_string(),
            })
            .collect();

        assert_eq!(actual.len(), expected.len());
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_audit_path_survives_early_iterator_drop() {
        // Dropping the iterator early must not deadlock: the extraction
        // thread may linger blocked on the channel until it fills up, but a
        // subsequent audit must still complete normally.
        let path = test_resources();
        let results = audit_path(&path, None).unwrap();
        assert_eq!(results.take(1).count(), 1);

        let results = audit_path(&path, None).unwrap();
        let count = results.count();
        assert!(count > 50);
    }
}
