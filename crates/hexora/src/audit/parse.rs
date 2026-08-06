use crate::audit::result::AuditResult;
use hexora_io::PythonFileStream;
use hexora_ml::{FeatureRecord, ScoreModel, extract_features};
use hexora_rules::result::AuditItem;
use log::{debug, error};

use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Maximum number of files audited concurrently.
/// Only this many source buffers, ASTs and semantic indices are in flight at once.
const MAX_IN_FLIGHT_AUDITS: usize = 48;

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

/// Dispatches audits from the extraction stream on demand and reorders
/// results back into discovery sequence before yielding them.
struct OrderedAuditResults {
    stream: PythonFileStream,
    tx: std::sync::mpsc::Sender<(usize, Option<AuditResult>)>,
    rx: std::sync::mpsc::Receiver<(usize, Option<AuditResult>)>,
    pending: HashMap<usize, Option<AuditResult>>,
    seq: usize,
    in_flight: usize,
    next: usize,
}

impl Iterator for OrderedAuditResults {
    type Item = AuditResult;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(entry) = self.pending.remove(&self.next) {
                self.next += 1;
                if let Some(result) = entry {
                    return Some(result);
                }
                continue;
            }

            while self.in_flight < MAX_IN_FLIGHT_AUDITS {
                match self.stream.next() {
                    Some(file) => {
                        let seq = self.seq;
                        self.seq += 1;
                        self.in_flight += 1;
                        let tx = self.tx.clone();
                        rayon::spawn(move || {
                            let result = audit_file_checked(file);
                            let _ = tx.send((seq, result));
                        });
                    }
                    None => break,
                }
            }

            // The extraction stream is exhausted and every dispatched audit
            // has reported back: no result can arrive anymore.
            if self.in_flight == 0 && self.pending.is_empty() {
                return None;
            }

            match self.rx.recv() {
                Ok((seq, result)) => {
                    self.in_flight -= 1;
                    self.pending.insert(seq, result);
                }
                Err(_) => return None,
            }
        }
    }
}

/// Audit files in the provided directory or a file.
/// Automatically discovers Python files in .tar.gz, .zip files or in folders.
///
/// Files are pulled from the extraction stream lazily: each call to the
/// returned iterator keeps up to `MAX_IN_FLIGHT_AUDITS` audits running on the
/// rayon pool, which bounds memory. Results arrive out of order and are
/// reordered by discovery sequence before being yielded in order. Dropping
/// the iterator early stops extraction; audits already in flight finish on
/// their own.
pub fn audit_path(
    file_path: &Path,
    exclude_names: Option<&HashSet<String>>,
) -> Result<impl Iterator<Item = AuditResult>, String> {
    let stream: PythonFileStream = hexora_io::spawn_python_files(file_path, exclude_names)?;
    let (tx, rx) = std::sync::mpsc::channel::<(usize, Option<AuditResult>)>();

    Ok(OrderedAuditResults {
        stream,
        tx,
        rx,
        pending: HashMap::new(),
        seq: 0,
        in_flight: 0,
        next: 0,
    })
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
