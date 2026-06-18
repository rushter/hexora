use crate::audit::annotate::annotate_results;
use hexora_ml::FeatureRecord;
pub use hexora_rules::result::{AuditConfidence, AuditItem};
use log::error;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct AuditResult {
    pub items: Vec<AuditItem>,
    pub features: FeatureRecord,
    pub path: PathBuf,
    pub archive_path: Option<PathBuf>,
    pub score: f64,
    pub source_code: String,
}

fn sha256_path(path: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

impl AuditResult {
    pub fn file_score(&self) -> f64 {
        self.score
    }

    pub fn filter_items<'a>(
        &'a self,
        include_codes: &'a HashSet<String>,
        exclude_codes: &'a HashSet<String>,
        min_confidence: AuditConfidence,
    ) -> impl Iterator<Item = &'a AuditItem> + 'a {
        self.items.iter().filter(move |item| {
            if item.confidence < min_confidence {
                return false;
            }

            let code = item.rule.code();

            if !include_codes.is_empty() && !include_codes.contains(code) {
                return false;
            }

            if exclude_codes.contains(code) {
                return false;
            }

            true
        })
    }
    pub fn annotate_to_file(&self, items: &[&AuditItem], dest_folder: &Path) {
        if items.is_empty() {
            return;
        }
        let file_name = format!("audit_{}.py", sha256_path(&self.path));
        let dest_path = dest_folder.join(file_name);
        let annotations = annotate_results(
            items.iter().copied(),
            &self.path,
            self.archive_path.as_deref(),
            &self.source_code,
        );
        match annotations {
            Ok(annotated) => {
                std::fs::write(&dest_path, annotated).unwrap_or_else(|e| {
                    error!(
                        "Failed to write annotations to file {:?}: {:?}",
                        dest_path, e
                    )
                });
            }
            Err(e) => {
                error!("Failed to annotate results for file {:?}: {}", self.path, e);
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuditItemJSON<'a> {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_path: Option<String>,
    pub label: &'a String,
    pub rule: &'a str,
    pub description: &'a String,
    pub confidence: &'a AuditConfidence,
    pub location_start: Option<usize>,
    pub location_end: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotation: Option<String>,
}
impl<'a> AuditItemJSON<'a> {
    pub fn new(
        item: &'a AuditItem,
        path: &Path,
        archive_path: Option<&Path>,
        source_code: &str,
        annotate: bool,
    ) -> Self {
        let annotation = if annotate {
            crate::audit::annotate::annotation_preview(item, path, archive_path, source_code, 2)
                .inspect_err(|err| error!("Failed to annotate result: {}", err))
                .ok()
        } else {
            None
        };

        Self {
            path: path.display().to_string(),
            archive_path: archive_path.map(|p| p.display().to_string()),
            label: &item.label,
            rule: item.rule.code(),
            description: &item.description,
            confidence: &item.confidence,
            location_start: item.location.map(|l| l.start().into()),
            location_end: item.location.map(|l| l.end().into()),
            annotation,
        }
    }
}
