pub mod ast;
pub mod import;
pub mod rule;
pub mod semantic;
pub mod source;
pub mod tests;

use crate::schema::FeatureRecord;
use hexora_rules::result::AuditItem;
use hexora_semantic::analysis::AnalyzedSource;
use std::collections::BTreeMap;
use std::path::Path;

pub fn extract_features(
    analyzed: &AnalyzedSource<'_, '_>,
    source: &str,
    items: &[AuditItem],
) -> FeatureRecord {
    let mut record = FeatureRecord::new();
    source::extract_source_features(&mut record, analyzed.locator, source);
    ast::extract_ast_features(&mut record, analyzed, source);
    import::extract_import_features(&mut record, analyzed);
    semantic::extract_semantic_features(&mut record, analyzed);
    rule::extract_rule_features(&mut record, items);
    let decoded = record.get("semantic.decoded_nodes").unwrap_or(0.0);
    let total_exprs = record.get("ast.total_exprs").unwrap_or(0.0);
    record.insert(
        "semantic.decoded_ratio",
        safe_ratio(decoded, total_exprs),
    );
    let dynamic = record.get("call.dynamic_count").unwrap_or(0.0);
    let total_calls = record.get("ast.num_calls").unwrap_or(0.0);
    record.insert("call.dynamic_ratio", safe_ratio(dynamic, total_calls));
    record.insert("meta.feature_count", record.len() as f64);
    record
}

pub fn extract_features_from_source(code: &str, file_path: &Path) -> Result<FeatureRecord, String> {
    let prepared = hexora_semantic::analysis::prepare_source(code)?;
    let items = hexora_rules::audit_prepared(&prepared, Some(file_path))?;
    let features =
        prepared.with_original_indexed(|analyzed| extract_features(&analyzed, code, &items));
    Ok(features)
}

fn safe_ratio(numer: f64, denom: f64) -> f64 {
    if denom > 0.0 {
        numer / denom
    } else {
        0.0
    }
}

#[derive(Debug, Default)]
pub(crate) struct StringStats {
    pub count: usize,
    pub total_len: usize,
    pub max_len: usize,
    pub total_entropy: f64,
    pub max_entropy: f64,
}

impl StringStats {
    pub fn observe(&mut self, value: &str) {
        self.count += 1;
        let char_count = value.chars().count();
        self.total_len += char_count;
        self.max_len = self.max_len.max(char_count);
        let entropy = shannon_entropy(value);
        self.total_entropy += entropy;
        self.max_entropy = self.max_entropy.max(entropy);
    }

    pub fn mean_len(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.total_len as f64 / self.count as f64
        }
    }

    pub fn mean_entropy(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.total_entropy / self.count as f64
        }
    }
}

pub(crate) fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }

    let mut counts = BTreeMap::new();
    let len = value.chars().count() as f64;
    for ch in value.chars() {
        *counts.entry(ch).or_insert(0usize) += 1;
    }

    counts
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            -(p * p.log2())
        })
        .sum()
}
