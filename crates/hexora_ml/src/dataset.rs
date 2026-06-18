use crate::schema::{FeatureRecord, FeatureSchema};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledFeatureRecord {
    pub label: f64,
    pub features: FeatureRecord,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrainingDataset {
    pub rows: Vec<LabeledFeatureRecord>,
}

impl TrainingDataset {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, row: LabeledFeatureRecord) {
        self.rows.push(row);
    }

    pub fn build_schema(&self) -> FeatureSchema {
        FeatureSchema::fit(self.rows.iter().map(|row| &row.features))
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LabeledFeatureRow {
    #[serde(flatten)]
    pub features: FeatureRecord,
    pub _label: String,
    pub _file_path: String,
}

impl LabeledFeatureRow {
    pub fn new(features: FeatureRecord, label: String, file_path: String) -> Self {
        Self {
            features,
            _label: label,
            _file_path: file_path,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_labeled_feature_row_serialization() {
        let mut features = FeatureRecord::new();
        features.insert("source.num_lines", 10.0);
        features.insert("source.num_bytes", 42.0);

        let row = LabeledFeatureRow::new(
            features,
            "benign".to_string(),
            "sample.py".to_string(),
        );

        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("\"source.num_lines\":10.0"));
        assert!(json.contains("\"source.num_bytes\":42.0"));
        assert!(json.contains("\"_label\":\"benign\""));
        assert!(json.contains("\"_file_path\":\"sample.py\""));
    }

    #[test]
    fn test_labeled_feature_row_verdict_values() {
        let features = FeatureRecord::new();
        let row = LabeledFeatureRow::new(
            features,
            "malicious".to_string(),
            "evil.py".to_string(),
        );

        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(json["_label"], "malicious");
        assert_eq!(json["_file_path"], "evil.py");
    }
}
