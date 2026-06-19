use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FeatureRecord {
    values: BTreeMap<String, f64>,
}

impl FeatureRecord {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: impl Into<String>, value: f64) {
        self.values.insert(key.into(), value);
    }

    pub fn add(&mut self, key: impl Into<String>, delta: f64) {
        *self.values.entry(key.into()).or_insert(0.0) += delta;
    }

    pub fn set_flag(&mut self, key: impl Into<String>) {
        self.insert(key, 1.0);
    }

    pub fn get(&self, key: &str) -> Option<f64> {
        self.values.get(key).copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, f64)> {
        self.values
            .iter()
            .map(|(key, value)| (key.as_str(), *value))
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FeatureSchema {
    indices: HashMap<String, usize>,
    names: Vec<String>,
}

impl FeatureSchema {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fit<'a>(records: impl IntoIterator<Item = &'a FeatureRecord>) -> Self {
        let mut schema = Self::new();
        for record in records {
            for (name, _) in record.iter() {
                schema.ensure_feature(name);
            }
        }
        schema
    }

    pub fn ensure_feature(&mut self, name: &str) -> usize {
        if let Some(&index) = self.indices.get(name) {
            return index;
        }

        let index = self.names.len();
        let owned = name.to_string();
        self.indices.insert(owned.clone(), index);
        self.names.push(owned);
        index
    }

    pub fn encode(&self, record: &FeatureRecord) -> Vec<f64> {
        let mut dense = vec![0.0; self.names.len()];
        for (name, value) in record.iter() {
            if let Some(&index) = self.indices.get(name) {
                dense[index] = value;
            }
        }
        dense
    }

    pub fn feature_names(&self) -> &[String] {
        &self.names
    }
}
