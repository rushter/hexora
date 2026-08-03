//! CatBoost inference module.
//!
//! This is a minimal inference-only implementation of Catboost to avoid pulling in C++
//! dependencies. Based on <https://github.com/wafer-inc/catboost> (MIT License),
//! but supports our own feature format.

use crate::schema::FeatureRecord;
use serde::Deserialize;
use std::{fmt, fs::File, io::BufReader, path::Path, sync::OnceLock};

static MODEL_JSON: OnceLock<String> = OnceLock::new();
static SCORE_MODEL: OnceLock<ScoreModel> = OnceLock::new();

fn decompress_model() -> &'static str {
    MODEL_JSON.get_or_init(|| {
        let compressed = include_bytes!("model.json.gz");
        let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
        let mut s = String::new();
        std::io::Read::read_to_string(&mut decoder, &mut s)
            .expect("failed to decompress embedded model");
        s
    })
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CatBoost {
    features_info: Features,
    oblivious_trees: Vec<ObliviousTree>,
    scale_and_bias: (f32, Vec<f32>),
    #[serde(skip)]
    num_features: usize,
    #[serde(skip)]
    prepared: Prepared,
}

/// Precomputed inference state: only the features that actually appear in
/// splits (the rest cannot influence the prediction), ordered by feature id
/// so record lookups can be a single linear merge over the sorted record.
#[derive(Debug, Clone, Default)]
struct Prepared {
    features: Vec<PreparedFeature>,
    total_borders: usize,
}

#[derive(Debug, Clone)]
struct PreparedFeature {
    key: String,
    flat_index: usize,
    borders_offset: usize,
    borders: Vec<f32>,
    has_nans: bool,
    nan_value_treatment: NanValueTreatment,
}

thread_local! {
    static PREDICT_BUFFERS: std::cell::RefCell<PredictBuffers> =
        std::cell::RefCell::new(PredictBuffers::default());
}

#[derive(Default)]
struct PredictBuffers {
    values: Vec<f32>,
    go_lefts: Vec<bool>,
}

impl CatBoost {
    pub fn load(path: &Path) -> Result<Self, std::io::Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut model: CatBoost = serde_json::from_reader(reader)?;
        model.num_features = model.compute_num_features();
        model.prepared = model.prepare();
        Ok(model)
    }

    pub fn try_from_json(model_str: &str) -> Result<Self, serde_json::Error> {
        let mut model: CatBoost = serde_json::from_str(model_str)?;
        model.num_features = model.compute_num_features();
        model.prepared = model.prepare();
        Ok(model)
    }

    fn compute_num_features(&self) -> usize {
        self.features_info
            .float_features
            .iter()
            .map(|f| f.flat_feature_index)
            .max()
            .map_or(0, |m| m + 1)
    }

    fn num_features(&self) -> usize {
        self.num_features
    }

    fn prepare(&self) -> Prepared {
        let mut offset = 0usize;
        let mut features = Vec::new();
        for f in &self.features_info.float_features {
            if !f.borders.is_empty() {
                features.push(PreparedFeature {
                    key: f.feature_id.clone(),
                    flat_index: f.flat_feature_index,
                    borders_offset: offset,
                    borders: f.borders.clone(),
                    has_nans: f.has_nans,
                    nan_value_treatment: f.nan_value_treatment,
                });
            }
            offset += f.borders.len();
        }
        features.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        Prepared {
            features,
            total_borders: offset,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
struct Features {
    float_features: Vec<FloatFeature>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FloatFeature {
    pub feature_id: String,
    #[allow(dead_code)]
    feature_index: usize,
    flat_feature_index: usize,
    borders: Vec<f32>,
    #[allow(dead_code)]
    has_nans: bool,
    nan_value_treatment: NanValueTreatment,
}

#[derive(Debug, Deserialize, PartialEq, Clone, Copy)]
pub enum NanValueTreatment {
    #[serde(rename = "AsIs")]
    Unspecified,
    #[serde(rename = "AsTrue")]
    Left,
    #[serde(rename = "AsFalse")]
    Right,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ObliviousTree {
    leaf_values: Vec<f32>,
    splits: Vec<Split>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", tag = "")]
pub struct Split {
    #[allow(dead_code)]
    split_type: SplitType,
    #[allow(dead_code)]
    float_feature_index: usize,
    split_index: usize,
    #[allow(dead_code)]
    border: f32,
}

#[derive(Debug, Clone, Deserialize)]
pub enum SplitType {
    #[serde(rename = "FloatFeature")]
    FloatFeature,
}

#[derive(Debug, serde::Serialize)]
pub enum InferenceError {
    NumFeaturesMismatch { expected: usize, actual: usize },
}

impl fmt::Display for InferenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InferenceError::NumFeaturesMismatch { expected, actual } => {
                write!(
                    f,
                    "Incorrect number of features provided. Expected {expected}, got {actual}."
                )
            }
        }
    }
}

impl std::error::Error for InferenceError {}

impl CatBoost {
    pub fn predict(&self, features: &[f32]) -> Result<f32, InferenceError> {
        let prediction = self.predict_raw(features)?;
        Ok(1.0 / (1.0 + (-prediction).exp()))
    }

    pub fn predict_raw(&self, features: &[f32]) -> Result<f32, InferenceError> {
        let expected_features = self.num_features();
        if features.len() != expected_features {
            return Err(InferenceError::NumFeaturesMismatch {
                expected: expected_features,
                actual: features.len(),
            });
        }

        let go_lefts = self
            .features_info
            .float_features
            .iter()
            .flat_map(|f| {
                let feature_value = features[f.flat_feature_index];
                f.borders.iter().map(move |border| {
                    if feature_value.is_nan() {
                        if !f.has_nans {
                            false
                        } else {
                            match f.nan_value_treatment {
                                NanValueTreatment::Unspecified => false,
                                NanValueTreatment::Left => true,
                                NanValueTreatment::Right => false,
                            }
                        }
                    } else {
                        feature_value > *border
                    }
                })
            })
            .collect::<Vec<bool>>();

        let logits = self
            .oblivious_trees
            .iter()
            .map(|tree| {
                let depth = tree.splits.len();
                if depth == 0 {
                    if !tree.leaf_values.is_empty() {
                        return tree.leaf_values[0];
                    }
                    panic!("No leaf values");
                }
                let mut current_leaf_index = 0usize;
                for (level, split) in tree.splits.iter().enumerate() {
                    current_leaf_index |= (go_lefts[split.split_index] as usize) << level;
                }
                tree.leaf_values[current_leaf_index]
            })
            .sum::<f32>();

        let scale = self.scale_and_bias.0;
        let bias = self.scale_and_bias.1.first().unwrap_or(&0.0);
        Ok(logits * scale + bias)
    }

    pub fn predict_from_record(&self, record: &FeatureRecord) -> Result<f32, InferenceError> {
        let prediction = self.predict_raw_from_record(record)?;
        Ok(1.0 / (1.0 + (-prediction).exp()))
    }

    pub fn predict_raw_from_record(&self, record: &FeatureRecord) -> Result<f32, InferenceError> {
        PREDICT_BUFFERS.with(|buffers| {
            let mut buffers = buffers.borrow_mut();
            let values = &mut buffers.values;
            values.clear();
            values.resize(self.num_features(), 0.0f32);

            let mut entries = record.iter();
            let mut current = entries.next();
            for feature in &self.prepared.features {
                while let Some((key, _)) = current {
                    if key < feature.key.as_str() {
                        current = entries.next();
                    } else {
                        break;
                    }
                }
                if let Some((key, value)) = current {
                    if key == feature.key.as_str() {
                        values[feature.flat_index] = value as f32;
                        current = entries.next();
                    }
                }
            }

            let logits = self.predict_with_values(&mut buffers)?;
            let scale = self.scale_and_bias.0;
            let bias = self.scale_and_bias.1.first().unwrap_or(&0.0);
            Ok(logits * scale + bias)
        })
    }

    fn predict_with_values(&self, buffers: &mut PredictBuffers) -> Result<f32, InferenceError> {
        let values = &buffers.values;
        let go_lefts = &mut buffers.go_lefts;
        go_lefts.clear();
        go_lefts.resize(self.prepared.total_borders, false);

        for feature in &self.prepared.features {
            let feature_value = values[feature.flat_index];
            if feature_value.is_nan() {
                let left = if !feature.has_nans {
                    false
                } else {
                    match feature.nan_value_treatment {
                        NanValueTreatment::Unspecified => false,
                        NanValueTreatment::Left => true,
                        NanValueTreatment::Right => false,
                    }
                };
                for slot in &mut go_lefts
                    [feature.borders_offset..feature.borders_offset + feature.borders.len()]
                {
                    *slot = left;
                }
            } else {
                for (i, border) in feature.borders.iter().enumerate() {
                    go_lefts[feature.borders_offset + i] = feature_value > *border;
                }
            }
        }

        let logits = self
            .oblivious_trees
            .iter()
            .map(|tree| {
                let depth = tree.splits.len();
                if depth == 0 {
                    if !tree.leaf_values.is_empty() {
                        return tree.leaf_values[0];
                    }
                    panic!("No leaf values");
                }
                let mut current_leaf_index = 0usize;
                for (level, split) in tree.splits.iter().enumerate() {
                    current_leaf_index |= (go_lefts[split.split_index] as usize) << level;
                }
                tree.leaf_values[current_leaf_index]
            })
            .sum::<f32>();
        Ok(logits)
    }
}

#[derive(Debug, Clone)]
pub struct ScoreModel {
    catboost: CatBoost,
}

impl ScoreModel {
    pub fn load(path: &Path) -> Result<Self, std::io::Error> {
        CatBoost::load(path).map(|catboost| Self { catboost })
    }

    pub fn embedded() -> Result<Self, serde_json::Error> {
        CatBoost::try_from_json(decompress_model()).map(|catboost| Self { catboost })
    }

    pub fn cached() -> &'static Self {
        SCORE_MODEL
            .get_or_init(|| Self::embedded().expect("failed to load embedded CatBoost model"))
    }

    pub fn predict(&self, record: &FeatureRecord) -> Result<f64, InferenceError> {
        self.catboost.predict_from_record(record).map(|p| p as f64)
    }

    pub fn predict_raw(&self, record: &FeatureRecord) -> Result<f64, InferenceError> {
        self.catboost
            .predict_raw_from_record(record)
            .map(|p| p as f64)
    }
}

impl Default for ScoreModel {
    fn default() -> Self {
        Self::cached().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::fs;

    #[test]
    fn test_embedded_model_predictions() {
        let model = ScoreModel::load(Path::new("resources/test/model.json")).unwrap();
        let data = fs::read_to_string("resources/test/dataset.json").unwrap();
        let expected = [
            0.0040038, 0.01497678, 0.00442786, 0.00387944, 0.00239373, 0.93382871, 0.97137932,
            0.98279432, 0.96473167, 0.17695585,
        ];

        for (line, &exp) in data.lines().zip(expected.iter()) {
            let map: serde_json::Map<String, Value> = serde_json::from_str(line).unwrap();
            let mut record = FeatureRecord::new();
            for (k, v) in map {
                if let Some(n) = v.as_f64() {
                    record.insert(k, n);
                }
            }
            let prob = model.predict(&record).unwrap();
            let diff = (prob - exp).abs();
            assert!(diff < 1e-4, "expected {exp}, got {prob} (diff {diff})");
        }
    }
}
