use crate::schema::FeatureRecord;
use hexora_rules::result::{AuditConfidence, AuditItem, Rule};
use std::collections::BTreeMap;

pub(crate) fn extract_rule_features(record: &mut FeatureRecord, items: &[AuditItem]) {
    record.insert("rule.total_hits", items.len() as f64);

    let mut per_rule = BTreeMap::new();
    for rule in Rule::iter() {
        per_rule.insert(rule.code(), RuleStats::default());
    }
    let mut total_score = 0.0;
    let mut max_score: f64 = 0.0;
    let mut min_score = f64::INFINITY;

    for item in items {
        let score = confidence_score(item.confidence);
        total_score += score;
        max_score = max_score.max(score);
        min_score = min_score.min(score);

        record.add(
            format!("confidence.{:?}", item.confidence).to_lowercase(),
            1.0,
        );

        let stats = per_rule.entry(item.rule.code()).or_default();
        stats.count += 1;
        stats.sum += score;
        stats.max = stats.max.max(score);
        stats.min = stats.min.min(score);
    }

    record.insert("rule.score_sum", total_score);
    record.insert("rule.score_max", max_score);
    record.insert(
        "rule.score_min",
        if items.is_empty() { 0.0 } else { min_score },
    );

    for (code, stats) in per_rule {
        record.insert(format!("rule.count.{code}"), stats.count as f64);
        record.insert(format!("rule.conf_sum.{code}"), stats.sum);
        record.insert(format!("rule.conf_max.{code}"), stats.max);
        record.insert(
            format!("rule.conf_min.{code}"),
            if stats.count == 0 { 0.0 } else { stats.min },
        );
    }
}

#[derive(Debug, Clone, Copy)]
struct RuleStats {
    count: usize,
    sum: f64,
    max: f64,
    min: f64,
}

impl Default for RuleStats {
    fn default() -> Self {
        Self {
            count: 0,
            sum: 0.0,
            max: 0.0,
            min: f64::INFINITY,
        }
    }
}

fn confidence_score(confidence: AuditConfidence) -> f64 {
    confidence as u8 as f64
}
