use crate::audit::parse::audit_path;
use crate::audit::result::{AuditConfidence, Rule};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Default)]
pub struct BenchmarkResult {
    pub input_path: String,
    pub total_files: usize,
    pub total_matches: usize,
    pub duration: Duration,
    pub confidence_counts: HashMap<AuditConfidence, usize>,
    pub rule_counts: HashMap<Rule, usize>,
    pub archive_path_counts: HashMap<String, usize>,
}

impl BenchmarkResult {
    pub fn print_results(&self, print_missing: bool) {
        println!("Benchmark results for: {}", self.input_path);
        println!("Total files: {}", self.total_files);
        println!("Total matches: {}", self.total_matches);
        println!("Time elapsed: {:?}", self.duration);

        println!("\nMatches by Confidence:");
        let mut confidence_counts: Vec<_> = self.confidence_counts.iter().collect();
        confidence_counts.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        for (confidence, count) in confidence_counts {
            println!("  {:?}: {}", confidence, count);
        }

        println!("\nMatches by Rule Code:");
        let mut rule_counts: Vec<_> = self.rule_counts.iter().collect();
        rule_counts.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.code().cmp(b.0.code())));
        for (rule, count) in rule_counts {
            println!("{:?} ({}): {}", rule, rule.code(), count);
        }

        if print_missing {
            let mut missing_audits: Vec<_> = self
                .archive_path_counts
                .iter()
                .filter(|&(_, &count)| count == 0)
                .map(|(path, _)| path)
                .collect();
            missing_audits.sort();

            if !missing_audits.is_empty() {
                println!("\nZip paths with missing audits:");
                for path in missing_audits {
                    println!("Missing audits for: {}", path);
                }
            }
        }
    }
}

pub fn run_benchmark(
    path: &Path,
    exclude_names: Option<&HashSet<String>>,
    min_confidence: AuditConfidence,
) -> Result<BenchmarkResult, String> {
    let start = Instant::now();
    let audit_results = audit_path(path, exclude_names).map_err(|e| e.to_string())?;
    let duration = start.elapsed();

    let mut benchmark_result = BenchmarkResult {
        input_path: path.to_string_lossy().to_string(),
        duration,
        ..Default::default()
    };

    for result in audit_results {
        benchmark_result.total_files += 1;
        if let Some(archive_path) = &result.archive_path {
            benchmark_result
                .archive_path_counts
                .entry(archive_path.to_string_lossy().to_string())
                .or_insert(0);
        }

        for item in result.items {
            if item.confidence < min_confidence {
                continue;
            }
            benchmark_result.total_matches += 1;

            *benchmark_result
                .confidence_counts
                .entry(item.confidence)
                .or_insert(0) += 1;

            *benchmark_result.rule_counts.entry(item.rule).or_insert(0) += 1;

            if let Some(archive_path) = &result.archive_path {
                *benchmark_result
                    .archive_path_counts
                    .entry(archive_path.to_string_lossy().to_string())
                    .or_insert(0) += 1;
            }
        }
    }

    Ok(benchmark_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_benchmark_counts() {
        let test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/test");
        let result =
            run_benchmark(&test_path, None, AuditConfidence::VeryLow).expect("Benchmark failed");

        assert!(result.total_files > 0);
        assert!(result.total_matches > 0);

        let sum_confidence: usize = result.confidence_counts.values().sum();
        assert_eq!(sum_confidence, result.total_matches);

        let sum_rules: usize = result.rule_counts.values().sum();
        assert_eq!(sum_rules, result.total_matches);

        assert!(result.rule_counts.keys().any(|r| r.code() == "HX4010"));
    }

    #[test]
    fn test_benchmark_confidence_filter() {
        let test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/test");

        let result_all =
            run_benchmark(&test_path, None, AuditConfidence::VeryLow).expect("Benchmark failed");

        let result_high =
            run_benchmark(&test_path, None, AuditConfidence::High).expect("Benchmark failed");

        assert!(result_all.total_matches >= result_high.total_matches);

        for (&confidence, &count) in &result_high.confidence_counts {
            assert!(confidence >= AuditConfidence::High);
            assert!(count > 0);
        }
    }
}
