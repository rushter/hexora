use crate::dataset::LabeledFeatureRow;
use crate::features::extract_features_from_source;
use flate2::read::GzDecoder;
use hexora_io::encoding::base64_decode;
use hexora_rules::pipeline::audit_source;
use hexora_rules::result::{AuditConfidence, AuditItem};
use log::error;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[derive(Deserialize)]
struct DatasetEntry {
    code: String,
    verdict: String,
    file: String,
}

fn open_dataset(input_path: &Path) -> Option<Box<dyn BufRead>> {
    let file = File::open(input_path).ok()?;
    let reader: Box<dyn BufRead> = if input_path.extension().is_some_and(|ext| ext == "gz") {
        Box::new(BufReader::new(GzDecoder::new(file)))
    } else {
        Box::new(BufReader::new(file))
    };
    Some(reader)
}

fn output_writer(output_path: Option<&Path>) -> Option<Box<dyn Write>> {
    let writer: Box<dyn Write> = match output_path {
        Some(path) => Box::new(File::create(path).ok()?),
        None => Box::new(std::io::stdout()),
    };
    Some(writer)
}

fn decode_entry_code(code_b64: &str) -> Result<String, String> {
    let bytes = base64_decode(code_b64, false).ok_or("invalid base64 code")?;
    String::from_utf8(bytes).map_err(|e| format!("code is not valid UTF-8: {}", e))
}

#[derive(Serialize)]
struct ValidateRuleOutput {
    code: &'static str,
    label: String,
    description: String,
    confidence: AuditConfidence,
}

#[derive(Serialize)]
struct ValidateFileOutput {
    file: String,
    rules: Vec<ValidateRuleOutput>,
}

fn write_validate_json(writer: &mut dyn Write, file: String, items: &[AuditItem]) -> bool {
    let output = ValidateFileOutput {
        file,
        rules: items
            .iter()
            .map(|item| ValidateRuleOutput {
                code: item.rule.code(),
                label: item.label.clone(),
                description: item.description.clone(),
                confidence: item.confidence,
            })
            .collect(),
    };
    serde_json::to_string(&output)
        .ok()
        .and_then(|json| writeln!(writer, "{json}").ok())
        .is_some()
}

pub fn process_raw_entry(code_b64: &str, file: &str, verdict: &str) -> Result<String, String> {
    let code = decode_entry_code(code_b64)?;
    let features = extract_features_from_source(&code, Path::new(file))?;
    let row = LabeledFeatureRow::new(features, verdict.to_string(), file.to_string());
    serde_json::to_string(&row).map_err(|e| e.to_string())
}

pub fn validate_dataset_entry(code_b64: &str, file: &str) -> Result<Vec<AuditItem>, String> {
    let code = decode_entry_code(code_b64)?;
    audit_source(&code, Some(Path::new(file))).map_err(|e| format!("audit error: {e}"))
}

pub fn validate_dataset(
    input_path: &Path,
    output_path: Option<&Path>,
    min_confidence: AuditConfidence,
    no_rules_only: bool,
) {
    let Some(reader) = open_dataset(input_path) else {
        error!("Failed to open input file: {:?}", input_path);
        return;
    };
    let Some(mut writer) = output_writer(output_path) else {
        error!("Failed to create output file");
        return;
    };

    for (line_num, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                error!("Line {}: read error: {}", line_num + 1, e);
                continue;
            }
        };

        let entry: DatasetEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                error!("Line {}: invalid JSON: {}", line_num + 1, e);
                continue;
            }
        };

        if entry.verdict != "malicious" {
            continue;
        }

        let audit_items = match validate_dataset_entry(&entry.code, &entry.file) {
            Ok(items) => items
                .into_iter()
                .filter(|item| item.confidence >= min_confidence)
                .collect::<Vec<_>>(),
            Err(e) => {
                error!("Line {}: {}", line_num + 1, e);
                continue;
            }
        };

        if no_rules_only && !audit_items.is_empty() {
            continue;
        }

        if !write_validate_json(&mut writer, entry.file, &audit_items) {
            error!("Line {}: failed to write output", line_num + 1);
            return;
        }
    }
}

pub fn read_file_from_dataset(input_path: &Path, file_path: &str) {
    let Some(reader) = open_dataset(input_path) else {
        error!("Failed to open input file: {:?}", input_path);
        return;
    };

    for (line_num, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                error!("Line {}: read error: {}", line_num + 1, e);
                continue;
            }
        };

        let entry: DatasetEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                error!("Line {}: invalid JSON: {}", line_num + 1, e);
                continue;
            }
        };

        if entry.file != file_path {
            continue;
        }

        match decode_entry_code(&entry.code) {
            Ok(code) => {
                println!("{code}");
                return;
            }
            Err(e) => {
                error!("Line {}: {}", line_num + 1, e);
                return;
            }
        }
    }

    error!("No entry found with file: {file_path}");
}

pub fn generate_features_from_dataset(
    input_path: &Path,
    output_path: Option<&Path>,
    limit: Option<usize>,
) {
    let Some(reader) = open_dataset(input_path) else {
        error!("Failed to open input file: {:?}", input_path);
        return;
    };
    let Some(mut writer) = output_writer(output_path) else {
        error!("Failed to create output file");
        return;
    };

    let mut processed: usize = 0;
    for (line_num, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                error!("Line {}: read error: {}", line_num + 1, e);
                continue;
            }
        };

        let entry: DatasetEntry = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                error!("Line {}: invalid JSON: {}", line_num + 1, e);
                continue;
            }
        };

        let json = match process_raw_entry(&entry.code, &entry.file, &entry.verdict) {
            Ok(j) => j,
            Err(e) => {
                error!("Line {}: {}", line_num + 1, e);
                continue;
            }
        };

        if writeln!(writer, "{json}").is_err() {
            error!("Line {}: failed to write output", line_num + 1);
            return;
        }

        processed += 1;
        if let Some(limit) = limit {
            if processed >= limit {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;

    #[test]
    fn test_generate_features_from_dataset() {
        let dir = std::env::temp_dir().join("hexora_test_gen_features");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let input_path = dir.join("input.jsonl");
        let output_path = dir.join("output.jsonl");

        let benign_code = "eCA9IDE=";
        let malicious_code = "aW1wb3J0IG9zCm9zLnN5c3RlbSgiaWQiKQo=";

        let entries = vec![
            format!(
                r#"{{"archive":"test.zip","file":"hello.py","reason":"","code":"{}","verdict":"benign","lines":null}}"#,
                benign_code
            ),
            format!(
                r#"{{"archive":"test.zip","file":"evil.py","reason":"","code":"{}","verdict":"malicious","lines":null}}"#,
                malicious_code
            ),
        ];

        fs::write(&input_path, entries.join("\n")).unwrap();

        generate_features_from_dataset(&input_path, Some(&output_path), None);

        let mut output = String::new();
        fs::File::open(&output_path)
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();

        let lines: Vec<&str> = output.lines().collect();
        assert_eq!(lines.len(), 2, "Expected 2 output lines, got: {:?}", lines);

        for line in &lines {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(value.get("_label").is_some(), "Missing _label in: {}", line);
            assert!(
                value.get("_file_path").is_some(),
                "Missing _file_path in: {}",
                line
            );
            assert!(
                value.get("source.num_lines").is_some(),
                "Missing feature in: {}",
                line
            );
        }

        assert_eq!(lines[0].contains("\"_label\":\"benign\""), true);
        assert_eq!(lines[1].contains("\"_label\":\"malicious\""), true);

        let _ = fs::remove_dir_all(&dir);
    }
}
