use crate::pipeline::audit_source;
use crate::result::{AuditConfidence, AuditResult, Rule};
use std::path::{Path, PathBuf};

pub fn get_resources_path() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // When running tests for hexora_rules, resources/test/ is in the hexora crate
    // Try both relative to hexora_rules and hexora
    let candidates = [
        manifest_dir.join("../../crates/hexora/resources/test/"),
        manifest_dir.join("../hexora/resources/test/"),
        manifest_dir.join("resources/test/"),
    ];
    for p in &candidates {
        if p.exists() {
            return Ok(p.clone());
        }
    }
    Err(format!(
        "Cannot find resources/test/ directory. Tried: {:?}",
        candidates
    ))
}

pub fn test_path(path: impl AsRef<Path>) -> Result<AuditResult, String> {
    let resources_path = get_resources_path()?;
    let path = resources_path.join(path);
    let source =
        std::fs::read_to_string(&path).map_err(|e| format!("{}: {}", e, path.display()))?;
    let items = audit_source(&source, Some(&path))?;
    Ok(AuditResult {
        items,
        path,
        archive_path: None,
        source_code: source,
    })
}

pub fn assert_audit_results_by_name(path: &str, category: Rule, expected_names: Vec<&str>) {
    match test_path(path) {
        Ok(result) => {
            let actual = result
                .items
                .iter()
                .filter(|r| r.rule == category)
                .map(|r| r.label.clone())
                .collect::<Vec<String>>();
            assert_eq!(actual, expected_names);
        }
        Err(e) => {
            panic!("test failed: {:?}", e);
        }
    }
}

pub fn assert_audit_results(path: &str, category: Rule, expected: Vec<(&str, AuditConfidence)>) {
    match test_path(path) {
        Ok(result) => {
            let actual = result
                .items
                .iter()
                .filter(|r| r.rule == category)
                .map(|r| (r.label.as_str(), r.confidence))
                .collect::<Vec<(&str, AuditConfidence)>>();
            assert_eq!(actual, expected);
        }
        Err(e) => {
            panic!("test failed: {:?}", e);
        }
    }
}
