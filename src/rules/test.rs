use crate::audit::parse::audit_file;
use crate::audit::result::{AuditResult, Rule};
use std::fs::canonicalize;
use std::path::Path;

pub fn get_resources_path() -> std::path::PathBuf {
    let current_path = canonicalize(Path::new(".")).unwrap();
    current_path.join("resources/test/")
}

pub fn test_path(path: impl AsRef<Path>) -> Result<AuditResult, String> {
    let path = get_resources_path().join(path);
    audit_file(path.as_path())
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
            panic!("{:?}", e);
        }
    }
}
