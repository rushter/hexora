use crate::audit::parse::audit_file;
use crate::audit::result::{AuditResult, Rule};
use std::fs::canonicalize;
use std::io;
use std::path::{Path, PathBuf};

pub fn get_resources_path() -> io::Result<PathBuf> {
    let current_path = canonicalize(Path::new("."))?;
    Ok(current_path.join("resources/test/"))
}

pub fn test_path(path: impl AsRef<Path>) -> Result<AuditResult, String> {
    let resources_path = get_resources_path().map_err(|e| e.to_string())?;
    let path = resources_path.join(path);
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
            panic!("test failed: {:?}", e);
        }
    }
}
