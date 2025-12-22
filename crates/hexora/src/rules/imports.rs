use crate::indexer::checker::Checker;
use once_cell::sync::Lazy;
use ruff_python_ast::Stmt;
use serde::Serialize;
use std::collections::HashMap;

use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use ruff_python_ast::identifier::Identifier;
use ruff_python_ast::{self as ast};
use ruff_text_size::TextRange;

macro_rules! add_import {
    ($map:expr, $name:expr, $desc:expr, $rule:expr) => {
        $map.insert(
            $name,
            SuspiciousImport {
                name: $name,
                description: $desc,
                rule: $rule,
                confidence: None,
            },
        );
    };
    ($map:expr, $name:expr, $desc:expr, $rule:expr, $confidence:expr) => {
        $map.insert(
            $name,
            SuspiciousImport {
                name: $name,
                description: $desc,
                rule: $rule,
                confidence: Some($confidence),
            },
        );
    };
}

#[derive(Debug, Serialize)]
pub struct SuspiciousImport {
    pub name: &'static str,
    pub description: Option<&'static str>,
    pub rule: Option<Rule>,
    pub confidence: Option<AuditConfidence>,
}

#[rustfmt::skip]
static IMPORTS: Lazy<HashMap<&str, SuspiciousImport>> = Lazy::new(|| {
    let mut m = HashMap::new();
    add_import!(m, "struct", None, Some(Rule::StructImport));
    add_import!(m, "ctypes", None, Some(Rule::CtypesImport));
    add_import!(m, "scapy", Some("scapy can be used to craft malicious packets."), None);
    add_import!(m, "impacket", Some("impacket can be used to craft malicious payload"), None);
    add_import!(m, "winappdbg", Some("winappdbg can be used to access process memory."), None);
    add_import!(m, "stegano", Some("stegano is a library that can be used to hide data in images."), None);
    add_import!(m, "judyb", Some("judyb is a library that can be used to hide data in images."), None);
    add_import!(m, "steganography", Some("steganography is a library that can be used to hide data in images."), None);
    add_import!(m, "pynput", Some("pynput can be used to monitor input devices and implement keyloggers."), None);
    add_import!(m, "keyboard", Some("keyboard enables global key event hooks and keylogging."), None);
    add_import!(m, "mss", Some("mss package allows taking screenshots of your system"), None);
    add_import!(m, "telnetlib", Some("telnetlib can be used to automate Telnet sessions for unauthorized access."), None);
    add_import!(m, "ftplib", Some("ftplib can be used to exfiltrate data"), None);
    add_import!(m, "pickle", None, Some(Rule::PickleImport));
    add_import!(m, "marshal", None, Some(Rule::MarshalImport));
    add_import!(m, "socket", None, Some(Rule::SocketImport));
    add_import!(m, "pyperclip", Some("pyperclip can be used to copy and paste data from the clipboard."), None, AuditConfidence::High);
    add_import!(m, "paramiko", Some("paramiko can be used to automate SSH sessions for unauthorized access."), None);
    add_import!(m, "win32com", Some("win32com can be used to exploit Windows systems."), None);
    add_import!(m, "getpass", Some("getpass can be used to  capture user credentials."), None);
    add_import!(m, "browser_cookie3", Some("browser-cookie3 can be used to steal browser cookies."), None, AuditConfidence::High);
    m
});

fn add_suspicious_import(
    checker: &mut Checker,
    suspicious_import: &SuspiciousImport,
    label: String,
    location: TextRange,
) {
    let description = match &suspicious_import.description {
        Some(description) => description.to_string(),
        None => suspicious_import
            .rule
            .as_ref()
            .expect("Rule should be set for suspicious imports")
            .description()
            .to_string(),
    };
    let rule = match &suspicious_import.rule {
        Some(rule) => *rule,
        None => Rule::SuspiciousImport,
    };
    let confidence = suspicious_import.confidence.unwrap_or(AuditConfidence::Low);
    checker.audit_results.push(AuditItem {
        label,
        rule,
        description,
        confidence,
        location: Some(location),
    });
}

pub fn check_import(stmt: &Stmt, checker: &mut Checker) {
    match stmt {
        Stmt::Import(ast::StmtImport { names, .. }) => {
            for name in names {
                let import_name = name.name.as_str();
                if let Some(suspicious_import) = IMPORTS.get(import_name) {
                    add_suspicious_import(
                        checker,
                        suspicious_import,
                        import_name.to_string(),
                        name.range,
                    );
                }
            }
        }
        Stmt::ImportFrom(ast::StmtImportFrom { module, names, .. }) => {
            let Some(identifier) = module else { return };
            let import_name = identifier.as_str();
            if let Some(suspicious_import) = IMPORTS.get(import_name) {
                add_suspicious_import(
                    checker,
                    suspicious_import,
                    import_name.to_string(),
                    identifier.range,
                );
            }

            for alias in names {
                let bound_name = alias.asname.as_ref().unwrap_or(&alias.name);
                if let Some(confidence) =
                    crate::rules::identifier::is_suspicious_variable(bound_name.as_str())
                {
                    checker.audit_results.push(AuditItem {
                        label: bound_name.as_str().to_string(),
                        rule: Rule::SuspiciousVariable,
                        description: format!("Suspicious variable name: {}", bound_name.as_str()),
                        confidence,
                        location: Some(alias.identifier()),
                    });
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::{AuditConfidence, Rule};
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("imports_01.py", Rule::SuspiciousImport, vec!["scapy"])]
    #[test_case("imports_01.py", Rule::CtypesImport, vec!["ctypes"])]
    #[test_case("imports_01.py", Rule::StructImport, vec!["struct"])]
    fn test_imports(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }

    #[test]
    fn test_import_confidence_default() {
        let result = test_path("imports_01.py").unwrap();
        for item in result.items {
            if item.rule == Rule::SuspiciousImport
                || item.rule == Rule::CtypesImport
                || item.rule == Rule::StructImport
            {
                assert_eq!(item.confidence, AuditConfidence::Low);
            }
        }
    }
}
