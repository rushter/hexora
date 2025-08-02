use crate::audit::parse::Checker;
use once_cell::sync::Lazy;
use ruff_python_ast::Stmt;
use serde::Serialize;
use std::collections::HashMap;

use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use ruff_python_ast::{self as ast};

#[derive(Debug, Serialize)]
pub struct SuspiciousImport {
    pub name: String,
    pub description: Option<String>,
    pub rule: Option<Rule>,
}

static IMPORTS: Lazy<HashMap<&str, SuspiciousImport>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(
        "struct",
        SuspiciousImport {
            name: "struct".to_string(),
            description: None,
            rule: Some(Rule::StructImport),
        },
    );
    m.insert(
        "ctypes",
        SuspiciousImport {
            name: "ctypes".to_string(),
            description: None,
            rule: Some(Rule::CtypesImport),
        },
    );

    m.insert(
        "scapy",
        SuspiciousImport {
            name: "scapy".to_string(),
            description: Some("scapy can be used to craft malicious packets.".to_string()),
            rule: None,
        },
    );
    m.insert(
        "impacket",
        SuspiciousImport {
            name: "impacket".to_string(),
            description: Some("impacket can be used to craft malicious payload".to_string()),
            rule: None,
        },
    );
    m.insert(
        "winappdbg",
        SuspiciousImport {
            name: "winappdbg".to_string(),
            description: Some("winappdbg can be used to access process memory.".to_string()),
            rule: None,
        },
    );
    m.insert(
        "stegano",
        SuspiciousImport {
            name: "stegano".to_string(),
            description: Some(
                "stegano is a library that can be used to hide data in images.".to_string(),
            ),
            rule: None,
        },
    );
    m.insert(
        "judyb",
        SuspiciousImport {
            name: "judyb".to_string(),
            description: Some(
                "judyb is a library that can be used to hide data in images.".to_string(),
            ),
            rule: None,
        },
    );
    m.insert(
        "steganography",
        SuspiciousImport {
            name: "steganography".to_string(),
            description: Some(
                "steganography is a library that can be used to hide data in images.".to_string(),
            ),
            rule: None,
        },
    );
    m.insert(
        "pynput",
        SuspiciousImport {
            name: "pynput".to_string(),
            description: Some(
                "pynput can be used to monitor input devices and implement keyloggers.".to_string(),
            ),
            rule: None,
        },
    );
    m.insert(
        "keyboard",
        SuspiciousImport {
            name: "keyboard".to_string(),
            description: Some(
                "keyboard enables global key event hooks and keylogging.".to_string(),
            ),
            rule: None,
        },
    );
    m.insert(
        "mss",
        SuspiciousImport {
            name: "mss".to_string(),
            description: Some("mss package allows taking screenshots of your system".to_string()),
            rule: None,
        },
    );
    m.insert(
        "telnetlib",
        SuspiciousImport {
            name: "telnetlib".to_string(),
            description: Some(
                "telnetlib can be used to automate Telnet sessions for unauthorized access."
                    .to_string(),
            ),
            rule: None,
        },
    );
    m.insert(
        "ftplib",
        SuspiciousImport {
            name: "ftplib".to_string(),
            description: Some("ftplib can be used to exfiltrate data".to_string()),
            rule: None,
        },
    );
    m.insert(
        "pickle",
        SuspiciousImport {
            name: "pickle".to_string(),
            description: None,
            rule: Some(Rule::PickleImport),
        },
    );
    m.insert(
        "marshal",
        SuspiciousImport {
            name: "marshal".to_string(),
            description: None,
            rule: Some(Rule::MarshalImport),
        },
    );
    m.insert(
        "socket",
        SuspiciousImport {
            name: "socket".to_string(),
            description: None,
            rule: Some(Rule::SocketImport),
        },
    );
    m.insert(
        "pyperclip",
        SuspiciousImport {
            name: "pyperclip".to_string(),
            description: Some(
                "pyperclip can be used to copy and paste data from the clipboard.".to_string(),
            ),
            rule: None,
        },
    );
    m.insert(
        "paramiko",
        SuspiciousImport {
            name: "paramiko".to_string(),
            description: Some(
                "paramiko can be used to automate SSH sessions for unauthorized access."
                    .to_string(),
            ),
            rule: None,
        },
    );

    m
});

pub fn check_import(stmt: &Stmt, checker: &mut Checker) {
    match stmt {
        Stmt::Import(ast::StmtImport { names, .. }) => {
            for name in names {
                let import_name = name.name.as_str();
                let is_suspicious = IMPORTS.get(import_name);
                if let Some(suspicious_import) = is_suspicious {
                    let description = match &suspicious_import.description {
                        Some(description) => description.clone(),
                        None => suspicious_import
                            .rule
                            .as_ref()
                            .unwrap()
                            .clone()
                            .description()
                            .to_string(),
                    };
                    let rule = match &suspicious_import.rule {
                        Some(rule) => rule.clone(),
                        None => Rule::SuspiciousImport,
                    };
                    checker.audit_results.push(AuditItem {
                        label: import_name.to_string(),
                        rule,
                        description,
                        confidence: AuditConfidence::Low,
                        location: Some(name.range),
                    });
                }
            }
        }
        Stmt::ImportFrom(ast::StmtImportFrom { module, .. }) => {
            let Some(identifier) = module else { return };
            let import_name = identifier.as_str();
            let is_suspicious = IMPORTS.get(import_name);
            if let Some(suspicious_import) = is_suspicious {
                let description = match &suspicious_import.description {
                    Some(description) => description.clone(),
                    None => suspicious_import
                        .rule
                        .as_ref()
                        .unwrap()
                        .clone()
                        .description()
                        .to_string(),
                };
                let rule = match &suspicious_import.rule {
                    Some(rule) => rule.clone(),
                    None => Rule::SuspiciousImport,
                };
                checker.audit_results.push(AuditItem {
                    label: import_name.to_string(),
                    rule,
                    description,
                    confidence: AuditConfidence::Low,
                    location: Some(identifier.range),
                });
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("imports_01.py", Rule::SuspiciousImport, vec!["scapy"])]
    #[test_case("imports_01.py", Rule::CtypesImport, vec!["ctypes"])]
    #[test_case("imports_01.py", Rule::StructImport, vec!["struct"])]
    fn test_imports(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
