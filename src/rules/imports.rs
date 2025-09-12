use crate::indexer::checker::Checker;
use once_cell::sync::Lazy;
use ruff_python_ast::Stmt;
use serde::Serialize;
use std::collections::HashMap;

use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use ruff_python_ast::identifier::Identifier;
use ruff_python_ast::{self as ast};

#[derive(Debug, Serialize)]
pub struct SuspiciousImport {
    pub name: &'static str,
    pub description: Option<&'static str>,
    pub rule: Option<Rule>,
}

static IMPORTS: Lazy<HashMap<&str, SuspiciousImport>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(
        "struct",
        SuspiciousImport {
            name: "struct",
            description: None,
            rule: Some(Rule::StructImport),
        },
    );
    m.insert(
        "ctypes",
        SuspiciousImport {
            name: "ctypes",
            description: None,
            rule: Some(Rule::CtypesImport),
        },
    );

    m.insert(
        "scapy",
        SuspiciousImport {
            name: "scapy",
            description: Some("scapy can be used to craft malicious packets."),
            rule: None,
        },
    );
    m.insert(
        "impacket",
        SuspiciousImport {
            name: "impacket",
            description: Some("impacket can be used to craft malicious payload"),
            rule: None,
        },
    );
    m.insert(
        "winappdbg",
        SuspiciousImport {
            name: "winappdbg",
            description: Some("winappdbg can be used to access process memory."),
            rule: None,
        },
    );
    m.insert(
        "stegano",
        SuspiciousImport {
            name: "stegano",
            description: Some("stegano is a library that can be used to hide data in images."),
            rule: None,
        },
    );
    m.insert(
        "judyb",
        SuspiciousImport {
            name: "judyb",
            description: Some("judyb is a library that can be used to hide data in images."),
            rule: None,
        },
    );
    m.insert(
        "steganography",
        SuspiciousImport {
            name: "steganography",
            description: Some(
                "steganography is a library that can be used to hide data in images.",
            ),
            rule: None,
        },
    );
    m.insert(
        "pynput",
        SuspiciousImport {
            name: "pynput",
            description: Some(
                "pynput can be used to monitor input devices and implement keyloggers.",
            ),
            rule: None,
        },
    );
    m.insert(
        "keyboard",
        SuspiciousImport {
            name: "keyboard",
            description: Some("keyboard enables global key event hooks and keylogging."),
            rule: None,
        },
    );
    m.insert(
        "mss",
        SuspiciousImport {
            name: "mss",
            description: Some("mss package allows taking screenshots of your system"),
            rule: None,
        },
    );
    m.insert(
        "telnetlib",
        SuspiciousImport {
            name: "telnetlib",
            description: Some(
                "telnetlib can be used to automate Telnet sessions for unauthorized access.",
            ),
            rule: None,
        },
    );
    m.insert(
        "ftplib",
        SuspiciousImport {
            name: "ftplib",
            description: Some("ftplib can be used to exfiltrate data"),
            rule: None,
        },
    );
    m.insert(
        "pickle",
        SuspiciousImport {
            name: "pickle",
            description: None,
            rule: Some(Rule::PickleImport),
        },
    );
    m.insert(
        "marshal",
        SuspiciousImport {
            name: "marshal",
            description: None,
            rule: Some(Rule::MarshalImport),
        },
    );
    m.insert(
        "socket",
        SuspiciousImport {
            name: "socket",
            description: None,
            rule: Some(Rule::SocketImport),
        },
    );
    m.insert(
        "pyperclip",
        SuspiciousImport {
            name: "pyperclip",
            description: Some("pyperclip can be used to copy and paste data from the clipboard."),
            rule: None,
        },
    );
    m.insert(
        "paramiko",
        SuspiciousImport {
            name: "paramiko",
            description: Some(
                "paramiko can be used to automate SSH sessions for unauthorized access.",
            ),
            rule: None,
        },
    );
    m.insert(
        "win32com",
        SuspiciousImport {
            name: "win32com",
            description: Some("win32com can be used to exploit Windows systems."),
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
                        Some(description) => description.to_string(),
                        None => suspicious_import
                            .rule
                            .as_ref()
                            .expect("Rule should be set for suspicious imports")
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
        Stmt::ImportFrom(ast::StmtImportFrom { module, names, .. }) => {
            let Some(identifier) = module else { return };
            let import_name = identifier.as_str();
            let is_suspicious = IMPORTS.get(import_name);
            if let Some(suspicious_import) = is_suspicious {
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
