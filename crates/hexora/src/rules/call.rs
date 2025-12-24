use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
use crate::indexer::taint::TaintKind;
use crate::rules::exec::is_shell_command;
use once_cell::sync::Lazy;

use ruff_python_ast as ast;

struct SuspiciousCallRule {
    name: &'static [&'static str],
    description: &'static str,
    confidence: AuditConfidence,
}

static CALLS: Lazy<Vec<SuspiciousCallRule>> = Lazy::new(|| {
    vec![
        SuspiciousCallRule {
            name: &["os", "dup2"],
            description: "Duplicate a file descriptor. Often used in reverse shells to redirect stdin/stdout/stderr to a socket.",
            confidence: AuditConfidence::Medium,
        },
        SuspiciousCallRule {
            name: &["pty", "spawn"],
            description: "Spawn a process with a pseudo-terminal. Often used in reverse shells to provide an interactive shell.",
            confidence: AuditConfidence::High,
        },
    ]
});

pub fn suspicious_call(checker: &mut Checker, call: &ast::ExprCall) {
    if let Some(qualified_name) = checker.indexer.resolve_qualified_name(&call.func) {
        let name = qualified_name.as_str();

        // Check if it's a shell command to potentially upgrade os.dup2 confidence
        let is_shell = is_shell_command(&qualified_name.segments());

        if is_shell {
            for item in checker.audit_results.iter_mut() {
                if item.label == "os.dup2" {
                    item.confidence = AuditConfidence::High;
                }
            }
            return;
        }

        for call_rule in CALLS.iter() {
            if qualified_name.segments().as_slice() == call_rule.name {
                let mut confidence = call_rule.confidence;

                if name == "os.dup2" {
                    if let Some(first_arg) = call.arguments.args.first() {
                        if checker
                            .indexer
                            .get_taint(first_arg)
                            .contains(&TaintKind::NetworkSourced)
                        {
                            confidence = AuditConfidence::High;
                        }
                    }

                    if confidence != AuditConfidence::High
                        && checker.audit_results.iter().any(|item| {
                            item.label == "pty.spawn"
                                || item.rule == Rule::ShellExec
                                || item.rule == Rule::DangerousExec
                        })
                    {
                        confidence = AuditConfidence::High;
                    }
                } else if name == "pty.spawn" {
                    for item in checker.audit_results.iter_mut() {
                        if item.label == "os.dup2" {
                            item.confidence = AuditConfidence::High;
                        }
                    }
                }

                checker.audit_results.push(AuditItem {
                    label: name,
                    rule: Rule::SuspiciousCall,
                    description: call_rule.description.to_string(),
                    confidence,
                    location: Some(call.range),
                });
                return;
            }
        }
    }
}

fn get_exfil_confidence(taint: &TaintKind) -> Option<AuditConfidence> {
    match taint {
        TaintKind::Fingerprinting | TaintKind::Decoded | TaintKind::Deobfuscated => {
            Some(AuditConfidence::High)
        }
        TaintKind::EnvVariables | TaintKind::NetworkSourced | TaintKind::FileSourced => {
            Some(AuditConfidence::Medium)
        }
        _ => None,
    }
}

pub fn data_exfiltration(checker: &mut Checker, call: &ast::ExprCall) {
    let Some(qualified_name) = checker.indexer.resolve_qualified_name(&call.func) else {
        return;
    };
    let segments = qualified_name.segments();

    let is_exfil = match segments.as_slice() {
        s if s.starts_with(&["urllib"])
            && (s.ends_with(&["urlopen"]) || s.ends_with(&["Request"])) =>
        {
            true
        }
        [
            "requests",
            "get" | "post" | "request" | "put" | "patch" | "delete",
        ]
        | [
            "http",
            "client",
            "HTTPConnection" | "HTTPSConnection",
            "request",
        ]
        | ["socket", "socket", "send" | "sendall" | "sendto"] => true,
        _ => false,
    };

    if !is_exfil {
        return;
    }

    let mut found_taint = None;
    let mut confidence = AuditConfidence::High;

    for arg in &call.arguments.args {
        let taints = checker.indexer.get_taint(arg);
        if let Some((taint, conf)) = taints
            .iter()
            .find_map(|t| get_exfil_confidence(t).map(|c| (t, c)))
        {
            found_taint = Some(*taint);
            confidence = conf;
            break;
        }
    }

    if found_taint.is_none() {
        for kw in &call.arguments.keywords {
            let taints = checker.indexer.get_taint(&kw.value);
            if let Some((taint, conf)) = taints
                .iter()
                .find_map(|t| get_exfil_confidence(t).map(|c| (t, c)))
            {
                found_taint = Some(*taint);
                confidence = conf;
                break;
            }
        }
    }

    if let Some(taint) = found_taint {
        checker.audit_results.push(AuditItem {
            label: qualified_name.as_str(),
            rule: Rule::DataExfiltration,
            description: format!(
                "Potential data exfiltration with {:?} data via {}.",
                taint,
                qualified_name.as_str()
            ),
            confidence,
            location: Some(call.range),
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("call_01.py", Rule::SuspiciousCall, vec!["os.dup2", "os.dup2", "os.dup2", "pty.spawn"])]
    #[test_case("call_04.py", Rule::SuspiciousCall, vec!["os.dup2", "os.dup2", "os.dup2"])]
    fn test_call(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }

    #[test_case("exfil_01.py", Rule::DataExfiltration, vec!["urllib.request.request.urlopen"])]
    #[test_case("exfil_02.py", Rule::DataExfiltration, vec!["requests.get"])]
    fn test_exfiltration(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }

    #[test]
    fn test_call_confidence() {
        use crate::audit::result::AuditConfidence;

        // both present -> High
        let result = test_path("call_01.py").unwrap();
        let dup2_results: Vec<_> = result
            .items
            .iter()
            .filter(|i| i.label == "os.dup2")
            .collect();
        assert!(!dup2_results.is_empty());
        for item in dup2_results {
            assert_eq!(item.confidence, AuditConfidence::High);
        }

        // only os.dup2 -> Medium
        let result = test_path("call_02.py").unwrap();
        let dup2_results: Vec<_> = result
            .items
            .iter()
            .filter(|i| i.label == "os.dup2")
            .collect();
        assert!(!dup2_results.is_empty());
        for item in dup2_results {
            assert_eq!(item.confidence, AuditConfidence::Medium);
        }

        //  pty.spawn before os.dup2 -> High
        let result = test_path("call_03.py").unwrap();
        let dup2_results: Vec<_> = result
            .items
            .iter()
            .filter(|i| i.label == "os.dup2")
            .collect();
        assert!(!dup2_results.is_empty());
        for item in dup2_results {
            assert_eq!(item.confidence, AuditConfidence::High);
        }

        let result = test_path("call_04.py").unwrap();
        let dup2_results: Vec<_> = result
            .items
            .iter()
            .filter(|i| i.label == "os.dup2")
            .collect();
        assert!(!dup2_results.is_empty());
        for item in dup2_results {
            assert_eq!(item.confidence, AuditConfidence::High);
        }
    }
}
