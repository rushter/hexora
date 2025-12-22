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
