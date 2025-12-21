use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
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
            confidence: AuditConfidence::High,
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
        for call_rule in CALLS.iter() {
            if qualified_name.segments().as_slice() == call_rule.name {
                checker.audit_results.push(AuditItem {
                    label: qualified_name.as_str(),
                    rule: Rule::SuspiciousCall,
                    description: call_rule.description.to_string(),
                    confidence: call_rule.confidence,
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
    fn test_call(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
