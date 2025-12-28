use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;

use ruff_python_ast as ast;

pub fn fingerprinting(checker: &mut Checker, call: &ast::ExprCall) {
    let qualified_name = checker.indexer.resolve_qualified_name(&call.func);

    if let Some(qualified_name) = qualified_name {
        let name = qualified_name.to_string();

        let mut matched = qualified_name.is_os_fingerprint();

        let arg_qn = call
            .arguments
            .args
            .first()
            .and_then(|arg| checker.indexer.resolve_qualified_name(arg));

        if !matched && (name == "dict" || name == "str") {
            if let Some(ref arg_qn) = arg_qn {
                if arg_qn.is_exact(&["os", "environ"]) {
                    matched = true;
                }
            }
        }

        if matched {
            let (label, confidence) = if qualified_name.as_str() == "os.environ.copy" {
                (name, AuditConfidence::Medium)
            } else if name == "dict" || name == "str" {
                let label = arg_qn.map(|qn| qn.to_string()).unwrap_or(name);
                (label, AuditConfidence::VeryHigh)
            } else {
                (name, AuditConfidence::Medium)
            };

            checker.audit_results.push(AuditItem {
                label,
                rule: Rule::OSFingerprint,
                description: "Suspicious OS fingerprinting".to_string(),
                confidence,
                location: Some(call.range),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("fingerprinting_01.py", Rule::OSFingerprint, vec![
        "os.uname",
        "getpass.getuser",
        "os.getlogin",
        "platform.system",
        "socket.gethostname",
        "platform.platform",
        "platform.version",
        "platform.release",
        "platform.node",
        "platform.processor",
        "platform.machine",
        "platform.architecture",
        "platform.uname"
    ])]
    #[test_case("fingerprinting_02.py", Rule::OSFingerprint, vec![
        "os.environ.copy",
        "os.environ.copy",
        "os.environ",
        "os.environ",
        "os.environ",
        "os.environ"
    ])]
    #[test_case("fingerprinting_03.py", Rule::OSFingerprint, vec![
        "os.getlogin",
        "socket.gethostname"
    ])]
    fn test_fingerprinting(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
