use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;

use ruff_python_ast as ast;

/// Checks for possible DLL injection in Python code.
pub fn dll_injection(checker: &mut Checker, call: &ast::ExprCall) {
    if let Some(qualified_name) = checker.indexer.resolve_qualified_name(&call.func) {
        if qualified_name.is_dll_injection() {
            checker.audit_results.push(AuditItem {
                label: qualified_name.as_str(),
                rule: Rule::DLLInjection,
                description: if qualified_name.is_exact(&["ctypes", "CDLL"]) {
                    "Possible DLL injection/execution. CDLL is used to load a DLL.".to_string()
                } else {
                    format!(
                        "Possible DLL injection/execution. Process manipulation using `{}`.",
                        qualified_name.last().unwrap_or("unknown")
                    )
                },
                confidence: AuditConfidence::High,
                location: Some(call.range),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;

    #[test]
    fn dll_injection_01() {
        let expected = vec![
            "ctypes.windll.kernel32.OpenProcess",
            "ctypes.windll.kernel32.VirtualAllocEx",
            "ctypes.windll.kernel32.WriteProcessMemory",
            "ctypes.windll.kernel32.CreateRemoteThread",
            "ctypes.CDLL",
        ];
        assert_audit_results_by_name("dll_injection_01.py", Rule::DLLInjection, expected)
    }

    #[test]
    fn dll_injection_02() {
        let expected = vec!["ctypes.windll.shell32.ShellExecuteW"];
        assert_audit_results_by_name("dll_injection_02.py", Rule::DLLInjection, expected)
    }
}
