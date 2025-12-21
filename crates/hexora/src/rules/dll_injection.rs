use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
use crate::indexer::name::QualifiedName;

use ruff_python_ast as ast;
use ruff_text_size::TextRange;

const SUSPICIOUS_FUNCTIONS: &[&str] = &[
    "OpenProcess",
    "CreateRemoteThread",
    "CreateProcessW",
    "CreateProcessA",
    "LoadLibraryA",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "RtlMoveMemory",
    "ShellExecuteW",
    "ShellExecuteA",
    "WinExec",
];

fn dll_injection_using_ctypes(
    qualified_name: &QualifiedName,
    range: &TextRange,
) -> Option<AuditItem> {
    let import_segments = qualified_name.segments();

    if import_segments.as_slice() == ["ctypes", "CDLL"] {
        return Some(AuditItem {
            label: qualified_name.as_str(),
            rule: Rule::DLLInjection,
            description: "Possible DLL injection/execution. CDLL is used to load a DLL."
                .to_string(),
            confidence: AuditConfidence::High,
            location: Some(*range),
        });
    }

    let is_windll_call = (import_segments.len() >= 4
        && import_segments.starts_with(&["ctypes", "windll"]))
        || (import_segments.len() >= 3 && import_segments.starts_with(&["windll"]));

    if is_windll_call {
        let last_segment = import_segments.last().unwrap();
        if SUSPICIOUS_FUNCTIONS.contains(last_segment) {
            return Some(AuditItem {
                label: qualified_name.as_str(),
                rule: Rule::DLLInjection,
                description: format!(
                    "Possible DLL injection/execution. Process manipulation using `{last_segment}`."
                ),
                confidence: AuditConfidence::High,
                location: Some(*range),
            });
        }
    }
    None
}

/// Checks for possible DLL injection in Python code.
pub fn dll_injection(checker: &mut Checker, call: &ast::ExprCall) {
    if let Some(qualified_name) = checker.indexer.resolve_qualified_name(&call.func) {
        if let Some(result) = dll_injection_using_ctypes(&qualified_name, &call.range) {
            checker.audit_results.push(result);
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
