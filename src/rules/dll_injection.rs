use crate::audit::parse::Checker;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use log::info;
use ruff_python_ast as ast;
use ruff_python_ast::name::QualifiedName;
use ruff_text_size::TextRange;

fn dll_injection_using_ctypes(
    qualified_name: &QualifiedName,
    range: &TextRange,
) -> Option<AuditItem> {
    let segments = qualified_name.segments();

    if segments.len() == 2 && qualified_name.segments().eq(&["ctypes", "CDLL"]) {
        return Some(AuditItem {
            label: qualified_name.to_string(),
            rule: Rule::DLLInjection,
            description: "Possible DLL injection. CDLL is used to load a DLL.".to_string(),
            confidence: AuditConfidence::High,
            location: Some(*range),
        });
    }

    if !(segments.len() > 3
        && qualified_name
            .segments()
            .starts_with(&["ctypes", "windll", "kernel32"]))
    {
        return None;
    }
    let last_segment = segments.last().copied().unwrap();
    match last_segment {
        "OpenProcess" | "CreateRemoteThread" | "CreateProcessW" | "CreateProcessA"
        | "LoadLibraryA" | "VirtualAllocEx" | "WriteProcessMemory" | "RtlMoveMemory" => {
            return Some(AuditItem {
                label: qualified_name.to_string(),
                rule: Rule::DLLInjection,
                description: format!(
                    "Possible DLL injection. Process manipulation using `{last_segment}`."
                )
                .to_string(),
                confidence: AuditConfidence::High,
                location: Some(*range),
            });
        }
        _ => {}
    }
    None
}

/// Checks for possible DLL injection in Python code.
pub fn dll_injection(checker: &mut Checker, call: &ast::ExprCall) {
    if let Some(qualified_name) = checker.semantic().resolve_qualified_name(&call.func) {
        let segments = qualified_name.segments();
        match segments.first().copied() {
            Some("ctypes") => {
                if let Some(result) = dll_injection_using_ctypes(&qualified_name, &call.range) {
                    checker.audit_results.push(result);
                }
            }
            Some("windll") => {
                info!("Unimplemented")
            }
            _ => {}
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
}
