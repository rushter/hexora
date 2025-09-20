use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
use crate::indexer::name::QualifiedName;

use log::info;
use ruff_python_ast as ast;
use ruff_text_size::TextRange;

fn dll_injection_using_ctypes(
    qualified_name: &QualifiedName,
    range: &TextRange,
) -> Option<AuditItem> {
    let import_segments = qualified_name.segments();

    if import_segments.as_slice() == ["ctypes", "CDLL"] {
        return Some(AuditItem {
            label: qualified_name.as_str(),
            rule: Rule::DLLInjection,
            description: "Possible DLL injection. CDLL is used to load a DLL.".to_string(),
            confidence: AuditConfidence::High,
            location: Some(*range),
        });
    }

    if !(import_segments.len() > 3
        && import_segments.starts_with(&["ctypes", "windll", "kernel32"]))
    {
        return None;
    }
    let last_segment = *import_segments.last().unwrap();
    match last_segment {
        "OpenProcess" | "CreateRemoteThread" | "CreateProcessW" | "CreateProcessA"
        | "LoadLibraryA" | "VirtualAllocEx" | "WriteProcessMemory" | "RtlMoveMemory" => {
            return Some(AuditItem {
                label: qualified_name.as_str(),
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
    if let Some(qualified_name) = checker.indexer.resolve_qualified_name(&call.func) {
        match qualified_name.segments().first().copied() {
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
