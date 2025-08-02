use crate::audit::parse::Checker;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use ruff_python_ast as ast;
use ruff_python_ast::Expr;
use ruff_python_ast::name::QualifiedName;

pub fn is_shell_command(segments: &[&str]) -> bool {
    match segments {
        &[module, submodule] => match module {
            "os" => matches!(
                submodule,
                "execl"
                    | "execle"
                    | "execlp"
                    | "execlpe"
                    | "execv"
                    | "execve"
                    | "execvp"
                    | "execvpe"
                    | "spawnl"
                    | "spawnle"
                    | "spawnlp"
                    | "spawnlpe"
                    | "spawnv"
                    | "spawnve"
                    | "spawnvp"
                    | "spawnvpe"
                    | "startfile"
                    | "system"
                    | "popen"
                    | "popen2"
                    | "popen3"
                    | "popen4"
            ),
            "subprocess" => matches!(
                submodule,
                "Popen"
                    | "call"
                    | "check_call"
                    | "check_output"
                    | "run"
                    | "getoutput"
                    | "getstatusoutput"
            ),
            "popen2" => matches!(
                submodule,
                "popen2" | "popen3" | "popen4" | "Popen3" | "Popen4"
            ),
            "commands" => matches!(submodule, "getoutput" | "getstatusoutput"),
            _ => false,
        },
        _ => false,
    }
}

pub fn is_code_exec(segments: &[&str]) -> bool {
    match segments {
        &[module, submodule] => match module {
            "builtins" => matches!(submodule, "exec" | "eval"),
            "" => matches!(submodule, "exec" | "eval"),
            _ => false,
        },
        _ => false,
    }
}

pub fn is_chained_with_base64_call(checker: &Checker, call: &ast::ExprCall) -> bool {
    fn contains_b64decode(checker: &Checker, expr: &Expr) -> bool {
        match expr {
            Expr::Call(inner_call) => {
                if let Some(qn) = checker.semantic().resolve_qualified_name(&inner_call.func) {
                    let segments = qn.segments();
                    if segments.len() == 2 && segments[0] == "base64" && segments[1] == "b64decode"
                    {
                        return true;
                    }
                }
                for arg in &*inner_call.arguments.args {
                    if contains_b64decode(checker, arg) {
                        return true;
                    }
                }
                for kw in &*inner_call.arguments.keywords {
                    if contains_b64decode(checker, &kw.value) {
                        return true;
                    }
                }
                false
            }
            Expr::List(ast::ExprList { elts, .. }) => {
                for elt in elts {
                    if contains_b64decode(checker, elt) {
                        return true;
                    }
                }
                false
            }
            Expr::Tuple(ast::ExprTuple { elts, .. }) => {
                for elt in elts {
                    if contains_b64decode(checker, elt) {
                        return true;
                    }
                }
                false
            }
            _ => false,
        }
    }

    for arg in &*call.arguments.args {
        if contains_b64decode(checker, arg) {
            return true;
        }
    }
    for kw in &*call.arguments.keywords {
        if contains_b64decode(checker, &kw.value) {
            return true;
        }
    }
    false
}

pub fn check_shell_exec(
    qualified_name: &QualifiedName,
    call: &ast::ExprCall,
    checker: &mut Checker,
) {
    if is_chained_with_base64_call(checker, call) {
        checker.audit_results.push(AuditItem {
            label: qualified_name.to_string(),
            rule: Rule::ObfuscateShellExec,
            description: "Execution of unwanted obfuscated shell command".to_string(),
            confidence: AuditConfidence::High,
            location: Some(call.range),
        });
    } else {
        checker.audit_results.push(AuditItem {
            label: qualified_name.to_string(),
            rule: Rule::ShellExec,
            description: "Possible execution of unwanted shell command".to_string(),
            confidence: AuditConfidence::Low,
            location: Some(call.range),
        });
    }
}

pub fn shell_exec(checker: &mut Checker, call: &ast::ExprCall) {
    let qualified_name = checker.semantic().resolve_qualified_name(&call.func);
    if let Some(qualified_name) = qualified_name
        && is_shell_command(qualified_name.segments())
    {
        check_shell_exec(&qualified_name, call, checker);
    }
}

pub fn check_code_exec(
    qualified_name: &QualifiedName,
    call: &ast::ExprCall,
    checker: &mut Checker,
) {
    if is_chained_with_base64_call(checker, call) {
        checker.audit_results.push(AuditItem {
            label: qualified_name.to_string(),
            rule: Rule::ObfuscatedCodeExec,
            description: "Execution of obfuscated code".to_string(),
            confidence: AuditConfidence::High,
            location: Some(call.range),
        });
    } else {
        checker.audit_results.push(AuditItem {
            label: qualified_name.to_string(),
            rule: Rule::CodeExec,
            description: "Possible execution of unwanted code".to_string(),
            confidence: AuditConfidence::Low,
            location: Some(call.range),
        })
    }
}

pub fn code_exec(checker: &mut Checker, call: &ast::ExprCall) {
    let qualified_name = checker.semantic().resolve_qualified_name(&call.func);
    if let Some(qualified_name) = qualified_name
        && is_code_exec(qualified_name.segments())
    {
        check_code_exec(&qualified_name, call, checker);
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("exec_01.py", Rule::ShellExec, vec!["subprocess.call", "os.popen", "subprocess.check_output"])]
    #[test_case("exec_02.py", Rule::CodeExec, vec!["eval", "builtins.exec", "exec", "eval", "exec", "eval", "exec"])]
    #[test_case("exec_03.py", Rule::ObfuscatedCodeExec, vec!["builtins.exec"])]
    #[test_case("exec_03.py", Rule::ObfuscateShellExec, vec!["os.system", "subprocess.run"])]
    fn test_exec(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
