use crate::audit::helpers::string_from_expr;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;

use once_cell::sync::Lazy;
use ruff_python_ast as ast;

static SUSPICIOUS_IMPORTS: Lazy<&[&str]> =
    Lazy::new(|| &["os", "subprocess", "popen2", "commands"]);

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

#[inline]
pub fn is_code_exec(segments: &[&str]) -> bool {
    match *segments {
        [only] => matches!(only, "exec" | "eval"),
        [module, submodule] => match module {
            "builtins" => matches!(submodule, "exec" | "eval"),
            "" => matches!(submodule, "exec" | "eval"),
            _ => false,
        },
        _ => false,
    }
}

pub fn is_chained_with_base64_call(checker: &Checker, call: &ast::ExprCall) -> bool {
    fn contains_b64decode(checker: &Checker, expr: &ast::Expr) -> bool {
        match expr {
            ast::Expr::Call(inner_call) => {
                if let Some(qn) = checker.indexer.resolve_qualified_name(&inner_call.func)
                    && qn.is_exact(&["base64", "b64decode"])
                {
                    return true;
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
            ast::Expr::List(ast::ExprList { elts, .. }) => {
                elts.iter().any(|elt| contains_b64decode(checker, elt))
            }
            ast::Expr::Tuple(ast::ExprTuple { elts, .. }) => {
                elts.iter().any(|elt| contains_b64decode(checker, elt))
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

fn contains_curl_wget_expr(checker: &Checker, expr: &ast::Expr) -> bool {
    if let Some(s) = string_from_expr(expr, &checker.indexer) {
        s.contains("curl") || s.contains("wget")
    } else {
        match expr {
            ast::Expr::List(l) => l.elts.iter().any(|e| contains_curl_wget_expr(checker, e)),
            ast::Expr::Tuple(t) => t.elts.iter().any(|e| contains_curl_wget_expr(checker, e)),
            _ => false,
        }
    }
}

fn contains_curl_wget(checker: &Checker, call: &ast::ExprCall) -> bool {
    for arg in &call.arguments.args {
        if contains_curl_wget_expr(checker, arg) {
            return true;
        }
    }
    for kw in &call.arguments.keywords {
        if contains_curl_wget_expr(checker, &kw.value) {
            return true;
        }
    }
    false
}

fn push_shell_report(checker: &mut Checker, call: &ast::ExprCall, label: String) {
    let is_obf = is_chained_with_base64_call(checker, call);
    checker.audit_results.push(AuditItem {
        label: label.clone(),
        rule: if is_obf {
            Rule::ObfuscateShellExec
        } else {
            Rule::ShellExec
        },
        description: if is_obf {
            "Execution of unwanted obfuscated shell command".to_string()
        } else {
            "Possible execution of unwanted shell command".to_string()
        },
        confidence: if is_obf {
            AuditConfidence::High
        } else {
            AuditConfidence::Low
        },
        location: Some(call.range),
    });

    if contains_curl_wget(checker, call) {
        let is_obf = is_chained_with_base64_call(checker, call);
        checker.audit_results.push(AuditItem {
            label,
            rule: Rule::CurlWgetExec,
            description: if is_obf {
                "Execution of obfuscated curl/wget in shell command".to_string()
            } else {
                "Execution of curl/wget in shell command".to_string()
            },
            confidence: AuditConfidence::High,
            location: Some(call.range),
        });
    }
}

fn push_code_report(checker: &mut Checker, call: &ast::ExprCall, label: String) {
    let is_obf = is_chained_with_base64_call(checker, call);
    checker.audit_results.push(AuditItem {
        label,
        rule: if is_obf {
            Rule::ObfuscatedCodeExec
        } else {
            Rule::CodeExec
        },
        description: if is_obf {
            "Execution of obfuscated code".to_string()
        } else {
            "Possible execution of unwanted code".to_string()
        },
        confidence: if is_obf {
            AuditConfidence::High
        } else {
            AuditConfidence::Low
        },
        location: Some(call.range),
    });
}

fn sys_modules_contain_imports(
    checker: &Checker,
    expr: &ast::Expr,
    imports: &[&str],
) -> Option<String> {
    // sys.modules["<module>"]
    let ast::Expr::Subscript(ast::ExprSubscript { value, slice, .. }) = expr else {
        return None;
    };
    let qn = checker.indexer.resolve_qualified_name(value.as_ref())?;
    if qn.segments() != ["sys", "modules"] {
        return None;
    }
    let key = string_from_expr(slice, &checker.indexer)?;
    imports.iter().any(|m| m == &key).then_some(key)
}

fn importlib_contains_imports(
    checker: &Checker,
    expr: &ast::Expr,
    imports: &[&str],
) -> Option<String> {
    // importlib.import_module("<module>")
    let ast::Expr::Call(call) = expr else {
        return None;
    };
    let qn = checker.indexer.resolve_qualified_name(&call.func)?;
    if qn.segments() != ["importlib", "import_module"] {
        return None;
    }
    let first_arg = call.arguments.args.first()?;
    let key = string_from_expr(first_arg, &checker.indexer)?;
    imports.iter().any(|m| m == &key).then_some(key)
}

#[derive(Copy, Clone)]
enum ImportOrigin {
    SysModules,
    Importlib,
}

fn resolve_import_origin(
    checker: &Checker,
    expr: &ast::Expr,
    imports: &[&str],
) -> Option<(String, ImportOrigin)> {
    if let Some(module) = sys_modules_contain_imports(checker, expr, imports) {
        return Some((module, ImportOrigin::SysModules));
    }
    if let Some(module) = importlib_contains_imports(checker, expr, imports) {
        return Some((module, ImportOrigin::Importlib));
    }
    None
}

pub fn shell_exec(checker: &mut Checker, call: &ast::ExprCall) {
    let qualified_name = checker.indexer.resolve_qualified_name(&call.func);
    if let Some(qualified_name) = qualified_name
        && is_shell_command(&qualified_name.segments())
    {
        push_shell_report(checker, call, qualified_name.as_str());
        return;
    }

    // sys.modules["os"].<func>(...) or importlib.import_module("os").<func>(...)
    if let ast::Expr::Attribute(attr) = &*call.func
        && let Some((module, origin)) =
            resolve_import_origin(checker, &attr.value, *SUSPICIOUS_IMPORTS)
    {
        let name = attr.attr.as_str();
        if is_shell_command(&[module.as_str(), name]) {
            let label = match origin {
                ImportOrigin::SysModules => format!("sys.modules[\"{}\"].{}", module, name),
                ImportOrigin::Importlib => {
                    format!("importlib.import_module(\"{}\").{}", module, name)
                }
            };
            push_shell_report(checker, call, label);
            return;
        }
    }

    // getattr(importlib.import_module("os"), "<func>")(…) or getattr(sys.modules["os"], "<func>")(…)
    if let ast::Expr::Call(inner_call) = &*call.func
        && let Some(qn) = checker.indexer.resolve_qualified_name(&inner_call.func)
    {
        let is_getattr = qn.last().map(|s| s == "getattr").unwrap_or(false);
        if is_getattr {
            let args = &inner_call.arguments.args;
            if args.len() >= 2 {
                let target = &args[0];
                let attr_name = string_from_expr(&args[1], &checker.indexer);

                if let Some(name) = attr_name
                    && let Some((module, origin)) =
                        resolve_import_origin(checker, target, *SUSPICIOUS_IMPORTS)
                    && is_shell_command(&[module.as_str(), name.as_str()])
                {
                    let label = match origin {
                        ImportOrigin::SysModules => {
                            format!("getattr(sys.modules[\"{}\"], \"{}\")", module, name)
                        }
                        ImportOrigin::Importlib => format!(
                            "getattr(importlib.import_module(\"{}\"), \"{}\")",
                            module, name
                        ),
                    };
                    push_shell_report(checker, call, label);
                }
            }
        }
    }
}

pub fn code_exec(checker: &mut Checker, call: &ast::ExprCall) {
    if let Some(qn) = checker.indexer.resolve_qualified_name(&call.func)
        && is_code_exec(&qn.segments())
    {
        push_code_report(checker, call, qn.as_str());
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
    #[test_case(
        "exec_04.py",
        Rule::ShellExec,
        vec![
            "sys.modules[\"os\"].system",
            "sys.modules[\"subprocess\"].Popen",
            "importlib.import_module(\"subprocess\").check_output",
            "importlib.import_module(\"commands\").getstatusoutput",
        ]
    )]
    #[test_case(
        "exec_05.py",
        Rule::ShellExec,
        vec![
            "getattr(importlib.import_module(\"commands\"), \"getstatusoutput\")",
            "getattr(sys.modules[\"commands\"], \"getstatusoutput\")"
        ]
    )]
    #[test_case("exec_06.py", Rule::CurlWgetExec, vec!["subprocess.run", "os.system"])]
    fn test_exec(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
