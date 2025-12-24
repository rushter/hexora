use crate::audit::helpers::string_from_expr;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
use crate::indexer::taint::TaintKind;

use ruff_python_ast as ast;
use ruff_python_ast::HasNodeIndex;

static DANGEROUS_COMMANDS: &[&str] = &[
    "curl",
    "wget",
    "powershell",
    "ifconfig",
    "netcat",
    "/bin/sh",
    "base64",
    "/dev/tcp",
    "start /B",
];

const MAX_DEPTH: u32 = 10;

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
            "builtins" | "__builtins__" => matches!(submodule, "exec" | "eval"),
            "" => matches!(submodule, "exec" | "eval"),
            _ => false,
        },
        _ => false,
    }
}

pub fn get_suspicious_taint(checker: &Checker, expr: &ast::Expr) -> Option<TaintKind> {
    let taints = checker.indexer.get_taint(expr);

    [
        TaintKind::Decoded,
        TaintKind::Deobfuscated,
        TaintKind::NetworkSourced,
        TaintKind::FileSourced,
        TaintKind::Fingerprinting,
        TaintKind::EnvVariables,
    ]
    .into_iter()
    .find(|kind| taints.contains(kind))
}

pub fn get_call_suspicious_taint(checker: &Checker, call: &ast::ExprCall) -> Option<TaintKind> {
    get_suspicious_taint(checker, &call.func)
        .or_else(|| {
            // Primarily check the first positional argument (the command/code)
            call.arguments
                .args
                .first()
                .and_then(|arg| get_suspicious_taint(checker, arg))
        })
        .or_else(|| {
            // Relevant keyword arguments that can carry malicious/obfuscated input
            call.arguments
                .keywords
                .iter()
                .find(|kw| {
                    kw.arg
                        .as_ref()
                        .map(|a| matches!(a.as_str(), "args" | "executable" | "source" | "object"))
                        .unwrap_or(false)
                })
                .and_then(|kw| get_suspicious_taint(checker, &kw.value))
        })
}

fn contains_dangerous_exec_expr(checker: &Checker, expr: &ast::Expr) -> bool {
    if let Some(s) = string_from_expr(expr, &checker.indexer) {
        DANGEROUS_COMMANDS.iter().any(|&c| s.contains(c))
    } else {
        match expr {
            ast::Expr::List(l) => l
                .elts
                .iter()
                .any(|e| contains_dangerous_exec_expr(checker, e)),
            ast::Expr::Tuple(t) => t
                .elts
                .iter()
                .any(|e| contains_dangerous_exec_expr(checker, e)),
            _ => false,
        }
    }
}

fn contains_dangerous_exec(checker: &Checker, call: &ast::ExprCall) -> bool {
    for arg in &call.arguments.args {
        if contains_dangerous_exec_expr(checker, arg) {
            return true;
        }
    }
    for kw in &call.arguments.keywords {
        if contains_dangerous_exec_expr(checker, &kw.value) {
            return true;
        }
    }
    false
}

fn get_taint_metadata(taint: TaintKind) -> (AuditConfidence, &'static str, &'static str) {
    match taint {
        TaintKind::Decoded | TaintKind::Deobfuscated => (
            AuditConfidence::High,
            "obfuscated shell command",
            "obfuscated code",
        ),
        TaintKind::NetworkSourced => (
            AuditConfidence::High,
            "shell command from network-sourced data",
            "code from network-sourced data",
        ),
        TaintKind::FileSourced => (
            AuditConfidence::High,
            "shell command from file-sourced data",
            "code from file-sourced data",
        ),
        TaintKind::Fingerprinting => (
            AuditConfidence::Medium,
            "shell command with system fingerprinting data",
            "code with system fingerprinting data",
        ),
        TaintKind::EnvVariables => (
            AuditConfidence::Medium,
            "shell command with environment variables",
            "code with environment variables",
        ),
        _ => (
            AuditConfidence::High,
            "unwanted shell command",
            "obfuscated code",
        ),
    }
}

fn contains_suspicious_expr(checker: &Checker, expr: &ast::Expr) -> bool {
    contains_suspicious_expr_limited(checker, expr, 0)
}

fn contains_suspicious_expr_limited(checker: &Checker, expr: &ast::Expr, depth: u32) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }

    if let Some(id) = expr.node_index().load().as_u32() {
        if let Some(exprs) = checker.indexer.model.expr_mapping.get(&id) {
            for &e in exprs {
                if contains_suspicious_expr_limited(checker, e, depth + 1) {
                    return true;
                }
            }
        }
    }

    match expr {
        ast::Expr::Call(call) => {
            if let Some(qn) = checker.indexer.get_qualified_name(call) {
                let segments = qn.segments();
                if segments.len() == 1 {
                    if matches!(
                        segments[0],
                        "__import__" | "compile" | "getattr" | "globals" | "locals" | "vars"
                    ) {
                        return true;
                    }
                } else if segments.len() == 2
                    && (segments[0] == "builtins" || segments[0] == "__builtins__")
                {
                    if matches!(
                        segments[1],
                        "__import__" | "compile" | "getattr" | "globals" | "locals" | "vars"
                    ) {
                        return true;
                    }
                }
            }

            if contains_suspicious_expr_limited(checker, &call.func, depth + 1) {
                return true;
            }

            for arg in &call.arguments.args {
                if contains_suspicious_expr_limited(checker, arg, depth + 1) {
                    return true;
                }
            }
            for kw in &call.arguments.keywords {
                if contains_suspicious_expr_limited(checker, &kw.value, depth + 1) {
                    return true;
                }
            }
        }
        ast::Expr::Attribute(attr) => {
            return contains_suspicious_expr_limited(checker, &attr.value, depth + 1);
        }
        ast::Expr::Subscript(sub) => {
            if contains_suspicious_expr_limited(checker, &sub.value, depth + 1) {
                return true;
            }
            return contains_suspicious_expr_limited(checker, &sub.slice, depth + 1);
        }
        ast::Expr::Lambda(lambda) => {
            return contains_suspicious_expr_limited(checker, &lambda.body, depth + 1);
        }
        _ => {}
    }
    false
}

fn is_highly_suspicious_exec(checker: &Checker, call: &ast::ExprCall) -> bool {
    if contains_suspicious_expr(checker, &call.func) {
        return true;
    }
    for arg in &call.arguments.args {
        if contains_suspicious_expr(checker, arg) {
            return true;
        }
    }
    for kw in &call.arguments.keywords {
        if contains_suspicious_expr(checker, &kw.value) {
            return true;
        }
    }
    false
}

pub fn is_shell_command_name(name: &str) -> bool {
    let segments: Vec<&str> = name.split('.').collect();
    is_shell_command(&segments)
}

pub fn is_code_exec_name(name: &str) -> bool {
    let segments: Vec<&str> = name.split('.').collect();
    is_code_exec(&segments)
}

fn record_execution_leak(checker: &mut Checker, call: &ast::ExprCall, label: &str) {
    for arg in &call.arguments.args {
        for taint in checker.indexer.get_taint(arg) {
            if let TaintKind::InternalParameter(param_idx) = taint {
                checker
                    .indexer
                    .add_parameter_leak(param_idx, label.to_string());
            }
        }
    }
    for kw in &call.arguments.keywords {
        for taint in checker.indexer.get_taint(&kw.value) {
            if let TaintKind::InternalParameter(param_idx) = taint {
                checker
                    .indexer
                    .add_parameter_leak(param_idx, label.to_string());
            }
        }
    }
}

fn is_dunder_or_builtins(checker: &Checker, call: &ast::ExprCall, label: &str) -> bool {
    if label.contains("builtins.")
        || label.contains("__builtins__.")
        || label.contains("globals")
        || label.contains("locals")
        || label.contains("vars")
    {
        return true;
    }

    contains_suspicious_expr(checker, &call.func)
}

fn push_report(checker: &mut Checker, call: &ast::ExprCall, label: String, is_shell: bool) {
    record_execution_leak(checker, call, &label);
    let suspicious_taint = get_call_suspicious_taint(checker, call);
    let is_highly_suspicious = is_highly_suspicious_exec(checker, call);
    let is_dunder_manipulation = is_dunder_or_builtins(checker, call, &label);

    if is_shell && contains_dangerous_exec(checker, call) {
        let is_obf = suspicious_taint.is_some() || is_highly_suspicious;
        checker.audit_results.push(AuditItem {
            label,
            rule: Rule::DangerousExec,
            description: if is_obf {
                "Execution of obfuscated dangerous command in shell command".to_string()
            } else {
                "Execution of potentially dangerous command in shell command".to_string()
            },
            confidence: AuditConfidence::High,
            location: Some(call.range),
        });
        return;
    }

    let (rule, description, mut confidence) = if let Some(taint) = suspicious_taint {
        let (confidence, shell_desc, code_desc) = get_taint_metadata(taint);
        let rule = if is_shell {
            Rule::ObfuscatedShellExec
        } else {
            Rule::ObfuscatedCodeExec
        };
        let desc = if is_shell { shell_desc } else { code_desc };
        (rule, format!("Execution of {}.", desc), confidence)
    } else if is_highly_suspicious {
        let rule = if is_shell {
            Rule::ObfuscatedShellExec
        } else {
            Rule::ObfuscatedCodeExec
        };
        let desc = if is_shell {
            "obfuscated shell command"
        } else {
            "obfuscated code"
        };
        (
            rule,
            format!("Execution of {}.", desc),
            AuditConfidence::High,
        )
    } else {
        let rule = if is_shell {
            Rule::ShellExec
        } else {
            Rule::CodeExec
        };
        let desc = if is_shell {
            "Possible execution of unwanted shell command."
        } else {
            "Possible execution of unwanted code."
        };
        (rule, desc.to_string(), AuditConfidence::Medium)
    };

    if is_highly_suspicious {
        confidence = AuditConfidence::High;
    }

    if is_dunder_manipulation {
        confidence = AuditConfidence::VeryHigh;
    }

    checker.audit_results.push(AuditItem {
        label,
        rule,
        description,
        confidence,
        location: Some(call.range),
    });
}

fn check_leaked_exec(checker: &mut Checker, call: &ast::ExprCall, is_shell: bool) {
    let Some(qn) = checker.indexer.resolve_qualified_name(&call.func) else {
        return;
    };
    let name = qn.as_str();
    let Some(binding) = checker.indexer.lookup_binding(&name) else {
        return;
    };

    let check_fn = if is_shell {
        is_shell_command_name
    } else {
        is_code_exec_name
    };

    let leaks = binding.parameter_leaks.clone();
    for (param_idx, sink_name) in leaks {
        if check_fn(&sink_name) {
            if let Some(arg) = call.arguments.args.get(param_idx) {
                let suspicious_taint = get_suspicious_taint(checker, arg);
                let (rule, description, confidence) = if let Some(taint) = suspicious_taint {
                    let (conf, shell_desc, code_desc) = get_taint_metadata(taint);
                    let desc = if is_shell { shell_desc } else { code_desc };
                    let rule = if is_shell {
                        Rule::ObfuscatedShellExec
                    } else {
                        Rule::ObfuscatedCodeExec
                    };
                    (
                        rule,
                        format!(
                            "Execution of {} (via local function {} leaking to {}).",
                            desc, name, sink_name
                        ),
                        conf,
                    )
                } else {
                    let rule = if is_shell {
                        Rule::ShellExec
                    } else {
                        Rule::CodeExec
                    };
                    let type_str = if is_shell { "shell command" } else { "code" };
                    (
                        rule,
                        format!(
                            "Possible execution of unwanted {} (via local function {} leaking to {}).",
                            type_str, name, sink_name
                        ),
                        AuditConfidence::Medium,
                    )
                };

                let mut confidence = confidence;
                if is_dunder_or_builtins(checker, call, &name) {
                    confidence = AuditConfidence::VeryHigh;
                }

                checker.audit_results.push(AuditItem {
                    label: name.clone(),
                    rule,
                    description,
                    confidence,
                    location: Some(call.range),
                });
            }
        }
    }
}

pub fn shell_exec(checker: &mut Checker, call: &ast::ExprCall) {
    if let Some(qn) = checker.indexer.get_qualified_name(call)
        && is_shell_command(&qn.segments())
    {
        push_report(checker, call, qn.as_str(), true);
        return;
    }

    check_leaked_exec(checker, call, true);
}

pub fn code_exec(checker: &mut Checker, call: &ast::ExprCall) {
    if let Some(qn) = checker.indexer.get_qualified_name(call)
        && is_code_exec(&qn.segments())
    {
        push_report(checker, call, qn.as_str(), false);
        return;
    }

    check_leaked_exec(checker, call, false);
}

#[cfg(test)]
mod tests {
    use crate::audit::result::{AuditConfidence, Rule};
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("exec_01.py", Rule::ShellExec, vec!["subprocess.call", "os.popen", "subprocess.check_output"])]
    #[test_case("exec_02.py", Rule::CodeExec, vec!["eval", "builtins.exec", "exec", "eval", "exec", "eval", "exec"])]
    #[test_case("exec_03.py", Rule::ObfuscatedCodeExec, vec!["builtins.exec", "builtins.exec"])]
    #[test_case("exec_03.py", Rule::ObfuscatedShellExec, vec!["os.system", "os.system", "subprocess.run"])]
    #[test_case(
        "exec_04.py",
        Rule::ObfuscatedShellExec,
        vec![
            "os.system",
            "subprocess.Popen",
            "subprocess.check_output",
            "commands.getstatusoutput",
        ]
    )]
    #[test_case(
        "exec_05.py",
        Rule::ObfuscatedShellExec,
        vec![
            "commands.getstatusoutput",
            "commands.getstatusoutput"
        ]
    )]
    #[test_case("exec_06.py", Rule::DangerousExec, vec!["subprocess.run", "os.system"])]
    #[test_case("exec_07.py", Rule::ObfuscatedCodeExec, vec!["exec", "builtins.exec", "exec"])]
    #[test_case("exec_08.py", Rule::ShellExec, vec!["subprocess.call"])]
    #[test_case("exec_09.py", Rule::ObfuscatedCodeExec, vec!["__builtins__.eval"])]
    #[test_case("exec_10.py", Rule::ObfuscatedCodeExec, vec!["eval"])]
    #[test_case("exec_11.py", Rule::ObfuscatedCodeExec, vec!["exec", "exec"])]
    #[test_case("exec_12.py", Rule::ObfuscatedCodeExec, vec!["exec"])]
    #[test_case("exec_14.py", Rule::ShellExec, vec!["subprocess.Popen"])]
    #[test_case("exec_15.py", Rule::ObfuscatedShellExec, vec!["os.system", "os.system"])]
    #[test_case("exec_16.py", Rule::DangerousExec, vec!["os.system", "subprocess.run"])]
    #[test_case("exec_17.py", Rule::ObfuscatedShellExec, vec!["os.system"])]
    #[test_case("exec_19.py", Rule::ObfuscatedCodeExec, vec!["exec"])]
    #[test_case("exec_20.py", Rule::ObfuscatedCodeExec, vec!["exec"])]
    fn test_exec(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }

    #[test]
    fn test_exec_confidence() {
        let result = test_path("exec_15.py").unwrap();
        for item in &result.items {
            if item.rule == Rule::ObfuscatedShellExec {
                assert_eq!(item.confidence, AuditConfidence::Medium);
            }
        }
    }

    #[test]
    fn test_suspicious_exec_confidence() {
        let result = test_path("exec_18.py").unwrap();
        let suspicious_items: Vec<_> = result
            .items
            .iter()
            .filter(|item| {
                matches!(
                    item.rule,
                    Rule::ShellExec
                        | Rule::CodeExec
                        | Rule::ObfuscatedShellExec
                        | Rule::ObfuscatedCodeExec
                )
            })
            .collect();

        assert!(!suspicious_items.is_empty());
        for item in suspicious_items {
            assert_eq!(
                item.confidence,
                AuditConfidence::High,
                "Item {} should have High confidence",
                item.label
            );
        }
    }

    #[test]
    fn test_exec_13() {
        match test_path("exec_13.py") {
            Ok(result) => {
                let actual = result
                    .items
                    .iter()
                    .map(|r| (r.label.clone(), r.rule))
                    .collect::<Vec<(String, Rule)>>();
                let expected = vec![
                    ("subprocess.run".to_string(), Rule::ShellExec),
                    ("subprocess.run".to_string(), Rule::DangerousExec),
                ];
                assert_eq!(actual, expected);
            }
            Err(e) => {
                panic!("test failed: {:?}", e);
            }
        }
    }
}
