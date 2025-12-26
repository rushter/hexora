use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
use crate::indexer::model::Transformation;
use crate::indexer::resolver::string_from_expr;
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
static DANGEROUS_COMMAND_PREFIXES: &[&str] = &["start "];
const MAX_DEPTH: u32 = 10;

#[inline]
pub fn is_shell_command(segments: &[&str]) -> bool {
    match segments {
        ["os", submodule] => matches!(
            *submodule,
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
                | "posix_spawn"
                | "posix_spawnp"
        ),
        ["subprocess", submodule] => matches!(
            *submodule,
            "Popen"
                | "call"
                | "check_call"
                | "check_output"
                | "run"
                | "getoutput"
                | "getstatusoutput"
        ),
        ["popen2", submodule] => matches!(
            *submodule,
            "popen2" | "popen3" | "popen4" | "Popen3" | "Popen4"
        ),
        ["commands", submodule] => matches!(*submodule, "getoutput" | "getstatusoutput"),
        _ => false,
    }
}

#[inline]
pub fn is_code_exec(segments: &[&str]) -> bool {
    match segments {
        [only] => matches!(*only, "exec" | "eval"),
        ["builtins" | "__builtins__" | "", submodule] => matches!(*submodule, "exec" | "eval"),
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
            call.arguments
                .args
                .first()
                .and_then(|arg| get_suspicious_taint(checker, arg))
        })
        .or_else(|| {
            call.arguments
                .keywords
                .iter()
                .find(|kw| {
                    kw.arg.as_ref().is_some_and(|a| {
                        matches!(a.as_str(), "args" | "executable" | "source" | "object")
                    })
                })
                .and_then(|kw| get_suspicious_taint(checker, &kw.value))
        })
}

fn contains_dangerous_exec_expr(checker: &Checker, expr: &ast::Expr) -> bool {
    if let Some(s) = string_from_expr(expr, &checker.indexer) {
        DANGEROUS_COMMANDS.iter().any(|&c| s.contains(c))
            || DANGEROUS_COMMAND_PREFIXES.iter().any(|&c| s.starts_with(c))
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
    call.arguments
        .args
        .iter()
        .any(|arg| contains_dangerous_exec_expr(checker, arg))
        || call
            .arguments
            .keywords
            .iter()
            .any(|kw| contains_dangerous_exec_expr(checker, &kw.value))
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
        if let Some(Transformation::Base64 | Transformation::Hex | Transformation::Other) =
            checker.indexer.model.decoded_nodes.borrow().get(&id)
        {
            return true;
        }
        if checker
            .indexer
            .model
            .expr_mapping
            .get(&id)
            .is_some_and(|exprs| {
                exprs
                    .iter()
                    .any(|&e| contains_suspicious_expr_limited(checker, e, depth + 1))
            })
        {
            return true;
        }
    }

    match expr {
        ast::Expr::Call(call) => {
            if let Some(qn) = checker.indexer.get_qualified_name(call) {
                let s = qn.segments();
                let sus = [
                    "__import__",
                    "compile",
                    "getattr",
                    "globals",
                    "locals",
                    "vars",
                ];
                if matches!(s[..], [name] if sus.contains(&name))
                    || matches!(s[..], ["builtins" | "__builtins__", name] if sus.contains(&name))
                {
                    return true;
                }
            }
            contains_suspicious_expr_limited(checker, &call.func, depth + 1)
                || call
                    .arguments
                    .args
                    .iter()
                    .any(|arg| contains_suspicious_expr_limited(checker, arg, depth + 1))
                || call
                    .arguments
                    .keywords
                    .iter()
                    .any(|kw| contains_suspicious_expr_limited(checker, &kw.value, depth + 1))
        }
        ast::Expr::Attribute(attr) => {
            contains_suspicious_expr_limited(checker, &attr.value, depth + 1)
        }
        ast::Expr::Subscript(sub) => {
            contains_suspicious_expr_limited(checker, &sub.value, depth + 1)
                || contains_suspicious_expr_limited(checker, &sub.slice, depth + 1)
        }
        ast::Expr::Lambda(lambda) => {
            contains_suspicious_expr_limited(checker, &lambda.body, depth + 1)
        }
        _ => false,
    }
}

fn is_highly_suspicious_exec(checker: &Checker, call: &ast::ExprCall) -> bool {
    contains_suspicious_expr(checker, &call.func)
        || call
            .arguments
            .args
            .iter()
            .any(|arg| contains_suspicious_expr(checker, arg))
        || call
            .arguments
            .keywords
            .iter()
            .any(|kw| contains_suspicious_expr(checker, &kw.value))
}

pub fn is_shell_command_name(name: &str) -> bool {
    is_shell_command(&name.split('.').collect::<Vec<_>>())
}

pub fn is_code_exec_name(name: &str) -> bool {
    is_code_exec(&name.split('.').collect::<Vec<_>>())
}

fn record_execution_leak(checker: &mut Checker, call: &ast::ExprCall, label: &str) {
    for expr in call
        .arguments
        .args
        .iter()
        .chain(call.arguments.keywords.iter().map(|k| &k.value))
    {
        for taint in checker.indexer.get_taint(expr) {
            if let TaintKind::InternalParameter(idx) = taint {
                checker.indexer.add_parameter_leak(idx, label.to_string());
            }
        }
    }
}

fn is_dunder_or_builtins(checker: &Checker, call: &ast::ExprCall, label: &str) -> bool {
    label.contains("builtins.")
        || label.contains("__builtins__.")
        || label.contains("globals")
        || label.contains("locals")
        || label.contains("vars")
        || label == "map"
        || contains_suspicious_expr(checker, &call.func)
}

fn get_audit_info(
    is_shell: bool,
    taint: Option<TaintKind>,
    is_highly_suspicious: bool,
) -> (Rule, String, AuditConfidence) {
    let is_obf = taint.is_some() || is_highly_suspicious;
    let rule = match (is_shell, is_obf) {
        (true, true) => Rule::ObfuscatedShellExec,
        (false, true) => Rule::ObfuscatedCodeExec,
        (true, false) => Rule::ShellExec,
        (false, false) => Rule::CodeExec,
    };

    let type_str = if is_shell { "shell command" } else { "code" };
    let (description, confidence) = match (taint, is_highly_suspicious) {
        (Some(t), _) => {
            let (conf, s, c) = get_taint_metadata(t);
            (
                format!("Execution of {}.", if is_shell { s } else { c }),
                conf,
            )
        }
        (None, true) => (
            format!("Execution of obfuscated {}.", type_str),
            AuditConfidence::High,
        ),
        (None, false) => (
            format!("Possible execution of unwanted {}.", type_str),
            AuditConfidence::Medium,
        ),
    };

    (rule, description, confidence)
}

fn push_report(
    checker: &mut Checker,
    call: &ast::ExprCall,
    label: String,
    is_shell: bool,
    extra_confidence: Option<AuditConfidence>,
) {
    record_execution_leak(checker, call, &label);

    if is_shell && contains_dangerous_exec(checker, call) {
        let is_obf = get_call_suspicious_taint(checker, call).is_some()
            || is_highly_suspicious_exec(checker, call);
        checker.audit_results.push(AuditItem {
            label,
            rule: Rule::DangerousExec,
            description: (if is_obf {
                "Execution of obfuscated dangerous command in shell command"
            } else {
                "Execution of potentially dangerous command in shell command"
            })
            .to_string(),
            confidence: AuditConfidence::High,
            location: Some(call.range),
        });
        return;
    }

    let (rule, description, mut confidence) = get_audit_info(
        is_shell,
        get_call_suspicious_taint(checker, call),
        is_highly_suspicious_exec(checker, call),
    );
    if is_dunder_or_builtins(checker, call, &label) {
        confidence = AuditConfidence::VeryHigh;
    }
    if let Some(extra) = extra_confidence {
        confidence = confidence.max(extra);
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

    for (param_idx, sink_name) in binding.parameter_leaks.clone() {
        if check_fn(&sink_name) {
            if let Some(arg) = call.arguments.args.get(param_idx) {
                let (rule, mut description, mut confidence) = get_audit_info(
                    is_shell,
                    get_suspicious_taint(checker, arg),
                    is_highly_suspicious_exec(checker, call),
                );
                description = format!(
                    "{} (via local function {} leaking to {}).",
                    &description[..description.len() - 1],
                    name,
                    sink_name
                );
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
    if let Some(qn) = checker.indexer.get_qualified_name(call) {
        if is_shell_command(&qn.segments()) {
            push_report(checker, call, qn.as_str(), true, None);
            return;
        }
        if qn.as_str() == "map" && !call.arguments.args.is_empty() {
            if let Some(func_qn) = checker
                .indexer
                .resolve_qualified_name(&call.arguments.args[0])
            {
                if is_shell_command(&func_qn.segments()) {
                    push_report(
                        checker,
                        call,
                        func_qn.as_str(),
                        true,
                        Some(AuditConfidence::VeryHigh),
                    );
                    return;
                }
            }
        }
    }
    check_leaked_exec(checker, call, true);
}

pub fn code_exec(checker: &mut Checker, call: &ast::ExprCall) {
    if let Some(qn) = checker.indexer.get_qualified_name(call) {
        if is_code_exec(&qn.segments()) {
            push_report(checker, call, qn.as_str(), false, None);
            return;
        }
        if qn.as_str() == "map" && !call.arguments.args.is_empty() {
            if let Some(func_qn) = checker
                .indexer
                .resolve_qualified_name(&call.arguments.args[0])
            {
                if is_code_exec(&func_qn.segments()) {
                    push_report(
                        checker,
                        call,
                        func_qn.as_str(),
                        false,
                        Some(AuditConfidence::VeryHigh),
                    );
                    return;
                }
            }
        }
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
    #[test_case(
        "exec_21.py",
        Rule::ObfuscatedShellExec,
        vec!["os.system", "os.system", "os.system"]
    )]
    #[test_case("exec_21.py", Rule::DangerousExec, vec!["os.posix_spawn"])]
    #[test_case("exec_21.py", Rule::ShellExec, vec!["os.system"])]
    #[test_case("exec_22.py", Rule::DangerousExec, vec!["os.system", "os.system"])]
    #[test_case("exec_23.py", Rule::ShellExec, vec!["subprocess.Popen"])]
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
