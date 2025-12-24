use crate::audit::helpers::string_from_expr;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
use crate::indexer::taint::TaintKind;

use once_cell::sync::Lazy;
use ruff_python_ast as ast;
use ruff_python_ast::HasNodeIndex;

static SUSPICIOUS_IMPORTS: Lazy<&[&str]> =
    Lazy::new(|| &["os", "subprocess", "popen2", "commands"]);

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
                    if matches!(segments[0], "__import__" | "compile") {
                        return true;
                    }
                } else if segments.len() == 2
                    && (segments[0] == "builtins" || segments[0] == "__builtins__")
                {
                    if matches!(segments[1], "__import__" | "compile") {
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
        ast::Expr::Lambda(lambda) => {
            return contains_suspicious_expr_limited(checker, &lambda.body, depth + 1);
        }
        _ => {}
    }
    false
}

fn is_highly_suspicious_exec(checker: &Checker, call: &ast::ExprCall) -> bool {
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

fn push_shell_report(checker: &mut Checker, call: &ast::ExprCall, label: String) {
    let suspicious_taint = get_call_suspicious_taint(checker, call);
    let is_highly_suspicious = is_highly_suspicious_exec(checker, call);

    if contains_dangerous_exec(checker, call) {
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
        let (confidence, desc, _) = get_taint_metadata(taint);
        (
            Rule::ObfuscatedShellExec,
            format!("Execution of {}.", desc),
            confidence,
        )
    } else if is_highly_suspicious {
        (
            Rule::ObfuscatedShellExec,
            "Execution of obfuscated shell command.".to_string(),
            AuditConfidence::High,
        )
    } else {
        (
            Rule::ShellExec,
            "Possible execution of unwanted shell command.".to_string(),
            AuditConfidence::Medium,
        )
    };

    if is_highly_suspicious {
        confidence = AuditConfidence::High;
    }

    checker.audit_results.push(AuditItem {
        label,
        rule,
        description,
        confidence,
        location: Some(call.range),
    });
}

fn push_code_report(checker: &mut Checker, call: &ast::ExprCall, label: String) {
    let suspicious_taint = get_call_suspicious_taint(checker, call);
    let is_highly_suspicious = is_highly_suspicious_exec(checker, call);

    let (rule, description, mut confidence) = if let Some(taint) = suspicious_taint {
        let (confidence, _, desc) = get_taint_metadata(taint);
        (
            Rule::ObfuscatedCodeExec,
            format!("Execution of {}.", desc),
            confidence,
        )
    } else if is_highly_suspicious {
        (
            Rule::ObfuscatedCodeExec,
            "Execution of obfuscated code.".to_string(),
            AuditConfidence::High,
        )
    } else {
        (
            Rule::CodeExec,
            "Possible execution of unwanted code.".to_string(),
            AuditConfidence::Medium,
        )
    };

    if is_highly_suspicious {
        confidence = AuditConfidence::High;
    }

    checker.audit_results.push(AuditItem {
        label,
        rule,
        description,
        confidence,
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

fn resolve_import_origin(checker: &Checker, expr: &ast::Expr, imports: &[&str]) -> Option<String> {
    sys_modules_contain_imports(checker, expr, imports)
}

pub fn shell_exec(checker: &mut Checker, call: &ast::ExprCall) {
    let qualified_name = checker.indexer.get_qualified_name(call);

    if let Some(qualified_name) = qualified_name
        && is_shell_command(&qualified_name.segments())
    {
        push_shell_report(checker, call, qualified_name.as_str());
        return;
    }

    // sys.modules["os"].<func>(...)
    if let ast::Expr::Attribute(attr) = &*call.func
        && let Some(module) = resolve_import_origin(checker, &attr.value, *SUSPICIOUS_IMPORTS)
    {
        let name = attr.attr.as_str();
        if is_shell_command(&[module.as_str(), name]) {
            let label = format!("sys.modules[\"{}\"].{}", module, name);
            push_shell_report(checker, call, label);
            return;
        }
    }

    // getattr(sys.modules["os"], "<func>")(…)
    if let ast::Expr::Call(inner_call) = &*call.func {
        let qn = checker.indexer.get_qualified_name(inner_call);

        if let Some(qn) = qn {
            let is_getattr = qn.last().map(|s| s == "getattr").unwrap_or(false);
            if is_getattr {
                let args = &inner_call.arguments.args;
                if args.len() >= 2 {
                    let target = &args[0];
                    let attr_name = string_from_expr(&args[1], &checker.indexer);

                    if let Some(name) = attr_name
                        && let Some(module) =
                            resolve_import_origin(checker, target, *SUSPICIOUS_IMPORTS)
                        && is_shell_command(&[module.as_str(), name.as_str()])
                    {
                        let label = format!("getattr(sys.modules[\"{}\"], \"{}\")", module, name);
                        push_shell_report(checker, call, label);
                    }
                }
            }
        }
    }
}

pub fn code_exec(checker: &mut Checker, call: &ast::ExprCall) {
    let qn = checker.indexer.get_qualified_name(call);

    if let Some(qn) = qn
        && is_code_exec(&qn.segments())
    {
        push_code_report(checker, call, qn.as_str());
        return;
    }

    // Handle globals()["eval"](...) or g["eval"](...)
    if let ast::Expr::Subscript(ast::ExprSubscript { value, slice, .. }) = &*call.func {
        if let Some(qn) = checker.indexer.resolve_qualified_name(value) {
            let segments = qn.segments();
            if segments.len() == 1 && matches!(segments[0], "globals" | "locals" | "vars") {
                if let Some(attr_name) = string_from_expr(slice, &checker.indexer) {
                    if is_code_exec(&[attr_name.as_str()]) {
                        push_code_report(checker, call, format!("{}.{}", segments[0], attr_name));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::{AuditConfidence, Rule};
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("exec_01.py", Rule::ShellExec, vec!["subprocess.call", "os.popen", "subprocess.check_output"])]
    #[test_case("exec_02.py", Rule::CodeExec, vec!["eval", "builtins.exec", "exec", "eval", "exec", "eval", "exec"])]
    #[test_case("exec_03.py", Rule::ObfuscatedCodeExec, vec!["builtins.exec"])]
    #[test_case("exec_03.py", Rule::ObfuscatedShellExec, vec!["os.system", "subprocess.run"])]
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
    #[test_case("exec_10.py", Rule::CodeExec, vec!["globals.eval"])]
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
