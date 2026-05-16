use crate::audit::parse::audit_source;
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

fn contains_shell_token(command: &str, token: &str) -> bool {
    command.match_indices(token).any(|(idx, _)| {
        let before = command[..idx].chars().next_back();
        let after = command[idx + token.len()..].chars().next();
        let is_boundary = |ch: Option<char>| match ch {
            None => true,
            Some(c) => c.is_whitespace() || matches!(c, '|' | '&' | ';' | '(' | ')' | '<' | '>'),
        };
        is_boundary(before) && is_boundary(after)
    })
}

fn is_dangerous_command_match(command: &str, token: &str) -> bool {
    if token == "base64" && command.trim() == token {
        return false;
    }

    contains_shell_token(command, token)
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

fn is_execution_keyword(name: &str) -> bool {
    matches!(
        name,
        "args" | "executable" | "source" | "object" | "expression" | "target"
    )
}

fn is_python_like_command(command: &str) -> bool {
    let lowered = command
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(command)
        .to_ascii_lowercase();
    lowered.starts_with("python")
}

fn expr_list_parts(expr: &ast::Expr) -> Option<&[ast::Expr]> {
    match expr {
        ast::Expr::List(list) => Some(&list.elts),
        ast::Expr::Tuple(tuple) => Some(&tuple.elts),
        _ => None,
    }
}

fn push_python_execution_subjects<'a>(
    checker: &'a Checker<'a>,
    first: &'a ast::Expr,
    second: Option<&'a ast::Expr>,
    third: Option<&'a ast::Expr>,
    subjects: &mut Vec<&'a ast::Expr>,
) {
    subjects.push(first);

    let second_flag = second.and_then(|expr| string_from_expr(expr, &checker.indexer));
    if second_flag.as_deref() == Some("-c") {
        if let Some(code) = third {
            subjects.push(code);
        }
        return;
    }

    if string_from_expr(first, &checker.indexer)
        .as_deref()
        .is_some_and(is_python_like_command)
        && !matches!(second_flag.as_deref(), Some("-"))
        && let Some(script_path) = second
    {
        subjects.push(script_path);
    }
}

fn push_execution_subjects_from_argv<'a>(
    checker: &'a Checker<'a>,
    expr: &'a ast::Expr,
    subjects: &mut Vec<&'a ast::Expr>,
) {
    if let ast::Expr::Starred(starred) = expr {
        push_execution_subjects_from_argv(checker, &starred.value, subjects);
        return;
    }

    let Some(parts) = expr_list_parts(expr) else {
        subjects.push(expr);
        return;
    };

    let Some(first) = parts.first() else {
        return;
    };

    push_python_execution_subjects(checker, first, parts.get(1), parts.get(2), subjects);
}

fn push_execution_subjects_from_parts<'a>(
    checker: &'a Checker<'a>,
    parts: &[&'a ast::Expr],
    subjects: &mut Vec<&'a ast::Expr>,
) {
    let Some(first) = parts.first().copied() else {
        return;
    };

    push_python_execution_subjects(
        checker,
        first,
        parts.get(1).copied(),
        parts.get(2).copied(),
        subjects,
    );
}

fn expr_sequence_parts<'a>(
    checker: &'a Checker<'a>,
    expr: &'a ast::Expr,
    depth: u32,
) -> Option<Vec<&'a ast::Expr>> {
    if depth > MAX_DEPTH {
        return None;
    }

    match expr {
        ast::Expr::Starred(starred) => expr_sequence_parts(checker, &starred.value, depth + 1),
        ast::Expr::List(list) => Some(list.elts.iter().collect()),
        ast::Expr::Tuple(tuple) => Some(tuple.elts.iter().collect()),
        _ => mapped_sequence_parts(checker, expr, depth + 1),
    }
}

fn insert_sequence_part<'a>(
    parts: &mut Vec<&'a ast::Expr>,
    idx_expr: &ast::Expr,
    value: &'a ast::Expr,
) {
    let Some(idx) = (match idx_expr {
        ast::Expr::NumberLiteral(num) => num.value.as_int().and_then(|int| int.as_u32()),
        _ => None,
    }) else {
        return;
    };

    let idx = (idx as usize).min(parts.len());
    parts.insert(idx, value);
}

fn mapped_sequence_parts<'a>(
    checker: &'a Checker<'a>,
    expr: &'a ast::Expr,
    depth: u32,
) -> Option<Vec<&'a ast::Expr>> {
    if depth > MAX_DEPTH {
        return None;
    }

    let node_id = expr.node_index().load().as_u32()?;
    let mapped = checker.indexer.model.expr_mapping.get(&node_id)?;
    let mut parts: Option<Vec<&'a ast::Expr>> = None;

    for mapped_expr in mapped {
        match mapped_expr {
            ast::Expr::List(list) => {
                if parts.is_none() {
                    parts = Some(list.elts.iter().collect());
                }
            }
            ast::Expr::Tuple(tuple) => {
                if parts.is_none() {
                    parts = Some(tuple.elts.iter().collect());
                }
            }
            ast::Expr::Call(call) => {
                let Some(attr) = call.func.as_attribute_expr() else {
                    continue;
                };

                let Some(current_parts) = parts.as_mut() else {
                    continue;
                };

                match attr.attr.as_str() {
                    "append" if !call.arguments.args.is_empty() => {
                        current_parts.push(&call.arguments.args[0]);
                    }
                    "extend" if !call.arguments.args.is_empty() => {
                        if let Some(extra_parts) =
                            expr_sequence_parts(checker, &call.arguments.args[0], depth + 1)
                        {
                            current_parts.extend(extra_parts);
                        }
                    }
                    "insert" if call.arguments.args.len() >= 2 => {
                        insert_sequence_part(
                            current_parts,
                            &call.arguments.args[0],
                            &call.arguments.args[1],
                        );
                    }
                    "reverse" => current_parts.reverse(),
                    _ => {}
                }
            }
            _ => {
                if parts.is_none() {
                    parts = expr_sequence_parts(checker, mapped_expr, depth + 1);
                }
            }
        }
    }

    parts
}

fn collect_execution_subjects<'a>(
    checker: &'a Checker<'a>,
    expr: &'a ast::Expr,
    subjects: &mut Vec<&'a ast::Expr>,
    depth: u32,
) {
    if depth > MAX_DEPTH {
        return;
    }

    if let Some(parts) = expr_sequence_parts(checker, expr, depth + 1) {
        push_execution_subjects_from_parts(checker, &parts, subjects);
        return;
    }

    let mut expanded = false;
    if let Some(id) = expr.node_index().load().as_u32()
        && let Some(mapped) = checker.indexer.model.expr_mapping.get(&id)
    {
        expanded = true;
        for mapped_expr in mapped {
            collect_execution_subjects(checker, mapped_expr, subjects, depth + 1);
        }
    }

    if !expanded {
        push_execution_subjects_from_argv(checker, expr, subjects);
    }
}

fn keyword_value<'a>(call: &'a ast::ExprCall, name: &str) -> Option<&'a ast::Expr> {
    call.arguments
        .keywords
        .iter()
        .find(|kw| kw.arg.as_ref().is_some_and(|arg| arg.as_str() == name))
        .map(|kw| &kw.value)
}

fn primary_arg_or_keyword<'a>(call: &'a ast::ExprCall, keyword: &str) -> Option<&'a ast::Expr> {
    call.arguments
        .args
        .first()
        .or_else(|| keyword_value(call, keyword))
}

fn exec_subject_position(checker: &Checker, call: &ast::ExprCall) -> usize {
    checker
        .indexer
        .resolve_qualified_name(&call.func)
        .and_then(|qn| match qn.segments_slice() {
            [os, name]
                if os == "os"
                    && matches!(
                        name.as_str(),
                        "execv"
                            | "execve"
                            | "execvp"
                            | "execvpe"
                            | "spawnv"
                            | "spawnve"
                            | "spawnvp"
                            | "spawnvpe"
                            | "posix_spawn"
                            | "posix_spawnp"
                    ) =>
            {
                Some(1)
            }
            _ => None,
        })
        .unwrap_or(0)
}

fn is_sys_executable_expr(checker: &Checker, expr: &ast::Expr) -> bool {
    checker
        .indexer
        .resolve_qualified_name(expr)
        .is_some_and(|qn| qn.as_str() == "sys.executable")
}

#[derive(Default)]
struct PythonExecInfo<'a> {
    c_code: Option<&'a ast::Expr>,
    stdin_code: Option<&'a ast::Expr>,
    script_path: Option<&'a ast::Expr>,
    is_module_invocation: bool,
    uses_stdin: bool,
}

fn merge_python_exec_info<'a>(into: &mut PythonExecInfo<'a>, next: PythonExecInfo<'a>) {
    into.c_code = into.c_code.or(next.c_code);
    into.stdin_code = into.stdin_code.or(next.stdin_code);
    into.script_path = into.script_path.or(next.script_path);
    into.is_module_invocation |= next.is_module_invocation;
    into.uses_stdin |= next.uses_stdin;
}

fn inspect_python_argv<'a>(
    checker: &Checker,
    parts: &'a [ast::Expr],
    executable: Option<&ast::Expr>,
) -> Option<PythonExecInfo<'a>> {
    let args = if let Some(executable) = executable {
        if !is_sys_executable_expr(checker, executable) {
            return None;
        }
        parts
    } else {
        let (program, args) = parts.split_first()?;
        if !is_sys_executable_expr(checker, program) {
            return None;
        }
        args
    };

    let mut info = PythonExecInfo::default();
    let Some(first_arg) = args.first() else {
        return Some(info);
    };

    match string_from_expr(first_arg, &checker.indexer).as_deref() {
        Some("-c") => info.c_code = args.get(1),
        Some("-") => info.uses_stdin = true,
        Some("-m") => info.is_module_invocation = true,
        _ => info.script_path = Some(first_arg),
    }

    Some(info)
}

fn get_python_exec_info<'a>(checker: &Checker, call: &'a ast::ExprCall) -> PythonExecInfo<'a> {
    let mut info = PythonExecInfo::default();

    for expr in call
        .arguments
        .args
        .iter()
        .chain(keyword_value(call, "args"))
    {
        let Some(parts) = expr_list_parts(expr) else {
            continue;
        };
        if let Some(parsed) = inspect_python_argv(checker, parts, None) {
            merge_python_exec_info(&mut info, parsed);
        }
    }

    if let Some(executable) = keyword_value(call, "executable")
        && let Some(args_expr) = primary_arg_or_keyword(call, "args")
        && let Some(parts) = expr_list_parts(args_expr)
        && let Some(parsed) = inspect_python_argv(checker, parts, Some(executable))
    {
        merge_python_exec_info(&mut info, parsed);
    }

    if info.uses_stdin {
        info.stdin_code = keyword_value(call, "input");
    }

    info
}

fn get_execution_subjects<'a>(
    checker: &'a Checker<'a>,
    call: &'a ast::ExprCall,
) -> Vec<&'a ast::Expr> {
    let mut subjects = Vec::new();

    if let Some(source) = get_direct_code_exec_source(checker, call) {
        subjects.push(source);
        return subjects;
    }

    let python_exec = get_python_exec_info(checker, call);
    if let Some(code) = python_exec.c_code {
        subjects.push(code);
    }
    if let Some(code) = python_exec.stdin_code {
        subjects.push(code);
    }
    if let Some(path) = python_exec.script_path {
        subjects.push(path);
    }
    if !subjects.is_empty() {
        return subjects;
    }

    if let Some(arg) = call
        .arguments
        .args
        .get(exec_subject_position(checker, call))
    {
        collect_execution_subjects(checker, arg, &mut subjects, 0);
    }

    for kw in &call.arguments.keywords {
        if kw
            .arg
            .as_ref()
            .is_some_and(|arg| is_execution_keyword(arg.as_str()))
        {
            collect_execution_subjects(checker, &kw.value, &mut subjects, 0);
        }
    }

    subjects
}

pub fn get_call_suspicious_taint(checker: &Checker, call: &ast::ExprCall) -> Option<TaintKind> {
    get_suspicious_taint(checker, &call.func).or_else(|| {
        get_execution_subjects(checker, call)
            .into_iter()
            .find_map(|expr| get_suspicious_taint(checker, expr))
    })
}

fn contains_dangerous_exec_expr(checker: &Checker, expr: &ast::Expr) -> bool {
    if let Some(s) = string_from_expr(expr, &checker.indexer) {
        DANGEROUS_COMMANDS
            .iter()
            .any(|&c| is_dangerous_command_match(&s, c))
            || DANGEROUS_COMMAND_PREFIXES.iter().any(|&c| s.starts_with(c))
    } else {
        expr_list_parts(expr).is_some_and(|parts| {
            parts
                .iter()
                .any(|part| contains_dangerous_exec_expr(checker, part))
        })
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

fn is_benign_exec_subject(checker: &Checker, expr: &ast::Expr) -> bool {
    checker
        .indexer
        .resolve_qualified_name(expr)
        .is_some_and(|qn| qn.as_str() == "sys.executable")
        || string_from_expr(expr, &checker.indexer)
            .as_deref()
            .is_some_and(is_python_like_command)
}

fn has_only_plain_exec_subjects(checker: &Checker, call: &ast::ExprCall) -> bool {
    get_execution_subjects(checker, call)
        .into_iter()
        .all(|expr| {
            is_benign_exec_subject(checker, expr) || !contains_suspicious_expr(checker, expr)
        })
}

fn is_plain_deobfuscated_subprocess_callable(checker: &Checker, expr: &ast::Expr) -> bool {
    match expr {
        ast::Expr::Name(_) => true,
        ast::Expr::Attribute(attr) => {
            let ast::Expr::Call(import_call) = attr.value.as_ref() else {
                return false;
            };

            checker
                .indexer
                .resolve_qualified_name(&import_call.func)
                .is_some_and(|qn| is_builtin_named(&qn, "__import__"))
                && import_call.arguments.args.len() == 1
                && import_call.arguments.keywords.is_empty()
                && import_call.arguments.args[0]
                    .as_string_literal_expr()
                    .is_some_and(|name| name.value.to_str() == "subprocess")
        }
        _ => false,
    }
}

fn contains_suspicious_expr_limited(checker: &Checker, expr: &ast::Expr, depth: u32) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }

    if checker
        .indexer
        .get_taint(expr)
        .iter()
        .any(|taint| matches!(taint, TaintKind::Decoded | TaintKind::Deobfuscated))
    {
        return true;
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
                if qn.is_suspicious_builtin() {
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
        ast::Expr::List(list) => list
            .elts
            .iter()
            .any(|elt| contains_suspicious_expr_limited(checker, elt, depth + 1)),
        ast::Expr::Tuple(tuple) => tuple
            .elts
            .iter()
            .any(|elt| contains_suspicious_expr_limited(checker, elt, depth + 1)),
        _ => false,
    }
}

fn is_highly_suspicious_exec(checker: &Checker, call: &ast::ExprCall) -> bool {
    contains_suspicious_exec_arguments(checker, call)
}

fn is_builtin_named(qn: &crate::indexer::name::QualifiedName, name: &str) -> bool {
    qn.is_exact(&[name]) || qn.is_exact(&["builtins", name]) || qn.is_exact(&["__builtins__", name])
}

fn is_builtin_call_named(checker: &Checker, expr: &ast::Expr, name: &str) -> bool {
    let ast::Expr::Call(call) = expr else {
        return false;
    };
    checker
        .indexer
        .resolve_qualified_name(&call.func)
        .is_some_and(|qn| is_builtin_named(&qn, name))
}

fn is_exec_eval_call(checker: &Checker, call: &ast::ExprCall) -> bool {
    checker
        .indexer
        .resolve_qualified_name(&call.func)
        .is_some_and(|qn| qn.is_code_exec())
}

fn is_aliased_code_exec_call(checker: &Checker, call: &ast::ExprCall) -> bool {
    let Some(qn) = checker.indexer.resolve_qualified_name(&call.func) else {
        return false;
    };
    if !qn.is_code_exec() {
        return false;
    }

    match call.func.as_ref() {
        ast::Expr::Name(name) => {
            let target = name.id.as_str();
            target != "exec" && target != "eval"
        }
        ast::Expr::Attribute(attr) => {
            let target = attr.attr.as_str();
            if target != "exec" && target != "eval" {
                return true;
            }

            !matches!(
                attr.value.as_ref(),
                ast::Expr::Name(base)
                    if {
                        let base_name = base.id.as_str();
                        base_name == "builtins" || base_name == "__builtins__"
                    }
            )
        }
        _ => true,
    }
}

fn is_explicit_builtin_code_exec_call(call: &ast::ExprCall) -> bool {
    let ast::Expr::Attribute(attr) = call.func.as_ref() else {
        return false;
    };

    let target = attr.attr.as_str();
    if target != "exec" && target != "eval" {
        return false;
    }

    matches!(
        attr.value.as_ref(),
        ast::Expr::Name(base)
            if {
                let base_name = base.id.as_str();
                base_name == "builtins" || base_name == "__builtins__"
            }
    )
}

fn is_relaxed_exec_arg(
    checker: &Checker,
    call: &ast::ExprCall,
    arg: &ast::Expr,
    position: Option<usize>,
    keyword: Option<&str>,
) -> bool {
    if !is_exec_eval_call(checker, call) {
        return false;
    }

    if position.is_some_and(|idx| idx >= 1)
        || keyword.is_some_and(|name| matches!(name, "globals" | "locals"))
    {
        return true;
    }

    if is_builtin_call_named(checker, arg, "compile") {
        return position == Some(0)
            || keyword.is_some_and(|name| matches!(name, "source" | "object" | "expression"));
    }

    false
}

fn is_relaxed_exec_arg_with_mapping(
    checker: &Checker,
    call: &ast::ExprCall,
    arg: &ast::Expr,
    position: Option<usize>,
    keyword: Option<&str>,
    depth: u32,
) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }

    if is_relaxed_exec_arg(checker, call, arg, position, keyword) {
        return true;
    }

    let Some(id) = arg.node_index().load().as_u32() else {
        return false;
    };

    checker
        .indexer
        .model
        .expr_mapping
        .get(&id)
        .is_some_and(|exprs| {
            exprs.iter().any(|mapped| {
                is_relaxed_exec_arg_with_mapping(
                    checker,
                    call,
                    mapped,
                    position,
                    keyword,
                    depth + 1,
                )
            })
        })
}

fn contains_suspicious_exec_arguments(checker: &Checker, call: &ast::ExprCall) -> bool {
    if is_exec_eval_call(checker, call) {
        return contains_suspicious_expr(checker, &call.func)
            || call.arguments.args.iter().enumerate().any(|(idx, arg)| {
                !is_relaxed_exec_arg_with_mapping(checker, call, arg, Some(idx), None, 0)
                    && contains_suspicious_expr(checker, arg)
            })
            || call.arguments.keywords.iter().any(|kw| {
                let kw_name = kw.arg.as_ref().map(|arg| arg.as_str());
                !is_relaxed_exec_arg_with_mapping(checker, call, &kw.value, None, kw_name, 0)
                    && contains_suspicious_expr(checker, &kw.value)
            });
    }

    contains_suspicious_expr(checker, &call.func)
        || get_execution_subjects(checker, call)
            .into_iter()
            .filter(|expr| !is_benign_exec_subject(checker, expr))
            .any(|expr| contains_suspicious_expr(checker, expr))
}

fn get_direct_code_exec_source<'a>(
    checker: &Checker,
    call: &'a ast::ExprCall,
) -> Option<&'a ast::Expr> {
    let qn = checker.indexer.resolve_qualified_name(&call.func)?;
    if !qn.is_code_exec() {
        return None;
    }

    call.arguments.args.first().or_else(|| {
        call.arguments
            .keywords
            .iter()
            .find(|kw| {
                kw.arg
                    .as_ref()
                    .is_some_and(|a| matches!(a.as_str(), "source" | "object" | "expression"))
            })
            .map(|kw| &kw.value)
    })
}

fn audit_nested_code_expr(checker: &mut Checker, call: &ast::ExprCall, code_expr: &ast::Expr) {
    if let Some(code_str) = string_from_expr(code_expr, &checker.indexer) {
        if let Ok(mut sub_results) = audit_source(&code_str, None) {
            for item in &mut sub_results {
                item.location = Some(call.range);
            }
            checker.audit_results.extend(sub_results);
        }
    }
}

fn record_execution_leak(checker: &mut Checker, call: &ast::ExprCall, label: &str) {
    let leaked_params: Vec<_> = get_execution_subjects(checker, call)
        .into_iter()
        .flat_map(|expr| checker.indexer.get_taint(expr).into_iter())
        .filter_map(|taint| match taint {
            TaintKind::InternalParameter(idx) => Some(idx),
            _ => None,
        })
        .collect();

    for idx in leaked_params {
        checker.indexer.add_parameter_leak(idx, label.to_string());
    }
}

fn is_obfuscated(checker: &Checker, call: &ast::ExprCall, label: &str) -> bool {
    label == "map" || contains_suspicious_exec_arguments(checker, call)
}

fn get_audit_info(
    is_shell: bool,
    taint: Option<TaintKind>,
    is_highly_suspicious: bool,
) -> (Rule, String, AuditConfidence) {
    let has_obfuscation_taint = taint.is_some_and(|t| t != TaintKind::EnvVariables);
    let is_obf = has_obfuscation_taint || is_highly_suspicious;
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

    let python_exec = get_python_exec_info(checker, call);
    let is_py_exec = python_exec.c_code.is_some()
        || python_exec.stdin_code.is_some()
        || (python_exec.script_path.is_some() && !python_exec.is_module_invocation);
    let call_taint = get_call_suspicious_taint(checker, call);
    let is_highly_suspicious = is_highly_suspicious_exec(checker, call);

    if is_shell && contains_dangerous_exec(checker, call) && !is_py_exec {
        let is_obf = call_taint.is_some() || is_highly_suspicious;
        let confidence = if is_obfuscated(checker, call, &label) {
            AuditConfidence::VeryHigh
        } else {
            AuditConfidence::High
        };
        checker.audit_results.push(AuditItem {
            label,
            rule: Rule::DangerousExec,
            description: (if is_obf {
                "Execution of obfuscated dangerous command in shell"
            } else {
                "Execution of potentially dangerous command in shell"
            })
            .to_string(),
            confidence,
            location: Some(call.range),
        });
        return;
    }

    let (mut rule, mut description, mut confidence) =
        get_audit_info(is_shell && !is_py_exec, call_taint, is_highly_suspicious);

    if is_py_exec {
        rule = Rule::CodeExec;
        description = "Suspicious Python code execution using subprocess".to_string();
        confidence = confidence.max(AuditConfidence::High);
        if let Some(code_expr) = python_exec.c_code {
            audit_nested_code_expr(checker, call, code_expr);
        }
        if let Some(code_expr) = python_exec.stdin_code {
            audit_nested_code_expr(checker, call, code_expr);
            if let Some(taint) = get_suspicious_taint(checker, code_expr) {
                let (conf, _, c) = get_taint_metadata(taint);
                rule = Rule::ObfuscatedCodeExec;
                confidence = conf;
                description = format!("Execution of {} via Python subprocess stdin.", c);
            }
        }
        if let Some(script_path) = python_exec.script_path {
            if let Some(taint) = get_suspicious_taint(checker, script_path) {
                let (conf, _, c) = get_taint_metadata(taint);
                rule = Rule::ObfuscatedCodeExec;
                confidence = conf;
                description = format!("Execution of {} via Python subprocess script path.", c);
            }
        }
    } else if !is_shell {
        if let Some(code_expr) = get_direct_code_exec_source(checker, call) {
            audit_nested_code_expr(checker, call, code_expr);
        }

        if is_aliased_code_exec_call(checker, call) || is_explicit_builtin_code_exec_call(call) {
            confidence = confidence.max(AuditConfidence::High);
        }
    }

    if is_obfuscated(checker, call, &label) && call_taint != Some(TaintKind::EnvVariables) {
        confidence = AuditConfidence::VeryHigh;
    }

    // Alias bindings like `original_run = __import__("subprocess").run` are deobfuscated,
    // but if the executed argv itself is plain we should not promote the call to VeryHigh.
    if is_shell
        && call_taint == Some(TaintKind::Deobfuscated)
        && checker
            .indexer
            .resolve_qualified_name(&call.func)
            .is_some_and(|qn| qn.starts_with(&["subprocess"]))
        && is_plain_deobfuscated_subprocess_callable(checker, &call.func)
        && has_only_plain_exec_subjects(checker, call)
    {
        confidence = confidence.min(AuditConfidence::High);
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

    for (param_idx, sink_name) in binding.parameter_leaks.clone() {
        let sink_qn = crate::indexer::name::QualifiedName::new(sink_name.clone());
        let matched = if is_shell {
            sink_qn.is_shell_command()
        } else {
            sink_qn.is_code_exec()
        };

        if !matched {
            continue;
        }

        let Some(arg) = call.arguments.args.get(param_idx) else {
            continue;
        };

        let arg_taint = get_suspicious_taint(checker, arg);
        let (rule, mut description, mut confidence) = get_audit_info(
            is_shell,
            arg_taint,
            is_highly_suspicious_exec(checker, call),
        );
        confidence = confidence.max(AuditConfidence::High);
        description = format!(
            "{} (via local function {} leaking to {}).",
            &description[..description.len() - 1],
            name,
            sink_name
        );
        if is_obfuscated(checker, call, &name)
            && arg_taint.is_some_and(|t| t != TaintKind::EnvVariables)
        {
            confidence = AuditConfidence::VeryHigh;
        }

        // Simple passthrough wrappers like test monkeypatch side effects often
        // forward a plain argv parameter unchanged to subprocess.run/Popen.
        // Keep those at High unless the argument itself carries obfuscation taint.
        if is_shell
            && arg_taint.is_none()
            && get_execution_subjects(checker, call)
                .into_iter()
                .all(|expr| !contains_suspicious_expr(checker, expr))
        {
            confidence = confidence.min(AuditConfidence::High);
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

fn matches_exec_kind(qn: &crate::indexer::name::QualifiedName, is_shell: bool) -> bool {
    if is_shell {
        qn.is_shell_command()
    } else {
        qn.is_code_exec()
    }
}

fn handle_exec(checker: &mut Checker, call: &ast::ExprCall, is_shell: bool) {
    if let Some(qn) = checker.indexer.resolve_qualified_name(&call.func) {
        if matches_exec_kind(&qn, is_shell) {
            push_report(checker, call, qn.as_str(), is_shell, None);
            return;
        }

        if qn.is_indirect_exec() {
            if let Some(target) = primary_arg_or_keyword(call, "target")
                && let Some(target_qn) = checker.indexer.resolve_qualified_name(target)
                && matches_exec_kind(&target_qn, is_shell)
            {
                push_report(
                    checker,
                    call,
                    target_qn.as_str(),
                    is_shell,
                    Some(AuditConfidence::VeryHigh),
                );
                return;
            }
        }

        if qn.as_str() == "map"
            && let Some(func) = call.arguments.args.first()
            && let Some(func_qn) = checker.indexer.resolve_qualified_name(func)
            && matches_exec_kind(&func_qn, is_shell)
        {
            push_report(
                checker,
                call,
                func_qn.as_str(),
                is_shell,
                Some(AuditConfidence::VeryHigh),
            );
            return;
        }
    }

    check_leaked_exec(checker, call, is_shell);
}

pub fn shell_exec(checker: &mut Checker, call: &ast::ExprCall) {
    handle_exec(checker, call, true);
}

pub fn code_exec(checker: &mut Checker, call: &ast::ExprCall) {
    handle_exec(checker, call, false);
}
