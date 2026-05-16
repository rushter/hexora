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

fn push_execution_subjects_from_argv<'a>(
    checker: &'a Checker<'a>,
    expr: &'a ast::Expr,
    subjects: &mut Vec<&'a ast::Expr>,
) {
    if let ast::Expr::Starred(starred) = expr {
        push_execution_subjects_from_argv(checker, &starred.value, subjects);
        return;
    }

    let elts = match expr {
        ast::Expr::List(list) => Some(&list.elts[..]),
        ast::Expr::Tuple(tuple) => Some(&tuple.elts[..]),
        _ => None,
    };

    let Some(elts) = elts else {
        subjects.push(expr);
        return;
    };

    let Some(first) = elts.first() else {
        return;
    };
    subjects.push(first);

    let second = elts.get(1);
    let second_flag = second.and_then(|expr| string_from_expr(expr, &checker.indexer));
    if second_flag.as_deref() == Some("-c") {
        if let Some(code) = elts.get(2) {
            subjects.push(code);
        }
        return;
    }

    let first_name = string_from_expr(first, &checker.indexer);
    if first_name.as_deref().is_some_and(is_python_like_command)
        && !matches!(second_flag.as_deref(), Some("-"))
        && let Some(script_path) = second
    {
        subjects.push(script_path);
    }
}

fn push_execution_subjects_from_parts<'a>(
    checker: &'a Checker<'a>,
    parts: &[&'a ast::Expr],
    subjects: &mut Vec<&'a ast::Expr>,
) {
    let Some(first) = parts.first().copied() else {
        return;
    };
    subjects.push(first);

    let second = parts.get(1).copied();
    let second_flag = second.and_then(|expr| string_from_expr(expr, &checker.indexer));
    if second_flag.as_deref() == Some("-c") {
        if let Some(code) = parts.get(2).copied() {
            subjects.push(code);
        }
        return;
    }

    let first_name = string_from_expr(first, &checker.indexer);
    if first_name.as_deref().is_some_and(is_python_like_command)
        && !matches!(second_flag.as_deref(), Some("-"))
        && let Some(script_path) = second
    {
        subjects.push(script_path);
    }
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

fn get_execution_subjects<'a>(
    checker: &'a Checker<'a>,
    call: &'a ast::ExprCall,
) -> Vec<&'a ast::Expr> {
    let mut subjects = Vec::new();

    if let Some(source) = get_direct_code_exec_source(checker, call) {
        subjects.push(source);
        return subjects;
    }

    if let Some(code) = get_python_exec_c_code(checker, call) {
        subjects.push(code);
    }
    if let Some(code) = get_python_exec_stdin_code(checker, call) {
        subjects.push(code);
    }
    if let Some(path) = get_python_exec_script_path(checker, call) {
        subjects.push(path);
    }
    if !subjects.is_empty() {
        return subjects;
    }

    let first_subject_idx = checker
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
        .unwrap_or(0);

    if let Some(arg) = call.arguments.args.get(first_subject_idx) {
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

fn get_python_exec_c_code<'a>(checker: &Checker, call: &'a ast::ExprCall) -> Option<&'a ast::Expr> {
    let check_list = |elts: &'a [ast::Expr]| -> Option<&'a ast::Expr> {
        if elts.len() < 2 {
            return None;
        }
        let first_is_sys_exec = checker
            .indexer
            .resolve_qualified_name(&elts[0])
            .is_some_and(|qn| qn.as_str() == "sys.executable");
        let second_is_c = string_from_expr(&elts[1], &checker.indexer).is_some_and(|s| s == "-c");

        if first_is_sys_exec && second_is_c {
            elts.get(2)
        } else {
            None
        }
    };

    for arg in &call.arguments.args {
        if let Some(code) = match arg {
            ast::Expr::List(l) => check_list(&l.elts),
            ast::Expr::Tuple(t) => check_list(&t.elts),
            _ => None,
        } {
            return Some(code);
        }
    }

    for kw in &call.arguments.keywords {
        if kw.arg.as_ref().is_some_and(|a| a.as_str() == "args") {
            if let Some(code) = match &kw.value {
                ast::Expr::List(l) => check_list(&l.elts),
                ast::Expr::Tuple(t) => check_list(&t.elts),
                _ => None,
            } {
                return Some(code);
            }
        }
    }

    let has_executable_sys_exec = call.arguments.keywords.iter().any(|kw| {
        kw.arg.as_ref().is_some_and(|a| a.as_str() == "executable")
            && checker
                .indexer
                .resolve_qualified_name(&kw.value)
                .is_some_and(|qn| qn.as_str() == "sys.executable")
    });

    if has_executable_sys_exec {
        let args_val = call.arguments.args.first().or_else(|| {
            call.arguments
                .keywords
                .iter()
                .find(|kw| kw.arg.as_ref().is_some_and(|a| a.as_str() == "args"))
                .map(|kw| &kw.value)
        });

        if let Some(args) = args_val {
            let elts = match args {
                ast::Expr::List(l) => Some(&l.elts[..]),
                ast::Expr::Tuple(t) => Some(&t.elts[..]),
                _ => None,
            };

            if let Some(elts) = elts {
                if elts
                    .first()
                    .and_then(|e| string_from_expr(e, &checker.indexer))
                    .is_some_and(|s| s == "-c")
                {
                    return elts.get(1);
                }
            }
        }
    }

    None
}

fn get_python_exec_script_path<'a>(
    checker: &Checker,
    call: &'a ast::ExprCall,
) -> Option<&'a ast::Expr> {
    let check_list = |elts: &'a [ast::Expr]| -> Option<&'a ast::Expr> {
        if elts.len() < 2 {
            return None;
        }
        let first_is_sys_exec = checker
            .indexer
            .resolve_qualified_name(&elts[0])
            .is_some_and(|qn| qn.as_str() == "sys.executable");
        if !first_is_sys_exec {
            return None;
        }
        let second = &elts[1];
        let second_flag = string_from_expr(second, &checker.indexer);
        if second_flag
            .as_deref()
            .is_some_and(|s| matches!(s, "-c" | "-"))
        {
            return None;
        }
        Some(second)
    };

    for arg in &call.arguments.args {
        if let Some(path) = match arg {
            ast::Expr::List(l) => check_list(&l.elts),
            ast::Expr::Tuple(t) => check_list(&t.elts),
            _ => None,
        } {
            return Some(path);
        }
    }

    for kw in &call.arguments.keywords {
        if kw.arg.as_ref().is_some_and(|a| a.as_str() == "args") {
            if let Some(path) = match &kw.value {
                ast::Expr::List(l) => check_list(&l.elts),
                ast::Expr::Tuple(t) => check_list(&t.elts),
                _ => None,
            } {
                return Some(path);
            }
        }
    }

    None
}

fn is_python_exec_shell_invocation(checker: &Checker, call: &ast::ExprCall) -> bool {
    let check_list = |elts: &[ast::Expr]| -> bool {
        if elts.len() < 2 {
            return false;
        }

        let first_is_sys_exec = checker
            .indexer
            .resolve_qualified_name(&elts[0])
            .is_some_and(|qn| qn.as_str() == "sys.executable");
        if !first_is_sys_exec {
            return false;
        }

        string_from_expr(&elts[1], &checker.indexer)
            .as_deref()
            .is_some_and(|s| s == "-m")
    };

    call.arguments.args.iter().any(|arg| match arg {
        ast::Expr::List(l) => check_list(&l.elts),
        ast::Expr::Tuple(t) => check_list(&t.elts),
        _ => false,
    }) || call.arguments.keywords.iter().any(|kw| {
        kw.arg.as_ref().is_some_and(|a| a.as_str() == "args")
            && match &kw.value {
                ast::Expr::List(l) => check_list(&l.elts),
                ast::Expr::Tuple(t) => check_list(&t.elts),
                _ => false,
            }
    })
}

fn get_python_exec_stdin_code<'a>(
    checker: &Checker,
    call: &'a ast::ExprCall,
) -> Option<&'a ast::Expr> {
    let has_stdin_python = {
        let check_list = |elts: &'a [ast::Expr]| -> bool {
            if elts.len() < 2 {
                return false;
            }
            let first_is_sys_exec = checker
                .indexer
                .resolve_qualified_name(&elts[0])
                .is_some_and(|qn| qn.as_str() == "sys.executable");
            let second_is_stdin =
                string_from_expr(&elts[1], &checker.indexer).is_some_and(|s| s == "-");
            first_is_sys_exec && second_is_stdin
        };

        call.arguments.args.iter().any(|arg| match arg {
            ast::Expr::List(l) => check_list(&l.elts),
            ast::Expr::Tuple(t) => check_list(&t.elts),
            _ => false,
        }) || call.arguments.keywords.iter().any(|kw| {
            kw.arg.as_ref().is_some_and(|a| a.as_str() == "args")
                && match &kw.value {
                    ast::Expr::List(l) => check_list(&l.elts),
                    ast::Expr::Tuple(t) => check_list(&t.elts),
                    _ => false,
                }
        })
    };

    if !has_stdin_python {
        return None;
    }

    call.arguments
        .keywords
        .iter()
        .find(|kw| kw.arg.as_ref().is_some_and(|a| a.as_str() == "input"))
        .map(|kw| &kw.value)
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

    let py_exec_code = get_python_exec_c_code(checker, call);
    let py_exec_script = get_python_exec_script_path(checker, call);
    let py_exec_stdin = get_python_exec_stdin_code(checker, call);
    let is_py_exec_shell = is_python_exec_shell_invocation(checker, call);
    let is_py_exec = py_exec_code.is_some()
        || py_exec_stdin.is_some()
        || (py_exec_script.is_some() && !is_py_exec_shell);
    let call_taint = get_call_suspicious_taint(checker, call);

    if is_shell && contains_dangerous_exec(checker, call) && !is_py_exec {
        let is_obf = get_call_suspicious_taint(checker, call).is_some()
            || is_highly_suspicious_exec(checker, call);
        let mut confidence = AuditConfidence::High;
        if is_obfuscated(checker, call, &label) {
            confidence = AuditConfidence::VeryHigh;
        }
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

    let (mut rule, mut description, mut confidence) = get_audit_info(
        is_shell && !is_py_exec,
        call_taint,
        is_highly_suspicious_exec(checker, call),
    );

    if is_py_exec {
        rule = Rule::CodeExec;
        description = "Suspicious Python code execution using subprocess".to_string();
        confidence = confidence.max(AuditConfidence::High);
        if let Some(code_expr) = py_exec_code {
            audit_nested_code_expr(checker, call, code_expr);
        }
        if let Some(code_expr) = py_exec_stdin {
            audit_nested_code_expr(checker, call, code_expr);
            if let Some(taint) = get_suspicious_taint(checker, code_expr) {
                let (conf, _, c) = get_taint_metadata(taint);
                rule = Rule::ObfuscatedCodeExec;
                confidence = conf;
                description = format!("Execution of {} via Python subprocess stdin.", c);
            }
        }
        if let Some(script_path) = py_exec_script {
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

        if matched {
            if let Some(arg) = call.arguments.args.get(param_idx) {
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
    }
}

pub fn shell_exec(checker: &mut Checker, call: &ast::ExprCall) {
    if let Some(qn) = checker.indexer.resolve_qualified_name(&call.func) {
        if qn.is_shell_command() {
            push_report(checker, call, qn.as_str(), true, None);
            return;
        }
        if qn.is_indirect_exec() {
            let target_arg = call.arguments.args.first().or_else(|| {
                call.arguments
                    .keywords
                    .iter()
                    .find(|kw| kw.arg.as_ref().map(|a| a.as_str()) == Some("target"))
                    .map(|kw| &kw.value)
            });
            if let Some(target) = target_arg {
                if let Some(target_qn) = checker.indexer.resolve_qualified_name(target) {
                    if target_qn.is_shell_command() {
                        push_report(
                            checker,
                            call,
                            target_qn.as_str(),
                            true,
                            Some(AuditConfidence::VeryHigh),
                        );
                        return;
                    }
                }
            }
        }
        if qn.as_str() == "map" && !call.arguments.args.is_empty() {
            if let Some(func_qn) = checker
                .indexer
                .resolve_qualified_name(&call.arguments.args[0])
            {
                if func_qn.is_shell_command() {
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
    if let Some(qn) = checker.indexer.resolve_qualified_name(&call.func) {
        if qn.is_code_exec() {
            push_report(checker, call, qn.as_str(), false, None);
            return;
        }
        if qn.is_indirect_exec() {
            let target_arg = call.arguments.args.first().or_else(|| {
                call.arguments
                    .keywords
                    .iter()
                    .find(|kw| kw.arg.as_ref().map(|a| a.as_str()) == Some("target"))
                    .map(|kw| &kw.value)
            });
            if let Some(target) = target_arg {
                if let Some(target_qn) = checker.indexer.resolve_qualified_name(target) {
                    if target_qn.is_code_exec() {
                        push_report(
                            checker,
                            call,
                            target_qn.as_str(),
                            false,
                            Some(AuditConfidence::VeryHigh),
                        );
                        return;
                    }
                }
            }
        }
        if qn.as_str() == "map" && !call.arguments.args.is_empty() {
            if let Some(func_qn) = checker
                .indexer
                .resolve_qualified_name(&call.arguments.args[0])
            {
                if func_qn.is_code_exec() {
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

    #[test_case(
        "exec_01.py",
        Rule::ShellExec,
        vec![
            ("subprocess.call", AuditConfidence::Medium),
            ("os.popen", AuditConfidence::Medium),
            ("subprocess.check_output", AuditConfidence::Medium),
        ]
    )]
    #[test_case(
        "exec_02.py",
        Rule::CodeExec,
        vec![
            ("eval", AuditConfidence::Medium),
            ("builtins.exec", AuditConfidence::High),
            ("exec", AuditConfidence::Medium),
            ("eval", AuditConfidence::High),
            ("exec", AuditConfidence::High),
            ("eval", AuditConfidence::High),
            ("exec", AuditConfidence::High),
        ]
    )]
    #[test_case(
        "exec_03.py",
        Rule::ObfuscatedCodeExec,
        vec![
            ("builtins.exec", AuditConfidence::VeryHigh),
            ("builtins.exec", AuditConfidence::VeryHigh),
        ]
    )]
    #[test_case(
        "exec_03.py",
        Rule::ObfuscatedShellExec,
        vec![
            ("os.system", AuditConfidence::VeryHigh),
            ("os.system", AuditConfidence::VeryHigh),
            ("subprocess.run", AuditConfidence::VeryHigh),
        ]
    )]
    #[test_case(
        "exec_04.py",
        Rule::ObfuscatedShellExec,
        vec![
            ("os.system", AuditConfidence::VeryHigh),
            ("subprocess.Popen", AuditConfidence::VeryHigh),
            ("subprocess.check_output", AuditConfidence::VeryHigh),
            ("commands.getstatusoutput", AuditConfidence::VeryHigh),
        ]
    )]
    #[test_case(
        "exec_05.py",
        Rule::ObfuscatedShellExec,
        vec![
            ("commands.getstatusoutput", AuditConfidence::VeryHigh),
            ("commands.getstatusoutput", AuditConfidence::VeryHigh),
        ]
    )]
    #[test_case(
        "exec_06.py",
        Rule::DangerousExec,
        vec![
            ("subprocess.run", AuditConfidence::High),
            ("os.system", AuditConfidence::High),
        ]
    )]
    #[test_case(
        "exec_07.py",
        Rule::ObfuscatedCodeExec,
        vec![
            ("exec", AuditConfidence::VeryHigh),
            ("builtins.exec", AuditConfidence::VeryHigh),
            ("exec", AuditConfidence::VeryHigh),
        ]
    )]
    #[test_case(
        "exec_08.py",
        Rule::ShellExec,
        vec![("subprocess.call", AuditConfidence::Medium)]
    )]
    #[test_case(
        "exec_09.py",
        Rule::ObfuscatedCodeExec,
        vec![("__builtins__.eval", AuditConfidence::VeryHigh)]
    )]
    #[test_case(
        "exec_10.py",
        Rule::ObfuscatedCodeExec,
        vec![("eval", AuditConfidence::VeryHigh)]
    )]
    #[test_case(
        "exec_11.py",
        Rule::ObfuscatedCodeExec,
        vec![
            ("exec", AuditConfidence::VeryHigh),
            ("exec", AuditConfidence::VeryHigh),
        ]
    )]
    #[test_case(
        "exec_12.py",
        Rule::ObfuscatedCodeExec,
        vec![("exec", AuditConfidence::VeryHigh)]
    )]
    #[test_case(
        "exec_14.py",
        Rule::ShellExec,
        vec![("subprocess.Popen", AuditConfidence::Medium)]
    )]
    #[test_case(
        "exec_15.py",
        Rule::ObfuscatedShellExec,
        vec![("os.system", AuditConfidence::Medium)]
    )]
    #[test_case(
        "exec_15.py",
        Rule::ShellExec,
        vec![("os.system", AuditConfidence::Medium)]
    )]
    #[test_case(
        "exec_16.py",
        Rule::DangerousExec,
        vec![
            ("os.system", AuditConfidence::High),
            ("subprocess.run", AuditConfidence::High),
        ]
    )]
    #[test_case(
        "exec_17.py",
        Rule::ObfuscatedShellExec,
        vec![("os.system", AuditConfidence::VeryHigh)]
    )]
    #[test_case(
        "exec_19.py",
        Rule::ObfuscatedCodeExec,
        vec![("exec", AuditConfidence::VeryHigh)]
    )]
    #[test_case(
        "exec_20.py",
        Rule::ObfuscatedCodeExec,
        vec![("exec", AuditConfidence::VeryHigh)]
    )]
    #[test_case(
        "exec_21.py",
        Rule::ObfuscatedShellExec,
        vec![
            ("os.system", AuditConfidence::VeryHigh),
            ("os.system", AuditConfidence::VeryHigh),
            ("os.system", AuditConfidence::VeryHigh),
        ]
    )]
    #[test_case(
        "exec_21.py",
        Rule::DangerousExec,
        vec![("os.posix_spawn", AuditConfidence::High)]
    )]
    #[test_case(
        "exec_21.py",
        Rule::ShellExec,
        vec![("os.system", AuditConfidence::VeryHigh)]
    )]
    #[test_case(
        "exec_22.py",
        Rule::DangerousExec,
        vec![
            ("os.system", AuditConfidence::High),
            ("os.system", AuditConfidence::High),
        ]
    )]
    #[test_case(
        "exec_23.py",
        Rule::ShellExec,
        vec![("subprocess.Popen", AuditConfidence::Medium)]
    )]
    #[test_case(
        "exec_24.py",
        Rule::CodeExec,
        vec![("subprocess.Popen", AuditConfidence::High)]
    )]
    #[test_case(
        "exec_24.py",
        Rule::ObfuscatedCodeExec,
        vec![
            ("exec", AuditConfidence::VeryHigh),
            ("subprocess.run", AuditConfidence::VeryHigh),
        ]
    )]
    #[test_case(
        "exec_25.py",
        Rule::CodeExec,
        vec![("exec", AuditConfidence::Medium)]
    )]
    #[test_case(
        "exec_25.py",
        Rule::ObfuscatedCodeExec,
        vec![("exec", AuditConfidence::VeryHigh)]
    )]
    #[test_case(
        "exec_26.py",
        Rule::ShellExec,
        vec![("execfile", AuditConfidence::Medium)]
    )]
    #[test_case(
        "exec_27.py",
        Rule::ObfuscatedCodeExec,
        vec![
            ("exec", AuditConfidence::VeryHigh),
            ("subprocess.run", AuditConfidence::VeryHigh),
            ("exec", AuditConfidence::VeryHigh),
        ]
    )]
    #[test_case(
        "exec_28.py",
        Rule::CodeExec,
        vec![
            ("exec", AuditConfidence::Medium),
            ("eval", AuditConfidence::Medium),
            ("exec", AuditConfidence::Medium),
            ("exec", AuditConfidence::Medium),
            ("exec", AuditConfidence::Medium),
            ("exec", AuditConfidence::Medium),
            ("exec", AuditConfidence::Medium),
            ("builtins.exec", AuditConfidence::High),
        ]
    )]
    #[test_case(
        "exec_28.py",
        Rule::ObfuscatedCodeExec,
        vec![
            ("exec", AuditConfidence::VeryHigh),
            ("builtins.exec", AuditConfidence::VeryHigh),
        ]
)]
    #[test_case(
        "exec_29.py",
        Rule::ShellExec,
        vec![
            ("subprocess.run", AuditConfidence::Medium),
            ("worker", AuditConfidence::High),
            ("run", AuditConfidence::High),
        ]
    )]
    fn test_exec(path: &str, rule: Rule, expected: Vec<(&str, AuditConfidence)>) {
        assert_audit_results(path, rule, expected);
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
            .map(|item| (item.label.clone(), item.rule, item.confidence))
            .collect();

        let expected = vec![
            (
                "os.system".to_string(),
                Rule::ObfuscatedShellExec,
                AuditConfidence::VeryHigh,
            ),
            (
                "exec".to_string(),
                Rule::ObfuscatedCodeExec,
                AuditConfidence::VeryHigh,
            ),
            ("exec".to_string(), Rule::CodeExec, AuditConfidence::Medium),
            ("eval".to_string(), Rule::CodeExec, AuditConfidence::Medium),
        ];

        assert_eq!(suspicious_items, expected);
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

    #[test_case(
        Rule::DangerousExec,
        vec![("os.system", AuditConfidence::High)]
    )]
    #[test_case(
        Rule::ShellExec,
        vec![
            ("os.system", AuditConfidence::VeryHigh),
            ("subprocess.call", AuditConfidence::VeryHigh),
        ]
    )]
    #[test_case(Rule::CodeExec, vec![("eval", AuditConfidence::Medium)])]
    #[test_case(
        Rule::ObfuscatedShellExec,
        vec![
            ("os.system", AuditConfidence::VeryHigh),
            ("os.system", AuditConfidence::VeryHigh),
            ("os.system", AuditConfidence::VeryHigh),
        ]
    )]
    fn test_bypasses(rule: Rule, expected: Vec<(&str, AuditConfidence)>) {
        assert_audit_results("exec_bypass.py", rule, expected);
    }

    #[test]
    fn test_dangerous_exec_ignores_plain_argument_mentions() {
        let source = r#"import subprocess
subprocess.run(["echo", "base64"])
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::DangerousExec)
            .map(|item| item.label)
            .collect();
        assert!(matches.is_empty());
    }

    #[test]
    fn test_vars_dict_shell_exec() {
        let source = r#"import os
vars(os)["system"]("whoami")
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::ObfuscatedShellExec)
            .map(|item| item.label.clone())
            .collect();
        assert!(matches.contains(&"os.system".to_string()));
    }

    #[test]
    fn test_asyncio_create_subprocess_shell() {
        let source = r#"import asyncio
asyncio.create_subprocess_shell("whoami")
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::ShellExec || item.rule == Rule::DangerousExec)
            .map(|item| item.label.clone())
            .collect();
        assert!(matches.contains(&"asyncio.create_subprocess_shell".to_string()));
    }

    #[test]
    fn test_asyncio_create_subprocess_exec() {
        let source = r#"import asyncio
asyncio.create_subprocess_exec("ls", "-la")
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::ShellExec)
            .map(|item| item.label.clone())
            .collect();
        assert!(matches.contains(&"asyncio.create_subprocess_exec".to_string()));
    }

    #[test]
    fn test_asyncio_from_import_subprocess() {
        let source = r#"from asyncio import create_subprocess_shell as start_proc
start_proc("whoami")
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::ShellExec)
            .map(|item| item.label.clone())
            .collect();
        assert!(matches.contains(&"asyncio.create_subprocess_shell".to_string()));
    }

    #[test]
    fn test_subprocess_input_does_not_count_as_exec_obfuscation() {
        let source = r#"import os
import subprocess

def run_fix_iteration(scorecard):
    cmd = ["claude", "-p"]
    if os.environ.get("ANTHROPIC_API_KEY"):
        cmd.append("--bare")
    prompt = open("fixer.md").read().replace("{scorecard}", str(scorecard))
    subprocess.run(cmd, input=prompt, text=True, check=False)

run_fix_iteration({"status": "FAIL"})
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();

        let obfuscated_shell_exec: Vec<_> = result
            .iter()
            .filter(|item| item.rule == Rule::ObfuscatedShellExec)
            .map(|item| item.label.clone())
            .collect();
        assert!(obfuscated_shell_exec.is_empty());

        let shell_exec: Vec<_> = result
            .iter()
            .filter(|item| item.rule == Rule::ShellExec)
            .map(|item| (item.label.clone(), item.confidence))
            .collect();
        assert_eq!(
            shell_exec,
            vec![("subprocess.run".to_string(), AuditConfidence::Medium)]
        );
    }

    #[test]
    fn test_wrapper_prompt_argument_does_not_leak_as_shell_command() {
        let source = r#"import subprocess

def run_fix_iteration(scorecard):
    prompt = "fix " + str(scorecard)
    cmd = ["claude", "-p", prompt, "--dangerously-skip-permissions"]
    subprocess.run(cmd, text=True, check=False)

run_fix_iteration({"status": "FAIL"})
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();

        let obfuscated_shell_exec: Vec<_> = result
            .iter()
            .filter(|item| item.rule == Rule::ObfuscatedShellExec)
            .map(|item| item.label.clone())
            .collect();
        assert!(obfuscated_shell_exec.is_empty());
    }

    #[test]
    fn test_execvpe_with_fixed_argv_variable_is_not_obfuscated() {
        let source = r#"import os
import sys

def preview(name):
    env = {**os.environ, "APP_THEME": name}
    cmd = [sys.executable, "-m", "dazzle", "serve", "--local"]
    os.execvpe(cmd[0], cmd, env)
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();

        let obfuscated_shell_exec: Vec<_> = result
            .iter()
            .filter(|item| item.rule == Rule::ObfuscatedShellExec)
            .map(|item| item.label.clone())
            .collect();
        assert!(obfuscated_shell_exec.is_empty());

        let shell_exec: Vec<_> = result
            .iter()
            .filter(|item| item.rule == Rule::ShellExec)
            .map(|item| (item.label.clone(), item.confidence))
            .collect();
        assert_eq!(
            shell_exec,
            vec![("os.execvpe".to_string(), AuditConfidence::Medium)]
        );
    }

    #[test]
    fn test_popen_with_fixed_argv_variable_is_not_obfuscated() {
        let source = r#"import subprocess

def open_folder(project_wdir):
    cmd = ["open"]
    cmd.append(project_wdir)
    subprocess.Popen(cmd, cwd=project_wdir)
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();

        let obfuscated_shell_exec: Vec<_> = result
            .iter()
            .filter(|item| item.rule == Rule::ObfuscatedShellExec)
            .map(|item| item.label.clone())
            .collect();
        assert!(obfuscated_shell_exec.is_empty());

        let shell_exec: Vec<_> = result
            .iter()
            .filter(|item| item.rule == Rule::ShellExec)
            .map(|item| (item.label.clone(), item.confidence))
            .collect();
        assert_eq!(
            shell_exec,
            vec![("subprocess.Popen".to_string(), AuditConfidence::Medium)]
        );
    }

    #[test]
    fn test_wrapper_passthrough_run_stays_high_not_very_high() {
        let source = r#"import subprocess

original_run = __import__("subprocess").run

def mock_run(args, **kwargs):
    if args[0] == "git" and args[1] == "push":
        class Result:
            returncode = 1
            stderr = "No remote"
        return Result()
    return original_run(args, **kwargs)

mock_run(["git", "status"])
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();

        let leaked_exec: Vec<_> = result
            .iter()
            .filter(|item| {
                item.description
                    .contains("via local function mock_run leaking to subprocess.run")
            })
            .map(|item| (item.rule.clone(), item.confidence))
            .collect();

        assert_eq!(leaked_exec, vec![(Rule::ShellExec, AuditConfidence::High)]);
    }

    #[test]
    fn test_deobfuscated_shell_alias_with_plain_argv_stays_high() {
        let source = r#"import subprocess

original_run = __import__("subprocess").run
original_run(["git", "status"], check=False)
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();

        let direct_exec: Vec<_> = result
            .iter()
            .filter(|item| item.label == "subprocess.run")
            .map(|item| (item.rule.clone(), item.confidence))
            .collect();

        assert_eq!(
            direct_exec,
            vec![(Rule::ObfuscatedShellExec, AuditConfidence::High)]
        );
    }

    #[test]
    fn test_inline_deobfuscated_subprocess_run_with_plain_argv_stays_high() {
        let source = r#"import sys

__import__("subprocess").run([sys.executable, "-m", "cli.main", "--help"], check=False)
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();

        let direct_exec: Vec<_> = result
            .iter()
            .filter(|item| item.label == "subprocess.run")
            .map(|item| (item.rule.clone(), item.confidence))
            .collect();

        assert_eq!(
            direct_exec,
            vec![(Rule::ObfuscatedShellExec, AuditConfidence::High)]
        );
    }

    #[test]
    fn test_inline_deobfuscated_subprocess_popen_with_plain_argv_stays_high() {
        let source = r#"__import__("subprocess").Popen(["git", "status"])
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();

        let direct_exec: Vec<_> = result
            .iter()
            .filter(|item| item.label == "subprocess.Popen")
            .map(|item| (item.rule.clone(), item.confidence))
            .collect();

        assert_eq!(
            direct_exec,
            vec![(Rule::ObfuscatedShellExec, AuditConfidence::High)]
        );
    }

    #[test]
    fn test_vars_dict_with_no_args() {
        let source = r#"import os
vars()["os"].system("whoami")
"#;
        let result = crate::audit::parse::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::ObfuscatedShellExec)
            .map(|item| item.label.clone())
            .collect();
        assert!(matches.contains(&"os.system".to_string()));
    }
}
