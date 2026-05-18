use crate::indexer::checker::Checker;
use crate::indexer::model::Transformation;
use crate::indexer::resolver::string_from_expr;
use crate::indexer::taint::TaintKind;

use ruff_python_ast as ast;
use ruff_python_ast::HasNodeIndex;

use super::subjects::{get_direct_code_exec_source, get_execution_subjects, shell_argv_layout};
use super::{MAX_DEPTH, is_builtin_named, is_python_like_command};

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

pub(super) fn get_suspicious_taint(checker: &Checker, expr: &ast::Expr) -> Option<TaintKind> {
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

pub(crate) fn get_call_suspicious_taint(
    checker: &Checker,
    call: &ast::ExprCall,
) -> Option<TaintKind> {
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
        super::expr_list_parts(expr).is_some_and(|parts| {
            parts
                .iter()
                .any(|part| contains_dangerous_exec_expr(checker, part))
        })
    }
}

pub(super) fn contains_dangerous_exec(checker: &Checker, call: &ast::ExprCall) -> bool {
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

pub(super) fn contains_suspicious_expr(checker: &Checker, expr: &ast::Expr) -> bool {
    contains_suspicious_expr_limited(checker, expr, 0)
}

pub(super) fn is_benign_exec_subject(checker: &Checker, expr: &ast::Expr) -> bool {
    checker
        .indexer
        .resolve_qualified_name(expr)
        .is_some_and(|qn| qn.as_str() == "sys.executable")
        || string_from_expr(expr, &checker.indexer)
            .as_deref()
            .is_some_and(is_python_like_command)
}

fn has_hard_obfuscation_signal(checker: &Checker, expr: &ast::Expr) -> bool {
    checker.indexer.get_taint(expr).iter().any(|taint| {
        matches!(
            taint,
            TaintKind::Decoded | TaintKind::NetworkSourced | TaintKind::FileSourced
        )
    }) || expr.node_index().load().as_u32().is_some_and(|id| {
        checker
            .indexer
            .model
            .decoded_nodes
            .borrow()
            .get(&id)
            .is_some_and(|transformation| {
                matches!(transformation, Transformation::Base64 | Transformation::Hex)
            })
    })
}

fn is_plain_argv_part(checker: &Checker, expr: &ast::Expr) -> bool {
    is_benign_exec_subject(checker, expr) || !contains_suspicious_expr(checker, expr)
}

pub(super) fn should_cap_plain_argv_shell_exec(checker: &Checker, call: &ast::ExprCall) -> bool {
    if contains_suspicious_expr(checker, &call.func) {
        return false;
    }

    let Some((parts, leading_dynamic_parts)) = shell_argv_layout(checker, call) else {
        return false;
    };

    if parts.is_empty() || parts.len() < leading_dynamic_parts {
        return false;
    }

    let (dynamic_parts, plain_parts) = parts.split_at(leading_dynamic_parts);
    dynamic_parts
        .iter()
        .all(|expr| !has_hard_obfuscation_signal(checker, expr))
        && plain_parts
            .iter()
            .all(|expr| is_plain_argv_part(checker, expr))
}

pub(super) fn is_plain_deobfuscated_subprocess_callable(
    checker: &Checker,
    expr: &ast::Expr,
) -> bool {
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

fn is_identifier_segment(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(ch) if ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn is_dotted_lookup_string(value: &str) -> bool {
    !value.is_empty() && value.split('.').all(is_identifier_segment)
}

fn is_plain_lookup_eval_expr(checker: &Checker, expr: &ast::Expr, depth: u32) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }

    if string_from_expr(expr, &checker.indexer)
        .as_deref()
        .is_some_and(is_dotted_lookup_string)
    {
        return true;
    }

    if let ast::Expr::Call(call) = expr
        && checker
            .indexer
            .resolve_qualified_name(&call.func)
            .is_some_and(|qn| is_builtin_named(&qn, "eval"))
        && call.arguments.args.len() == 1
        && call.arguments.keywords.is_empty()
        && string_from_expr(&call.arguments.args[0], &checker.indexer)
            .as_deref()
            .is_some_and(is_dotted_lookup_string)
    {
        return true;
    }

    let Some(id) = expr.node_index().load().as_u32() else {
        return false;
    };

    checker
        .indexer
        .model
        .expr_mapping
        .get(&id)
        .is_some_and(|exprs| {
            exprs
                .iter()
                .any(|mapped| is_plain_lookup_eval_expr(checker, mapped, depth + 1))
        })
}

pub(super) fn is_plain_lookup_exec_source(checker: &Checker, expr: &ast::Expr, depth: u32) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }

    if is_plain_lookup_eval_expr(checker, expr, depth) {
        return true;
    }

    let ast::Expr::Name(name) = expr else {
        return false;
    };

    checker
        .indexer
        .lookup_binding(name.id.as_str())
        .and_then(|binding| binding.value_expr)
        .is_some_and(|value_expr| is_plain_lookup_exec_source(checker, value_expr, depth + 1))
}

fn is_reflection_string_cleanup_method(name: &str) -> bool {
    matches!(
        name,
        "strip"
            | "lstrip"
            | "rstrip"
            | "replace"
            | "removeprefix"
            | "removesuffix"
            | "lower"
            | "upper"
    )
}

pub(super) fn is_reflection_like_exec_source(
    checker: &Checker,
    expr: &ast::Expr,
    depth: u32,
) -> bool {
    if depth > MAX_DEPTH {
        return false;
    }

    if has_hard_obfuscation_signal(checker, expr) {
        return false;
    }

    if is_plain_lookup_exec_source(checker, expr, depth) {
        return true;
    }

    match expr {
        ast::Expr::Name(_) | ast::Expr::Attribute(_) | ast::Expr::Subscript(_) => true,
        ast::Expr::Call(call) => {
            let Some(attr) = call.func.as_attribute_expr() else {
                return false;
            };

            is_reflection_string_cleanup_method(attr.attr.as_str())
                && is_reflection_like_exec_source(checker, &attr.value, depth + 1)
                && call
                    .arguments
                    .args
                    .iter()
                    .all(|arg| string_from_expr(arg, &checker.indexer).is_some())
                && call
                    .arguments
                    .keywords
                    .iter()
                    .all(|kw| string_from_expr(&kw.value, &checker.indexer).is_some())
        }
        _ => expr
            .node_index()
            .load()
            .as_u32()
            .and_then(|id| checker.indexer.model.expr_mapping.get(&id))
            .is_some_and(|exprs| {
                exprs
                    .iter()
                    .any(|mapped| is_reflection_like_exec_source(checker, mapped, depth + 1))
            }),
    }
}

pub(super) fn is_plain_reflection_call_result(checker: &Checker, expr: &ast::Expr) -> bool {
    let ast::Expr::Call(call) = expr else {
        return false;
    };

    checker
        .indexer
        .resolve_qualified_name(&call.func)
        .is_some_and(|qn| qn.is_code_exec())
        && get_direct_code_exec_source(checker, call)
            .is_some_and(|source| is_reflection_like_exec_source(checker, source, 0))
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
            if let Some(qn) = checker.indexer.get_qualified_name(call)
                && qn.is_suspicious_builtin()
            {
                return true;
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

pub(super) fn is_aliased_code_exec_call(checker: &Checker, call: &ast::ExprCall) -> bool {
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

pub(super) fn is_explicit_builtin_code_exec_call(call: &ast::ExprCall) -> bool {
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

pub(super) fn contains_suspicious_exec_arguments(checker: &Checker, call: &ast::ExprCall) -> bool {
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

pub(super) fn should_promote_exec_confidence(
    taint: Option<TaintKind>,
    is_highly_suspicious: bool,
) -> bool {
    is_highly_suspicious || taint.is_some_and(|t| t != TaintKind::EnvVariables)
}
