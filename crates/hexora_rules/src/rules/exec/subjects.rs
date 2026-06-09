use crate::checker::Checker;
use hexora_semantic::resolver::string_from_expr;

use ruff_python_ast as ast;
use ruff_python_ast::HasNodeIndex;

use super::sequence::expr_sequence_parts;
use super::{MAX_DEPTH, is_python_like_command, keyword_value, primary_arg_or_keyword};

fn is_execution_keyword(name: &str) -> bool {
    matches!(
        name,
        "args" | "executable" | "source" | "object" | "expression" | "target"
    )
}

fn push_python_execution_subjects<'a>(
    checker: &Checker<'_>,
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
    checker: &Checker<'_>,
    expr: &'a ast::Expr,
    subjects: &mut Vec<&'a ast::Expr>,
) {
    if let ast::Expr::Starred(starred) = expr {
        push_execution_subjects_from_argv(checker, &starred.value, subjects);
        return;
    }

    let Some(parts) = super::expr_list_parts(expr) else {
        subjects.push(expr);
        return;
    };

    let Some(first) = parts.first() else {
        return;
    };

    push_python_execution_subjects(checker, first, parts.get(1), parts.get(2), subjects);
}

fn push_execution_subjects_from_parts<'a>(
    checker: &Checker<'_>,
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

#[derive(Default, Clone, Copy)]
pub(super) struct PythonExecInfo<'a> {
    pub(super) c_code: Option<&'a ast::Expr>,
    pub(super) stdin_code: Option<&'a ast::Expr>,
    pub(super) script_path: Option<&'a ast::Expr>,
    pub(super) is_module_invocation: bool,
    pub(super) uses_stdin: bool,
}

impl<'a> PythonExecInfo<'a> {
    pub(super) fn is_python_code_execution(self) -> bool {
        self.c_code.is_some()
            || self.stdin_code.is_some()
            || (self.script_path.is_some() && !self.is_module_invocation)
    }
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

pub(super) fn get_python_exec_info<'a>(
    checker: &Checker,
    call: &'a ast::ExprCall,
) -> PythonExecInfo<'a> {
    let mut info = PythonExecInfo::default();

    for expr in call
        .arguments
        .args
        .iter()
        .chain(keyword_value(call, "args"))
    {
        let Some(parts) = super::expr_list_parts(expr) else {
            continue;
        };
        if let Some(parsed) = inspect_python_argv(checker, parts, None) {
            merge_python_exec_info(&mut info, parsed);
        }
    }

    if let Some(executable) = keyword_value(call, "executable")
        && let Some(args_expr) = primary_arg_or_keyword(call, "args")
        && let Some(parts) = super::expr_list_parts(args_expr)
        && let Some(parsed) = inspect_python_argv(checker, parts, Some(executable))
    {
        merge_python_exec_info(&mut info, parsed);
    }

    if info.uses_stdin {
        info.stdin_code = keyword_value(call, "input");
    }

    info
}

pub(super) fn get_execution_subjects<'a>(
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

pub(super) fn get_direct_code_exec_source<'a>(
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

pub(super) fn shell_argv_layout<'a>(
    checker: &'a Checker<'a>,
    call: &'a ast::ExprCall,
) -> Option<(Vec<&'a ast::Expr>, usize)> {
    let qn = checker.indexer.resolve_qualified_name(&call.func)?;

    if qn.starts_with(&["subprocess"]) || qn.is_exact(&["asyncio", "create_subprocess_exec"]) {
        let argv = primary_arg_or_keyword(call, "args")?;
        return expr_sequence_parts(checker, argv, 0).map(|parts| (parts, 1));
    }

    match qn.segments_slice() {
        [os, name]
            if os == "os"
                && matches!(
                    name.as_str(),
                    "execl"
                        | "execle"
                        | "execlp"
                        | "execlpe"
                        | "spawnl"
                        | "spawnle"
                        | "spawnlp"
                        | "spawnlpe"
                ) =>
        {
            Some((call.arguments.args.iter().collect(), 2))
        }
        _ => None,
    }
}
