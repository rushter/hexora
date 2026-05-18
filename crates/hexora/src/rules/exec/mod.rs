use crate::audit::result::AuditConfidence;
use crate::indexer::checker::Checker;

use ruff_python_ast as ast;

mod report;
mod sequence;
mod signals;
mod subjects;

pub(crate) use signals::get_call_suspicious_taint;

const MAX_DEPTH: u32 = 10;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExecKind {
    Shell,
    Code,
}

impl ExecKind {
    fn matches_qualified_name(self, qn: &crate::indexer::name::QualifiedName) -> bool {
        match self {
            Self::Shell => qn.is_shell_command(),
            Self::Code => qn.is_code_exec(),
        }
    }

    fn is_shell(self) -> bool {
        matches!(self, Self::Shell)
    }
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

fn is_builtin_named(qn: &crate::indexer::name::QualifiedName, name: &str) -> bool {
    qn.is_exact(&[name]) || qn.is_exact(&["builtins", name]) || qn.is_exact(&["__builtins__", name])
}

fn handle_exec(checker: &mut Checker, call: &ast::ExprCall, kind: ExecKind) {
    if let Some(qn) = checker.indexer.resolve_qualified_name(&call.func) {
        if kind.matches_qualified_name(&qn) {
            report::push_report(checker, call, qn.as_str(), kind, None);
            return;
        }

        if qn.is_indirect_exec() {
            if let Some(target) = primary_arg_or_keyword(call, "target")
                && let Some(target_qn) = checker.indexer.resolve_qualified_name(target)
                && kind.matches_qualified_name(&target_qn)
            {
                report::push_report(
                    checker,
                    call,
                    target_qn.as_str(),
                    kind,
                    Some(AuditConfidence::VeryHigh),
                );
                return;
            }
        }

        if qn.as_str() == "map"
            && let Some(func) = call.arguments.args.first()
            && let Some(func_qn) = checker.indexer.resolve_qualified_name(func)
            && kind.matches_qualified_name(&func_qn)
        {
            report::push_report(
                checker,
                call,
                func_qn.as_str(),
                kind,
                Some(AuditConfidence::VeryHigh),
            );
            return;
        }
    }

    report::check_leaked_exec(checker, call, kind);
}

pub fn shell_exec(checker: &mut Checker, call: &ast::ExprCall) {
    handle_exec(checker, call, ExecKind::Shell);
}

pub fn code_exec(checker: &mut Checker, call: &ast::ExprCall) {
    handle_exec(checker, call, ExecKind::Code);
}
