use crate::indexer::checker::Checker;
use crate::rules::builtins::check_builtins;
use crate::rules::call::{data_exfiltration, suspicious_call};
use crate::rules::clipboard::clipboard_read;
use crate::rules::dll_injection::dll_injection;
use crate::rules::download::binary_download;
use crate::rules::dunder::dunder_import;
use crate::rules::env::env_access;
use crate::rules::exec::{code_exec, shell_exec};
use crate::rules::fingerprinting::fingerprinting;
use crate::rules::identifier::suspicious_call_name;
use crate::rules::literal::{check_int_literals, check_literal};
use ruff_python_ast::{self as ast, Expr};

pub fn analyze(expr: &Expr, checker: &mut Checker) {
    match expr {
        Expr::Call(call) => {
            shell_exec(checker, call);
            code_exec(checker, call);
            dll_injection(checker, call);
            dunder_import(checker, call);
            env_access(checker, call);
            fingerprinting(checker, call);
            clipboard_read(checker, call);
            data_exfiltration(checker, call);
            suspicious_call(checker, call);
            binary_download(checker, call);
            check_builtins(checker, call);
            suspicious_call_name(checker, call);
        }
        Expr::List(list @ ast::ExprList { elts, .. }) => {
            if elts.is_empty() {
                return;
            }
            check_int_literals(checker, list);
        }
        Expr::Tuple(tuple) => {
            check_int_literals(checker, tuple);
        }
        Expr::StringLiteral(_) | Expr::BytesLiteral(_) | Expr::FString(_) => {
            check_literal(checker, expr)
        }
        _ => {}
    }
}
