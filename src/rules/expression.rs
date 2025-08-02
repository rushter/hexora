use crate::audit::parse::Checker;
use crate::rules::clipboard::clipboard_read;
use crate::rules::dll_injection::dll_injection;
use crate::rules::download::binary_download;
use crate::rules::dunder::dunder_import;
use crate::rules::env::env_access;
use crate::rules::exec::{code_exec, shell_exec};
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
            clipboard_read(checker, call);
            binary_download(checker, call);
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
        Expr::StringLiteral(string_literal) => check_literal(checker, string_literal.into()),
        Expr::BytesLiteral(bytes_literal) => check_literal(checker, bytes_literal.into()),
        Expr::FString(f_string) => check_literal(checker, f_string.into()),
        _ => {}
    }
}
