use crate::audit::parse::Checker;
use crate::rules::identifier::{
    suspicious_function_name, suspicious_function_parameter, suspicious_variable,
};
use crate::rules::imports::check_import;
use ruff_python_ast as ast;

pub fn analyze(stmt: &ast::Stmt, checker: &mut Checker) {
    match stmt {
        ast::Stmt::Import(_) => {
            check_import(stmt, checker);
        }
        ast::Stmt::ImportFrom(_) => {
            check_import(stmt, checker);
        }
        ast::Stmt::Assign(ast::StmtAssign { targets, .. }) => {
            suspicious_variable(checker, targets);
        }
        ast::Stmt::AnnAssign(ast::StmtAnnAssign { target, .. }) => {
            suspicious_variable(checker, std::slice::from_ref(target));
        }
        ast::Stmt::With(ast::StmtWith { items, .. }) => {
            for item in items {
                if let Some(expr) = &item.optional_vars {
                    suspicious_variable(checker, std::slice::from_ref(expr));
                }
            }
        }
        ast::Stmt::FunctionDef(ast::StmtFunctionDef {
            name, parameters, ..
        }) => {
            suspicious_function_name(checker, name);
            let args = &parameters.args;
            for arg in args {
                suspicious_function_parameter(checker, arg.parameter.name());
            }
        }

        _ => {}
    }
}
