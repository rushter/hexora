use crate::audit::helpers::ListLike;
use crate::audit::parse::Checker;
use log::debug;
use ruff_python_ast as ast;
use ruff_python_semantic::{BindingFlags, BindingKind, Import};

fn bind_pair<'a>(left: &'a ast::Expr, right: &'a ast::Expr, checker: &mut Checker<'a>) {
    match left {
        ast::Expr::Name(name_expr) => {
            let qualified_name = checker.semantic.resolve_qualified_name(right);
            let binding_kind = match &qualified_name {
                Some(qn) => BindingKind::Import(Import {
                    qualified_name: Box::new(qn.clone()),
                }),
                None => BindingKind::Assignment,
            };
            checker.add_binding(
                name_expr.id.as_str(),
                name_expr.range,
                binding_kind,
                BindingFlags::empty(),
            );
        }
        ast::Expr::Tuple(lhs_tuple) => match right {
            ast::Expr::Tuple(rhs_tuple) => {
                if lhs_tuple.elts.len() != rhs_tuple.elts.len() {
                    debug!("Mismatched tuple length for assigment");
                    return;
                }
                bind_assignments(&lhs_tuple.elts, &rhs_tuple.elts, checker);
            }
            ast::Expr::List(rhs_list) => {
                if lhs_tuple.elts.len() != rhs_list.elts.len() {
                    debug!("Mismatched list length for assigment");
                    return;
                }
                bind_assignments(&lhs_tuple.elts, &rhs_list.elts, checker);
            }
            _ => {
                debug!("Mismatched tuple assignment structure");
            }
        },
        ast::Expr::List(lhs_list) => match right {
            ast::Expr::Tuple(rhs_tuple) => {
                if lhs_list.elts.len() != rhs_tuple.elts.len() {
                    debug!("Mismatched tuple length for assigment");
                    return;
                }
                bind_assignments(&lhs_list.elts, &rhs_tuple.elts, checker);
            }
            ast::Expr::List(rhs_list) => {
                if lhs_list.elts.len() != rhs_list.elts.len() {
                    debug!("Mismatched list length for assigment");
                    return;
                }
                bind_assignments(&lhs_list.elts, &rhs_list.elts, checker);
            }
            _ => {
                debug!("Mismatched list assignment structure");
            }
        },
        _ => {}
    }
}

pub fn bind_assignments<'a>(lhs: &'a [ast::Expr], rhs: &'a [ast::Expr], checker: &mut Checker<'a>) {
    for (left, right) in lhs.iter().zip(rhs.iter()) {
        bind_pair(left, right, checker);
    }
}

pub fn match_tuple_assigment<'a, T>(
    lhs: &'a T,
    value: &'a ruff_python_ast::Expr,
    checker: &mut Checker<'a>,
) where
    T: ListLike,
{
    match value {
        ast::Expr::Tuple(rhs) => {
            if lhs.len() != rhs.len() {
                debug!("Mismatched tuple length for assigment");
                return;
            }
            bind_assignments(lhs.elements(), &rhs.elts, checker);
        }
        ast::Expr::List(rhs) => {
            if lhs.len() != rhs.len() {
                debug!("Mismatched list length for assigment");
                return;
            }
            bind_assignments(lhs.elements(), &rhs.elts, checker);
        }
        _ => {}
    }
}

pub fn resolve_assigment_to_imports<'a>(statement: &'a ast::StmtAssign, checker: &mut Checker<'a>) {
    let qualified_name = checker.semantic.resolve_qualified_name(&statement.value);
    for target in &statement.targets {
        match target {
            ast::Expr::Name(name_expr) => {
                let binding_kind = match &qualified_name {
                    Some(qn) => BindingKind::Import(Import {
                        qualified_name: Box::new(qn.clone()),
                    }),
                    None => BindingKind::Assignment,
                };
                checker.add_binding(
                    name_expr.id.as_str(),
                    name_expr.range,
                    binding_kind,
                    BindingFlags::empty(),
                );
            }
            ast::Expr::Tuple(tuple_expr) => {
                match_tuple_assigment(tuple_expr, &statement.value, checker);
            }
            ast::Expr::List(list_expr) => {
                match_tuple_assigment(list_expr, &statement.value, checker);
            }
            _ => {}
        }
    }
}
