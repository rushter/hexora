use crate::indexer::checker::Checker;

use ruff_python_ast as ast;
use ruff_python_ast::HasNodeIndex;

use super::MAX_DEPTH;

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

pub(super) fn expr_sequence_parts<'a>(
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
