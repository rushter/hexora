use crate::audit::helpers::eval_const_str;
use crate::audit::parse::Checker;
use crate::audit::resolver::matches_builtin_functions;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::rules::exec::is_chained_with_base64_call;
use ruff_python_ast as ast;
use ruff_python_ast::Expr;

fn contains_builtins_name<'a>(
    checker: &'a Checker,
    expr: &'a ast::Expr,
) -> Option<(&'a str, String)> {
    let Expr::Subscript(ast::ExprSubscript { value, slice, .. }) = expr else {
        return None;
    };

    let Expr::Call(call) = value.as_ref() else {
        return None;
    };

    let var_name = matches_builtin_functions(checker, &call.func, &["globals", "locals", "vars"])?;

    let key = eval_const_str(checker, slice)?;
    if key == "__builtins__" || key == "builtins" {
        Some((var_name, key))
    } else {
        None
    }
}

pub fn check_builtins(checker: &mut Checker, call: &ast::ExprCall) {
    // __builtins__.eval/exec(...)
    if let Expr::Attribute(attr) = &*call.func {
        if let Expr::Name(name_expr) = &*attr.value {
            if name_expr.id.as_str() == "__builtins__" {
                let name = attr.attr.as_str();
                if name == "eval" || name == "exec" {
                    let is_obf = is_chained_with_base64_call(checker, call);
                    checker.audit_results.push(AuditItem {
                        label: format!("__builtins__.{}", name),
                        rule: if is_obf {
                            Rule::ObfuscatedCodeExec
                        } else {
                            Rule::CodeExec
                        },
                        description: if is_obf {
                            "Execution of obfuscated code".to_string()
                        } else {
                            "Possible execution of unwanted code".to_string()
                        },
                        confidence: AuditConfidence::VeryHigh,
                        location: Some(call.range),
                    });
                    return;
                }
            }
        }
    }

    // getattr(__builtins__, "eval"/"exec")(...)
    if let Expr::Call(getattr_call) = &*call.func {
        let is_getattr = matches_builtin_functions(checker, &getattr_call.func, &["getattr"]);
        if is_getattr.is_some() && getattr_call.arguments.args.len() >= 2 {
            let base_obj = &getattr_call.arguments.args[0];
            let attr_name_expr = &getattr_call.arguments.args[1];
            if let Expr::Name(base_name) = base_obj {
                if base_name.id.as_str() == "__builtins__" {
                    if let Some(attr_name) = eval_const_str(checker, attr_name_expr) {
                        if attr_name == "eval" || attr_name == "exec" {
                            let is_obf = is_chained_with_base64_call(checker, call);
                            checker.audit_results.push(AuditItem {
                                label: format!("__builtins__.{}", attr_name),
                                rule: if is_obf {
                                    Rule::ObfuscatedCodeExec
                                } else {
                                    Rule::CodeExec
                                },
                                description: if is_obf {
                                    "Execution of obfuscated code".to_string()
                                } else {
                                    "Possible execution of unwanted code".to_string()
                                },
                                confidence: AuditConfidence::VeryHigh,
                                location: Some(call.range),
                            });
                            return;
                        }
                    }
                }
            }
        }
    }

    // globals()["__builtins__" or "builtins"].eval/exec(...)
    if let Expr::Attribute(attr) = &*call.func {
        if let Some((var_name, key)) = contains_builtins_name(checker, &attr.value) {
            let name = attr.attr.as_str();
            if name == "eval" || name == "exec" {
                let is_obf = is_chained_with_base64_call(checker, call);
                checker.audit_results.push(AuditItem {
                    label: format!("{}[\"{}\"].{}", var_name, key, name),
                    rule: if is_obf {
                        Rule::ObfuscatedCodeExec
                    } else {
                        Rule::CodeExec
                    },
                    description: if is_obf {
                        "Execution of obfuscated code".to_string()
                    } else {
                        "Possible execution of unwanted code".to_string()
                    },
                    confidence: AuditConfidence::VeryHigh,
                    location: Some(call.range),
                });
                return;
            }
        }
    }

    // globals()['__builtins__' or 'builtins'](...)
    if let Some((var_name, key)) = contains_builtins_name(checker, &call.func) {
        checker.audit_results.push(AuditItem {
            label: format!("{}()[\"{}\"]", var_name, key),
            rule: Rule::BuiltinsVariable,
            description: "Usage of builtins function:".to_string(),
            confidence: AuditConfidence::High,
            location: Some(call.range),
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("builtins_01.py", Rule::CodeExec, vec!["globals[\"__builtins__\"].eval" ])]
    #[test_case("builtins_02.py", Rule::CodeExec, vec!["__builtins__.eval", "__builtins__.eval" ])]
    #[test_case("builtins_03.py", Rule::CodeExec, vec!["globals[\"builtins\"].eval" ])]
    fn test_builtins(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
