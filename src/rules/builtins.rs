use crate::audit::helpers::eval_const_str;
use crate::audit::parse::Checker;
use crate::audit::resolver::matches_builtin_functions;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::rules::exec::is_chained_with_base64_call;
use ruff_python_ast as ast;
use ruff_python_ast::Expr;

fn contains_builtins_name<'a>(checker: &'a Checker, expr: &'a ast::Expr) -> Option<&'a str> {
    let Expr::Subscript(ast::ExprSubscript { value, slice, .. }) = expr else {
        return None;
    };

    let Expr::Call(call) = value.as_ref() else {
        return None;
    };

    let var_name = matches_builtin_functions(checker, &call.func, &["globals", "locals", "vars"])?;

    let key = eval_const_str(checker, slice)?;
    if key == "__builtins__" {
        Some(var_name)
    } else {
        None
    }
}

pub fn check_builtins(checker: &mut Checker, call: &ast::ExprCall) {
    // globals()["__builtins__"].eval/exec(...)
    if let Expr::Attribute(attr) = &*call.func {
        if let Some(var_name) = contains_builtins_name(checker, &attr.value) {
            let name = attr.attr.as_str();
            if name == "eval" || name == "exec" {
                let is_obf = is_chained_with_base64_call(checker, call);
                checker.audit_results.push(AuditItem {
                    label: format!("{}[\"__builtins__\"].{}", var_name, name),
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

    // globals()['__builtins__'](...)
    if let Some(var_name) = contains_builtins_name(checker, &call.func) {
        checker.audit_results.push(AuditItem {
            label: format!("{}()[\"__builtins__\"]", var_name),
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
    fn test_builtins(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
