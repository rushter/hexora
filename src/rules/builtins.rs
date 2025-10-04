use crate::audit::helpers::string_from_expr;
use crate::audit::resolver::matches_builtin_functions;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;

use crate::rules::exec::is_chained_with_base64_call;
use ruff_python_ast as ast;
use ruff_python_ast::Expr;

const EVAL_EXEC: [&str; 2] = ["eval", "exec"];
const VARS_FUNCTIONS: [&str; 3] = ["globals", "locals", "vars"];
const BUILTINS_MODULE: [&str; 2] = ["__builtins__", "builtins"];

#[inline]
fn is_eval_or_exec(name: &str) -> bool {
    EVAL_EXEC.contains(&name)
}

fn push_exec_report(checker: &mut Checker, call: &ast::ExprCall, label: String) {
    let is_obf = is_chained_with_base64_call(checker, call);
    let (rule, description) = if is_obf {
        (
            Rule::ObfuscatedCodeExec,
            "Execution of obfuscated code".to_string(),
        )
    } else {
        (
            Rule::CodeExec,
            "Possible execution of unwanted code".to_string(),
        )
    };
    checker.audit_results.push(AuditItem {
        label,
        rule,
        description,
        confidence: AuditConfidence::VeryHigh,
        location: Some(call.range),
    });
}

fn contains_builtins_name(checker: &Checker, expr: &ast::Expr) -> Option<(String, String)> {
    let Expr::Subscript(ast::ExprSubscript { value, slice, .. }) = expr else {
        return None;
    };
    let Expr::Call(call) = value.as_ref() else {
        return None;
    };

    let var_name = matches_builtin_functions(checker, &call.func, &VARS_FUNCTIONS)?;
    let key = string_from_expr(slice, &checker.indexer)?;

    BUILTINS_MODULE
        .contains(&key.as_str())
        .then_some((var_name, key))
}

fn contains_sys_modules_builtins(checker: &Checker, expr: &ast::Expr) -> Option<String> {
    // sys.modules["__builtins__" or "builtins"]
    let Expr::Subscript(ast::ExprSubscript { value, slice, .. }) = expr else {
        return None;
    };

    let qn = checker.indexer.resolve_qualified_name(value.as_ref())?;
    if qn.segments() != ["sys", "modules"] {
        return None;
    }

    let key = string_from_expr(slice, &checker.indexer)?;
    BUILTINS_MODULE.contains(&key.as_str()).then_some(key)
}

fn contains_importlib_builtins_call(checker: &Checker, expr: &ast::Expr) -> Option<String> {
    // importlib.import_module("builtins" or "__builtins__")
    let Expr::Call(call) = expr else { return None };

    let qn = checker.indexer.resolve_qualified_name(&call.func)?;
    if qn.segments() != ["importlib", "import_module"] {
        return None;
    }

    let first_arg = call.arguments.args.first()?;
    let key = string_from_expr(first_arg, &checker.indexer)?;

    BUILTINS_MODULE.contains(&key.as_str()).then_some(key)
}

pub fn check_builtins(checker: &mut Checker, call: &ast::ExprCall) {
    // __builtins__.eval/exec(...)
    if let Expr::Attribute(attr) = &*call.func
        && let Expr::Name(name_expr) = &*attr.value
        && name_expr.id.as_str() == "__builtins__"
    {
        let name = attr.attr.as_str();
        if is_eval_or_exec(name) {
            push_exec_report(checker, call, format!("__builtins__.{}", name));
            return;
        }
    }

    // importlib.import_module("__builtins__" or "builtins").eval/exec(...)
    if let Expr::Attribute(attr) = &*call.func
        && let Some(key) = contains_importlib_builtins_call(checker, &attr.value)
    {
        let name = attr.attr.as_str();
        if is_eval_or_exec(name) {
            push_exec_report(
                checker,
                call,
                format!("importlib.import_module(\"{}\").{}", key, name),
            );
            return;
        }
    }

    // getattr(__builtins__, "eval"/"exec")(...)
    if let Expr::Call(getattr_call) = &*call.func {
        let is_getattr = matches_builtin_functions(checker, &getattr_call.func, &["getattr"]);
        if is_getattr.is_some() && getattr_call.arguments.args.len() >= 2 {
            let base_obj = &getattr_call.arguments.args[0];
            let attr_name_expr = &getattr_call.arguments.args[1];
            if let Expr::Name(base_name) = base_obj
                && base_name.id.as_str() == "__builtins__"
                && let Some(attr_name) = string_from_expr(attr_name_expr, &checker.indexer)
                && is_eval_or_exec(&attr_name)
            {
                push_exec_report(checker, call, format!("__builtins__.{}", attr_name));
                return;
            }
            // getattr(sys.modules["__builtins__" or "builtins"], "eval"/"exec")(...)
            if let Some(attr_name) = string_from_expr(attr_name_expr, &checker.indexer)
                && is_eval_or_exec(&attr_name)
            {
                if let Some(key) = contains_sys_modules_builtins(checker, base_obj) {
                    push_exec_report(
                        checker,
                        call,
                        format!("sys.modules[\"{}\"].{}", key, attr_name),
                    );
                    return;
                }
                // getattr(importlib.import_module("__builtins__" or "builtins"), "eval"/"exec")(...)
                if let Some(key) = contains_importlib_builtins_call(checker, base_obj) {
                    push_exec_report(
                        checker,
                        call,
                        format!("importlib.import_module(\"{}\").{}", key, attr_name),
                    );
                    return;
                }
            }
        }
    }

    // sys.modules["__builtins__" or "builtins"].eval/exec(...)
    if let Expr::Attribute(attr) = &*call.func
        && let Some(key) = contains_sys_modules_builtins(checker, &attr.value)
    {
        let name = attr.attr.as_str();
        if is_eval_or_exec(name) {
            push_exec_report(checker, call, format!("sys.modules[\"{}\"].{}", key, name));
            return;
        }
    }

    // globals()["__builtins__" or "builtins"].eval/exec(...)
    if let Expr::Attribute(attr) = &*call.func
        && let Some((var_name, key)) = contains_builtins_name(checker, &attr.value)
    {
        let name = attr.attr.as_str();
        if is_eval_or_exec(name) {
            push_exec_report(checker, call, format!("{}[\"{}\"].{}", var_name, key, name));
            return;
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
    #[test_case("builtins_04.py", Rule::CodeExec, vec!["sys.modules[\"builtins\"].exec", "sys.modules[\"builtins\"].eval" ])]
    #[test_case("builtins_05.py", Rule::CodeExec, vec!["importlib.import_module(\"builtins\").exec", "importlib.import_module(\"builtins\").eval" ])]
    fn test_builtins(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
