use crate::audit::helpers::string_from_expr;
use crate::audit::resolver::matches_builtin_functions;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;

use crate::indexer::taint::TaintKind;
use crate::rules::exec::get_call_suspicious_taint;
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
    let suspicious_taint = get_call_suspicious_taint(checker, call);

    let (rule, description) = if let Some(taint) = suspicious_taint {
        let desc = match taint {
            TaintKind::Decoded | TaintKind::Deobfuscated => "Execution of obfuscated code.",
            TaintKind::NetworkSourced => "Execution of code from network-sourced data.",
            TaintKind::FileSourced => "Execution of code from file-sourced data.",
            TaintKind::Fingerprinting => "Execution of code with system fingerprinting data.",
            TaintKind::EnvVariables => "Execution of code with environment variables.",
            _ => "Execution of obfuscated code.",
        };
        (Rule::ObfuscatedCodeExec, desc.to_string())
    } else {
        (
            Rule::CodeExec,
            "Possible execution of unwanted code.".to_string(),
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

    let qn = checker.indexer.resolve_qualified_name(value)?;
    let segments = qn.segments();
    if segments.len() != 1 || !VARS_FUNCTIONS.contains(&segments[0]) {
        return None;
    }
    let var_name = segments[0].to_string();

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

fn resolve_builtins_subscript(checker: &Checker, expr: &Expr) -> Option<String> {
    if let Some(key) = contains_sys_modules_builtins(checker, expr) {
        return Some(format!("sys.modules[\"{}\"]", key));
    }
    if let Some((var_name, key)) = contains_builtins_name(checker, expr) {
        return Some(format!("{}[\"{}\"]", var_name, key));
    }
    None
}

pub fn check_builtins(checker: &mut Checker, call: &ast::ExprCall) {
    let func = &*call.func;

    // getattr(builtins_module, "eval"/"exec")(...)
    if let Expr::Call(getattr_call) = func
        && matches_builtin_functions(checker, &getattr_call.func, &["getattr"]).is_some()
        && getattr_call.arguments.args.len() >= 2
    {
        let base_obj = &getattr_call.arguments.args[0];
        let attr_expr = &getattr_call.arguments.args[1];

        if let Some(attr_name) = string_from_expr(attr_expr, &checker.indexer)
            && is_eval_or_exec(&attr_name)
        {
            let label = if let Some(qn) = checker.indexer.resolve_qualified_name(base_obj)
                && qn.segments().len() == 1
                && BUILTINS_MODULE.contains(&qn.segments()[0])
            {
                Some(qn.as_str().to_string())
            } else {
                resolve_builtins_subscript(checker, base_obj)
            };

            if let Some(label) = label {
                push_exec_report(checker, call, format!("{}.{}", label, attr_name));
                return;
            }
        }
    }

    //  builtins_module.eval/exec(...)
    if let Expr::Attribute(attr) = func
        && is_eval_or_exec(attr.attr.as_str())
        && let Some(label) = resolve_builtins_subscript(checker, &attr.value)
    {
        push_exec_report(checker, call, format!("{}.{}", label, attr.attr.as_str()));
        return;
    }

    // globals()["builtins"](...)
    if let Some((var_name, key)) = contains_builtins_name(checker, func) {
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
    #[test_case("builtins_02.py", Rule::ObfuscatedCodeExec, vec!["__builtins__.eval", "__builtins__.eval" ])]
    #[test_case("builtins_03.py", Rule::CodeExec, vec!["globals[\"builtins\"].eval" ])]
    #[test_case("builtins_04.py", Rule::ObfuscatedCodeExec, vec!["builtins.exec", "builtins.eval" ])]
    #[test_case("builtins_05.py", Rule::ObfuscatedCodeExec, vec!["builtins.exec", "builtins.eval" ])]
    fn test_builtins(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
