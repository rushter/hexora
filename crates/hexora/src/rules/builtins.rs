use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
use crate::indexer::resolver::string_from_expr;

use ruff_python_ast as ast;

const BUILTINS_MODULE: [&str; 2] = ["__builtins__", "builtins"];

fn contains_builtins_name(checker: &Checker, expr: &ast::Expr) -> Option<(String, String)> {
    let ast::Expr::Subscript(ast::ExprSubscript { value, slice, .. }) = expr else {
        return None;
    };

    let qn = checker.indexer.resolve_qualified_name(value)?;
    if !qn.is_vars_function() {
        return None;
    }
    let var_name = qn.last()?.to_string();

    let key = string_from_expr(slice, &checker.indexer)?;

    BUILTINS_MODULE
        .contains(&key.as_str())
        .then_some((var_name, key))
}

pub fn check_builtins(checker: &mut Checker, call: &ast::ExprCall) {
    let func = &*call.func;

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

    #[test_case("builtins_01.py", Rule::ObfuscatedCodeExec, vec!["__builtins__.eval" ])]
    #[test_case("builtins_02.py", Rule::ObfuscatedCodeExec, vec!["__builtins__.eval", "__builtins__.eval" ])]
    #[test_case("builtins_03.py", Rule::ObfuscatedCodeExec, vec!["builtins.eval" ])]
    #[test_case("builtins_04.py", Rule::ObfuscatedCodeExec, vec!["builtins.exec", "builtins.eval" ])]
    #[test_case("builtins_05.py", Rule::ObfuscatedCodeExec, vec!["builtins.exec", "builtins.eval" ])]
    fn test_builtins(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
