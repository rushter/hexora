use crate::audit::helpers::get_expression_range;
use crate::audit::parse::Checker;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use once_cell::sync::Lazy;
use ruff_python_ast as ast;
use ruff_python_ast::Identifier;

static SUSPICIOUS_SUBSTRINGS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "shellcode",
        "payload",
        "reverse_shell",
        "exploit",
        "webshell",
    ]
});

fn is_suspicious_variable(variable: &str) -> bool {
    SUSPICIOUS_SUBSTRINGS
        .iter()
        .any(|&substr| variable.to_lowercase().contains(substr))
}

#[inline]
fn get_target_names(target: &ast::Expr) -> Option<Vec<String>> {
    match target {
        ast::Expr::Name(ast::ExprName { id, .. }) => Some(vec![id.to_string()]),
        ast::Expr::Subscript(ast::ExprSubscript { slice, .. }) => match slice.as_ref() {
            ast::Expr::StringLiteral(ast::ExprStringLiteral { value, .. }) => {
                Some(vec![value.to_string()])
            }
            _ => None,
        },
        ast::Expr::StringLiteral(ast::ExprStringLiteral { value, .. }) => {
            Some(vec![value.to_string()])
        }
        ast::Expr::Attribute(ast::ExprAttribute { attr, .. }) => Some(vec![attr.to_string()]),
        ast::Expr::Tuple(ast::ExprTuple { elts, .. })
        | ast::Expr::List(ast::ExprList { elts, .. }) => {
            let mut result = vec![];
            for elt in elts {
                if let Some(names) = get_target_names(elt) {
                    result.extend(names);
                }
            }
            Some(result)
        }
        _ => None,
    }
}

pub fn suspicious_variable(checker: &mut Checker, targets: &[ast::Expr]) {
    for target in targets {
        let target_name = get_target_names(target);
        if let Some(names) = target_name {
            for name in names {
                if !is_suspicious_variable(&name) {
                    continue;
                }
                let description = format!("Suspicious variable name: {}", name);
                checker.audit_results.push(AuditItem {
                    label: name,
                    rule: Rule::SuspiciousVariable,
                    description,
                    confidence: AuditConfidence::Medium,
                    location: Some(get_expression_range(target)),
                })
            }
        }
    }
}

pub fn suspicious_function_name(checker: &mut Checker, name: &Identifier) {
    if !is_suspicious_variable(name) {
        return;
    }
    let description = format!("Suspicious function name: {}", name);
    checker.audit_results.push(AuditItem {
        label: name.id.to_string(),
        rule: Rule::SuspiciousFunctionName,
        description,
        confidence: AuditConfidence::Medium,
        location: Some(name.range),
    });
}

pub fn suspicious_function_parameter(checker: &mut Checker, name: &Identifier) {
    if !is_suspicious_variable(name) {
        return;
    }
    let description = format!("Suspicious function parameter: {}", name);
    checker.audit_results.push(AuditItem {
        label: name.id.to_string(),
        rule: Rule::SuspiciousParameterName,
        description,
        confidence: AuditConfidence::Medium,
        location: Some(name.range),
    });
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("identifier_01.py", Rule::SuspiciousVariable, vec!["payload", "shellCODE_01", "shellcode_02", "shellcode_03", "shellcode_04"])]
    #[test_case("identifier_01.py", Rule::SuspiciousFunctionName, vec!["PAYLOAD_generator"])]
    #[test_case("identifier_01.py", Rule::SuspiciousParameterName, vec!["shellcode_data"])]
    fn test_identifier(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
