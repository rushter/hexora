use crate::audit::parse::Checker;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::rules::exec::{is_chained_with_base64_call, is_code_exec, is_shell_command};
use ruff_python_ast as ast;
use ruff_python_ast::Expr;

fn get_import_name(call: &ast::ExprCall) -> Option<&str> {
    let arguments = &call.arguments.args;
    if arguments.len() != 1 {
        return None;
    }
    if let Some(Expr::StringLiteral(name)) = &arguments.first() {
        return Some(name.value.to_str());
    }
    None
}
fn get_dunder_import(call: &ast::ExprCall) -> Option<&str> {
    if let Expr::Name(name_expr) = &*call.func {
        let imported_module = get_import_name(call);
        if name_expr.id.as_str() == "__import__" && imported_module.is_some() {
            return imported_module;
        }
    }
    None
}

fn check_dunder_attribute_call(checker: &mut Checker, call: &ast::ExprCall) {
    if let Expr::Attribute(attr) = &*call.func
        && let Expr::Call(attr_call) = &*attr.value
        && let Some(dunder_import) = get_dunder_import(attr_call)
    {
        let name = attr.attr.as_str();
        let func_call: &[&str] = &[dunder_import, name];
        if is_shell_command(func_call) {
            if is_chained_with_base64_call(checker, call) {
                checker.audit_results.push(AuditItem {
                    label: func_call.join("."),
                    rule: Rule::ObfuscatedDunderShellExec,
                    description: "Execution of an obfuscated shell command via __import__."
                        .to_string(),
                    confidence: AuditConfidence::High,
                    location: Some(call.range),
                });
            } else {
                checker.audit_results.push(AuditItem {
                    label: func_call.join("."),
                    rule: Rule::DunderShellExec,
                    description: "Execution of an unwanted shell command via __import__."
                        .to_string(),
                    confidence: AuditConfidence::High,
                    location: Some(call.range),
                });
            }
        };
        if is_code_exec(func_call) {
            if is_chained_with_base64_call(checker, call) {
                checker.audit_results.push(AuditItem {
                    label: func_call.join("."),
                    rule: Rule::ObfuscatedDunderCodeExec,
                    description: "Execution of an obfuscated code via __import__".to_string(),
                    confidence: AuditConfidence::High,
                    location: Some(call.range),
                });
            } else {
                checker.audit_results.push(AuditItem {
                    label: func_call.join("."),
                    rule: Rule::DunderCodeExec,
                    description: "Execution of an unwanted code via __import__".to_string(),
                    confidence: AuditConfidence::High,
                    location: Some(call.range),
                });
            }
        }
    }
}

pub fn dunder_import(checker: &mut Checker, call: &ast::ExprCall) {
    if let Some(name) = get_dunder_import(call) {
        checker.audit_results.push(AuditItem {
            label: format!("__import__(\"{}\")", name),
            rule: Rule::DunderImport,
            description: "Suspicious __import__ call".to_string(),
            confidence: AuditConfidence::Medium,
            location: Some(call.range),
        });
    } else {
        check_dunder_attribute_call(checker, call);
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("dunder_01.py", Rule::DunderImport, vec!["__import__(\"builtins\")", "__import__(\"builtins\")", "__import__(\"subprocess\")", "__import__(\"os\")"])]
    #[test_case("dunder_01.py", Rule::DunderCodeExec, vec!["builtins.exec", "builtins.eval"])]
    #[test_case("dunder_01.py", Rule::DunderShellExec, vec!["subprocess.call", "os.system"])]
    #[test_case("exec_03.py", Rule::ObfuscatedDunderShellExec, vec!["os.system",])]
    #[test_case("exec_03.py", Rule::ObfuscatedDunderCodeExec, vec!["builtins.exec"])]
    fn test_dunder(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
