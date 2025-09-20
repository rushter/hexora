use crate::audit::helpers::string_from_expr;
use crate::audit::resolver::matches_builtin_functions;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
use crate::indexer::index::NodeIndexer;
use crate::rules::exec::{is_chained_with_base64_call, is_code_exec, is_shell_command};
use ruff_python_ast as ast;
use ruff_python_ast::Expr;

fn get_import_name(call: &ast::ExprCall, indexer: &NodeIndexer) -> Option<String> {
    let arguments = &call.arguments.args;
    if arguments.len() != 1 {
        return None;
    }
    if let Some(expr) = &arguments.first() {
        return string_from_expr(expr, indexer);
    }
    None
}

fn get_dunder_import(call: &ast::ExprCall, indexer: &NodeIndexer) -> Option<String> {
    if let Expr::Name(name_expr) = &*call.func {
        let imported_module = get_import_name(call, indexer);
        if name_expr.id.as_str() == "__import__" && imported_module.is_some() {
            return imported_module;
        }
    }
    None
}

fn check_dunder_attribute_call(checker: &mut Checker, call: &ast::ExprCall) {
    if let Expr::Attribute(attr) = &*call.func
        && let Expr::Call(attr_call) = &*attr.value
        && let Some(dunder_import) = get_dunder_import(attr_call, &checker.indexer)
    {
        let name = attr.attr.as_str();
        let func_call: &[&str] = &[&dunder_import, name];
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
                    confidence: AuditConfidence::VeryHigh,
                    location: Some(call.range),
                });
            } else {
                checker.audit_results.push(AuditItem {
                    label: func_call.join("."),
                    rule: Rule::DunderCodeExec,
                    description: "Execution of an unwanted code via __import__".to_string(),
                    confidence: AuditConfidence::VeryHigh,
                    location: Some(call.range),
                });
            }
        }
    }
}

fn check_dunder_getattr_call(checker: &mut Checker, call: &ast::ExprCall) {
    // Pattern: getattr(__import__(module_expr), name_expr)(...)
    if let Expr::Call(getattr_call) = &*call.func {
        let is_getattr = matches_builtin_functions(checker, &getattr_call.func, &["getattr"]);

        if is_getattr.is_none() {
            return;
        }

        if getattr_call.arguments.args.len() < 2 {
            return;
        }
        let base_obj = &getattr_call.arguments.args[0];
        let name_expr = &getattr_call.arguments.args[1];

        let dunder_module = if let Expr::Call(import_call) = base_obj {
            get_dunder_import(import_call, &checker.indexer)
        } else {
            None
        };
        if let Some(module_name) = dunder_module
            && let Some(attr_name) = string_from_expr(name_expr, &checker.indexer) {
                let func_call: [&str; 2] = [&module_name, &attr_name];
                let is_obf = is_chained_with_base64_call(checker, call);
                if is_shell_command(&func_call) {
                    checker.audit_results.push(AuditItem {
                        label: func_call.join("."),
                        rule: if is_obf { Rule::ObfuscatedDunderShellExec } else { Rule::DunderShellExec },
                        description: if is_obf {
                            "Execution of an obfuscated shell command via getattr(__import__(..), ..)".to_string()
                        } else {
                            "Execution of an unwanted shell command via getattr(__import__(..)), ..)".to_string()
                        },
                        confidence: AuditConfidence::VeryHigh,
                        location: Some(call.range),
                    });
                    return;
                }
                if is_code_exec(&func_call) {
                    checker.audit_results.push(AuditItem {
                        label: func_call.join("."),
                        rule: if is_obf {
                            Rule::ObfuscatedDunderCodeExec
                        } else {
                            Rule::DunderCodeExec
                        },
                        description: if is_obf {
                            "Execution of an obfuscated code via getattr(__import__(..), ..)"
                                .to_string()
                        } else {
                            "Execution of an unwanted code via getattr(__import__(..), ..)"
                                .to_string()
                        },
                        confidence: AuditConfidence::VeryHigh,
                        location: Some(call.range),
                    });
                }
            }
    }
}

pub fn dunder_import(checker: &mut Checker, call: &ast::ExprCall) {
    if let Some(name) = get_dunder_import(call, &checker.indexer) {
        checker.audit_results.push(AuditItem {
            label: format!("__import__(\"{}\")", name),
            rule: Rule::DunderImport,
            description: "Suspicious __import__ call".to_string(),
            confidence: AuditConfidence::Medium,
            location: Some(call.range),
        });
    }
    check_dunder_attribute_call(checker, call);
    check_dunder_getattr_call(checker, call);
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("dunder_01.py", Rule::DunderImport, vec!["__import__(\"builtins\")", "__import__(\"builtins\")", "__import__(\"subprocess\")", "__import__(\"os\")"])]
    #[test_case("dunder_01.py", Rule::DunderCodeExec, vec!["builtins.exec", "builtins.eval"])]
    #[test_case("dunder_01.py", Rule::DunderShellExec, vec!["subprocess.call", "os.system"])]
    #[test_case("dunder_02.py", Rule::DunderCodeExec, vec!["builtins.exec", "builtins.eval", "builtins.eval", "builtins.eval", "builtins.eval"])]
    #[test_case("dunder_02.py", Rule::ObfuscatedDunderCodeExec, vec!["builtins.exec"])]
    #[test_case("exec_03.py", Rule::ObfuscatedDunderShellExec, vec!["os.system",])]
    #[test_case("exec_03.py", Rule::ObfuscatedDunderCodeExec, vec!["builtins.exec"])]
    fn test_dunder(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
