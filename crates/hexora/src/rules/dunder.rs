use crate::audit::helpers::string_from_expr;
use crate::audit::resolver::matches_builtin_functions;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
use crate::indexer::index::NodeIndexer;
use crate::indexer::taint::TaintKind;
use crate::rules::exec::{get_call_suspicious_taint, is_code_exec, is_shell_command};
use once_cell::sync::Lazy;
use ruff_python_ast as ast;
use ruff_python_ast::Expr;

static IGNORED_DUNDER_IMPORTS: Lazy<&[&str]> =
    Lazy::new(|| &["typing", "pkg_resources", "pkgutil"]);

fn get_import_name(call: &ast::ExprCall, indexer: &NodeIndexer) -> Option<String> {
    call.arguments
        .args
        .first()
        .and_then(|expr| string_from_expr(expr, indexer))
}

fn get_dunder_import(call: &ast::ExprCall, indexer: &NodeIndexer) -> Option<String> {
    let Expr::Name(name_expr) = &*call.func else {
        return None;
    };

    if name_expr.id.as_str() != "__import__" {
        return None;
    }

    let imported_module = get_import_name(call, indexer)?;
    if IGNORED_DUNDER_IMPORTS.contains(&imported_module.as_str()) {
        return None;
    }

    Some(imported_module)
}

fn push_dunder_report(
    checker: &mut Checker,
    call: &ast::ExprCall,
    func_call: &[&str],
    is_shell: bool,
    via_getattr: bool,
) {
    let suspicious_taint = get_call_suspicious_taint(checker, call);
    let execution_type = if is_shell { "shell command" } else { "code" };
    let via = if via_getattr {
        "via getattr(__import__(..), ..)"
    } else {
        "via __import__"
    };

    let (rule, description) = if let Some(taint) = suspicious_taint {
        let rule = if is_shell {
            Rule::ObfuscatedDunderShellExec
        } else {
            Rule::ObfuscatedDunderCodeExec
        };
        let desc = match taint {
            TaintKind::Decoded | TaintKind::Deobfuscated => {
                format!("Execution of an obfuscated {} {}.", execution_type, via)
            }
            TaintKind::NetworkSourced => {
                format!(
                    "Execution of {} from network-sourced data {}.",
                    execution_type, via
                )
            }
            TaintKind::FileSourced => {
                format!(
                    "Execution of {} from file-sourced data {}.",
                    execution_type, via
                )
            }
            TaintKind::Fingerprinting => {
                format!(
                    "Execution of {} with system fingerprinting data {}.",
                    execution_type, via
                )
            }
            TaintKind::EnvVariables => {
                format!(
                    "Execution of {} with environment variables {}.",
                    execution_type, via
                )
            }
            _ => format!("Execution of an obfuscated {} {}.", execution_type, via),
        };
        (rule, desc)
    } else {
        let rule = if is_shell {
            Rule::DunderShellExec
        } else {
            Rule::DunderCodeExec
        };
        let desc = format!("Execution of an unwanted {} {}.", execution_type, via);
        (rule, desc)
    };

    let confidence = if via_getattr || !is_shell {
        AuditConfidence::VeryHigh
    } else {
        AuditConfidence::High
    };

    checker.audit_results.push(AuditItem {
        label: func_call.join("."),
        rule,
        description,
        confidence,
        location: Some(call.range),
    });
}

fn check_dunder_attribute_call(checker: &mut Checker, call: &ast::ExprCall) {
    // Pattern: __import__(module_expr).name(...)
    if let Expr::Attribute(attr) = &*call.func
        && let Expr::Call(attr_call) = &*attr.value
        && let Some(dunder_import) = get_dunder_import(attr_call, &checker.indexer)
    {
        let name = attr.attr.as_str();
        let func_call: &[&str] = &[&dunder_import, name];

        if is_shell_command(func_call) {
            push_dunder_report(checker, call, func_call, true, false);
        } else if is_code_exec(func_call) {
            push_dunder_report(checker, call, func_call, false, false);
        }
    }
}

fn check_dunder_getattr_call(checker: &mut Checker, call: &ast::ExprCall) {
    // Pattern: getattr(__import__(module_expr), name_expr)(...)
    let Expr::Call(getattr_call) = &*call.func else {
        return;
    };

    if matches_builtin_functions(checker, &getattr_call.func, &["getattr"]).is_none() {
        return;
    }

    let args = &getattr_call.arguments.args;
    if args.len() < 2 {
        return;
    }

    let base_obj = &args[0];
    let name_expr = &args[1];

    let Expr::Call(import_call) = base_obj else {
        return;
    };

    if let Some(module_name) = get_dunder_import(import_call, &checker.indexer)
        && let Some(attr_name) = string_from_expr(name_expr, &checker.indexer)
    {
        let func_call: [&str; 2] = [&module_name, &attr_name];

        if is_shell_command(&func_call) {
            push_dunder_report(checker, call, &func_call, true, true);
        } else if is_code_exec(&func_call) {
            push_dunder_report(checker, call, &func_call, false, true);
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
    #[test_case("dunder_01.py", Rule::ObfuscatedDunderCodeExec, vec!["builtins.exec", "builtins.eval"])]
    #[test_case("dunder_01.py", Rule::ObfuscatedDunderShellExec, vec!["subprocess.call", "os.system"])]
    #[test_case("dunder_02.py", Rule::ObfuscatedDunderCodeExec, vec!["builtins.exec", "builtins.exec", "builtins.eval", "builtins.eval", "builtins.eval", "builtins.eval"])]
    #[test_case("dunder_03.py", Rule::DunderImport, vec!["__import__(\"sys\")"])]
    #[test_case("exec_03.py", Rule::ObfuscatedDunderShellExec, vec!["os.system",])]
    #[test_case("exec_03.py", Rule::ObfuscatedDunderCodeExec, vec!["builtins.exec"])]
    fn test_dunder(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
