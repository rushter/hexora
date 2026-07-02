use crate::checker::Checker;
use crate::result::{AuditConfidence, AuditItem, Rule};
use hexora_semantic::index::NodeIndexer;
use hexora_semantic::resolver::string_from_expr;
use ruff_python_ast as ast;

fn class_name_from_expr(value: &ast::Expr, indexer: &NodeIndexer) -> String {
    if let ast::Expr::Name(name) = value {
        return name.id.to_string();
    }

    string_from_expr(value, indexer).unwrap_or_else(|| "<unknown>".to_string())
}

pub(crate) fn is_install_hook_base_class(
    class_def: &ast::StmtClassDef,
    indexer: &NodeIndexer,
) -> bool {
    class_def.bases().iter().any(|base| {
        indexer.resolve_qualified_name(base).is_some_and(|qn| {
            qn.is_exact(&["setuptools", "command", "install", "install"])
                || qn.is_exact(&["distutils", "core", "Command"])
        })
    })
}

pub fn check_setup_call(checker: &mut Checker, call: &ast::ExprCall) {
    let Some(qualified_name) = checker.indexer.resolve_qualified_name(&call.func) else {
        return;
    };

    if !qualified_name.is_setup_py_setup() {
        return;
    }

    for kw in &call.arguments.keywords {
        let Some(arg_name) = kw.arg.as_ref().map(|a| a.as_str()) else {
            continue;
        };
        if arg_name != "cmdclass" {
            continue;
        }
        let ast::Expr::Dict(dict) = &kw.value else {
            continue;
        };
        for item in &dict.items {
            let Some(key_str) = item
                .key
                .as_ref()
                .and_then(|k| string_from_expr(k, &checker.indexer))
            else {
                continue;
            };
            if key_str != "install" {
                continue;
            }
            let class_name = class_name_from_expr(&item.value, &checker.indexer);

            checker.audit_results.push(AuditItem {
                label: format!("cmdclass:{}", class_name),
                rule: Rule::InstallHook,
                description: format!(
                    "Install hook via cmdclass in setuptools.setup() registering class '{}'.",
                    class_name
                ),
                confidence: AuditConfidence::High,
                location: Some(call.range),
            });
        }
    }
}

pub(crate) fn check_expr_for_install_hook(checker: &mut Checker, expr: &ast::Expr) {
    if !(checker.is_setup_py() && checker.inside_install_hook()) {
        return;
    }

    let ast::Expr::Call(call) = expr else {
        return;
    };

    if checker
        .indexer
        .resolve_qualified_name(&call.func)
        .is_some_and(|qn| qn.is_suspicious_capability())
    {
        checker.record_install_hook_suspicious();
    }
}

pub fn check_class_def(checker: &mut Checker, class_def: &ast::StmtClassDef) {
    let has_relevant_method = class_def.body.iter().any(|stmt| {
        matches!(stmt, ast::Stmt::FunctionDef(func) if func.name.as_str() == "run" || func.name.as_str() == "__init__")
    });

    if !has_relevant_method {
        return;
    }

    let (confidence, description) = if checker.install_hook_has_suspicious() {
        (
            AuditConfidence::VeryHigh,
            format!(
                "Install hook class '{}' overrides install command with potentially dangerous method.",
                class_def.name
            ),
        )
    } else {
        (
            AuditConfidence::Medium,
            format!(
                "Install hook class '{}' overrides install command.",
                class_def.name
            ),
        )
    };

    checker.audit_results.push(AuditItem {
        label: class_def.name.to_string(),
        rule: Rule::InstallHook,
        description,
        confidence,
        location: Some(class_def.range),
    });
}

#[cfg(test)]
mod tests {
    use crate::result::AuditConfidence;
    use crate::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("test_01_setup.py", vec![("CustomInstall", AuditConfidence::VeryHigh), ("cmdclass:CustomInstall", AuditConfidence::High)])]
    #[test_case("test_02_setup.py", vec![("InstallCommand", AuditConfidence::VeryHigh), ("cmdclass:InstallCommand", AuditConfidence::High)])]
    #[test_case("test_04_setup.py", vec![("PostInstallCommand", AuditConfidence::VeryHigh), ("cmdclass:PostInstallCommand", AuditConfidence::High)])]
    #[test_case("test_05_setup.py", vec![("CustomInstall", AuditConfidence::Medium), ("cmdclass:CustomInstall", AuditConfidence::High)])]
    fn test_install_hook(path: &str, expected: Vec<(&str, AuditConfidence)>) {
        let result = test_path(path).unwrap();
        let actual: Vec<(&str, AuditConfidence)> = result
            .items
            .iter()
            .filter(|r| r.rule == Rule::InstallHook)
            .map(|r| (r.label.as_str(), r.confidence))
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_benign_setup_py_no_false_positive() {
        let result = test_path("test_03_setup.py").unwrap();
        let matches: Vec<_> = result
            .items
            .iter()
            .filter(|item| item.rule == Rule::InstallHook)
            .collect();
        assert!(
            matches.is_empty(),
            "Expected no InstallHook results, got: {:?}",
            matches
        );
    }

    #[test]
    fn test_code_exec_also_fires_on_install_hook() {
        let result = test_path("test_04_setup.py").unwrap();
        let code_exec: Vec<_> = result
            .items
            .iter()
            .filter(|i| i.rule == Rule::CodeExec)
            .collect();
        assert!(
            !code_exec.is_empty(),
            "Expected CodeExec to fire on exec() in install hook"
        );
    }

    #[test]
    fn test_non_setup_py_does_not_flag_install_hook() {
        let result = test_path("install_hook_01.py").unwrap();
        let matches: Vec<_> = result
            .items
            .iter()
            .filter(|i| i.rule == Rule::InstallHook)
            .collect();
        assert!(
            matches.is_empty(),
            "Expected no InstallHook results for non-setup.py file, got: {:?}",
            matches
        );
    }

    #[test]
    fn test_setup_py_non_install_class_with_run_not_flagged() {
        let result = test_path("test_06_setup.py").unwrap();
        let matches: Vec<_> = result
            .items
            .iter()
            .filter(|i| i.rule == Rule::InstallHook)
            .collect();
        assert!(
            matches.is_empty(),
            "Expected no InstallHook results for non-install-hook class with run(), got: {:?}",
            matches
        );
    }
}
