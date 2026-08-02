use crate::checker::Checker;
use crate::result::{AuditConfidence, AuditItem, Rule};
use hexora_semantic::index::NodeIndexer;
use hexora_semantic::resolver::string_from_expr;
use once_cell::sync::Lazy;
use ruff_python_ast as ast;
use ruff_text_size::TextRange;

static IGNORED_DUNDER_IMPORTS: Lazy<&[&str]> =
    Lazy::new(|| &["typing", "pkg_resources", "pkgutil"]);

fn get_import_name(call: &ast::ExprCall, indexer: &NodeIndexer) -> Option<String> {
    call.arguments
        .args
        .first()
        .and_then(|expr| string_from_expr(expr, indexer))
}

fn get_dunder_import(call: &ast::ExprCall, indexer: &NodeIndexer) -> Option<String> {
    let qn = indexer.resolve_qualified_name(&call.func)?;
    if !qn.is_import_call() {
        return None;
    }

    let imported_module = get_import_name(call, indexer)?;
    if IGNORED_DUNDER_IMPORTS.contains(&imported_module.as_str()) {
        return None;
    }

    Some(imported_module)
}

/// Emit DunderImport findings for `importlib.import_module` calls recorded by the string
/// transformer during its walk, so no separate tree traversal is required.
pub(crate) fn collect_import_module_imports(imports: &[(TextRange, String)]) -> Vec<AuditItem> {
    imports
        .iter()
        .filter(|(_, name)| !IGNORED_DUNDER_IMPORTS.contains(&name.as_str()))
        .map(|(range, name)| AuditItem {
            label: format!("__import__(\"{}\")", name),
            rule: Rule::DunderImport,
            description: "Suspicious dynamic import".to_string(),
            confidence: AuditConfidence::Medium,
            location: Some(*range),
        })
        .collect()
}

pub fn dunder_import(checker: &mut Checker, call: &ast::ExprCall) {
    if let Some(name) = get_dunder_import(call, &checker.indexer) {
        checker.audit_results.push(AuditItem {
            label: format!("__import__(\"{}\")", name),
            rule: Rule::DunderImport,
            description: "Suspicious dynamic import".to_string(),
            confidence: AuditConfidence::Medium,
            location: Some(call.range),
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("dunder_01.py", Rule::DunderImport, vec!["__import__(\"builtins\")", "__import__(\"builtins\")", "__import__(\"subprocess\")", "__import__(\"os\")"])]
    #[test_case("dunder_01.py", Rule::ObfuscatedCodeExec, vec!["builtins.exec", "builtins.eval"])]
    #[test_case("dunder_01.py", Rule::ObfuscatedShellExec, vec!["subprocess.call", "os.system"])]
    #[test_case("dunder_02.py", Rule::ObfuscatedCodeExec, vec!["builtins.exec", "builtins.exec", "builtins.eval", "builtins.eval", "builtins.eval", "builtins.eval"])]
    #[test_case("dunder_03.py", Rule::DunderImport, vec!["__import__(\"sys\")"])]
    #[test_case("exec_03.py", Rule::ObfuscatedShellExec, vec!["os.system", "os.system"])]
    #[test_case("exec_03.py", Rule::ObfuscatedCodeExec, vec!["builtins.exec", "builtins.exec"])]
    #[test_case("exec_03.py", Rule::CodeExec, vec!["subprocess.run"])]
    fn test_dunder(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }

    #[test]
    fn test_builtins_dunder_import() {
        let source = r#"import builtins
builtins.__import__("os")"#;
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::DunderImport)
            .map(|item| item.label)
            .collect();
        assert_eq!(matches, vec!["__import__(\"os\")"]);
    }

    #[test]
    fn test_importlib_import_module() {
        let source = r#"import importlib
importlib.import_module("os")"#;
        let result = crate::pipeline::audit_source(source, None).unwrap();
        let matches: Vec<_> = result
            .into_iter()
            .filter(|item| item.rule == Rule::DunderImport)
            .map(|item| item.label)
            .collect();
        assert_eq!(matches, vec!["__import__(\"os\")"]);
    }
}
