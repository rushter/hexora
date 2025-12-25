use crate::indexer::resolver::string_from_expr;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use crate::indexer::checker::Checker;
use crate::indexer::index::NodeIndexer;
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
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("dunder_01.py", Rule::DunderImport, vec!["__import__(\"builtins\")", "__import__(\"builtins\")", "__import__(\"subprocess\")", "__import__(\"os\")"])]
    #[test_case("dunder_01.py", Rule::ObfuscatedCodeExec, vec!["builtins.exec", "builtins.eval"])]
    #[test_case("dunder_01.py", Rule::ObfuscatedShellExec, vec!["subprocess.call", "os.system"])]
    #[test_case("dunder_02.py", Rule::ObfuscatedCodeExec, vec!["builtins.exec", "builtins.exec", "builtins.eval", "builtins.eval", "builtins.eval", "builtins.eval"])]
    #[test_case("dunder_03.py", Rule::DunderImport, vec!["__import__(\"sys\")"])]
    #[test_case("exec_03.py", Rule::ObfuscatedShellExec, vec!["os.system", "os.system", "subprocess.run"])]
    #[test_case("exec_03.py", Rule::ObfuscatedCodeExec, vec!["builtins.exec", "builtins.exec"])]
    fn test_dunder(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }
}
