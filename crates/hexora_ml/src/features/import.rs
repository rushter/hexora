use crate::schema::FeatureRecord;
use hexora_semantic::analysis::AnalyzedSource;
use hexora_semantic::scope::BindingKind;
use std::collections::HashSet;

pub(crate) fn extract_import_features(
    record: &mut FeatureRecord,
    analyzed: &AnalyzedSource<'_, '_>,
) {
    let mut import_roots = HashSet::new();
    let mut builtin_globals = HashSet::new();
    let mut builtin_module_calls = HashSet::new();

    for (name, binding) in analyzed.indexer.bindings() {
        match binding.kind {
            BindingKind::Import => {
                if let Some(root) = binding
                    .imported_path
                    .as_ref()
                    .and_then(|segments| segments.first())
                    .map(|segment| segment.as_str())
                {
                    import_roots.insert(root.to_string());
                }
            }
            BindingKind::Builtin => {
                builtin_globals.insert(name.to_string());
            }
            _ => {}
        }
    }

    for qn in analyzed.indexer.model.call_qualified_names.values() {
        if let Some(first) = qn.first() {
            if first == "builtins" || first == "__builtins__" {
                if let Some(last) = qn.last() {
                    builtin_module_calls.insert(last.to_string());
                }
            }
        }
    }

    record.insert("import.unique_roots", import_roots.len() as f64);
    for root in import_roots {
        record.set_flag(format!("import.module.{root}"));
    }

    for builtin in builtin_globals {
        record.set_flag(format!("builtin.global.{builtin}"));
    }
    for builtin in builtin_module_calls {
        record.set_flag(format!("builtin.import.{builtin}"));
    }
}
