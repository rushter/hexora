use crate::schema::FeatureRecord;
use hexora_semantic::analysis::AnalyzedSource;
use hexora_semantic::scope::BindingKind;
use std::collections::HashSet;

const SUSPICIOUS_PAIRS: &[(&str, &str)] = &[
    ("base64", "socket"),
    ("base64", "requests"),
    ("base64", "urllib"),
    ("base64", "smtplib"),
    ("base64", "ftplib"),
    ("os", "socket"),
    ("os", "requests"),
    ("os", "urllib"),
    ("os", "httplib"),
    ("subprocess", "socket"),
    ("subprocess", "requests"),
    ("os", "base64"),
    ("subprocess", "base64"),
    ("ctypes", "base64"),
    ("ctypes", "socket"),
    ("ctypes", "requests"),
    ("subprocess", "smtplib"),
    ("os", "smtplib"),
    ("os", "ftplib"),
    ("winreg", "os"),
    ("winreg", "subprocess"),
    ("cryptography", "os"),
    ("crypto", "os"),
    ("cryptography", "subprocess"),
    ("crypto", "subprocess"),
    ("pathlib", "requests"),
    ("pathlib", "urllib"),
];

const SUSPICIOUS_TRIPLES: &[(&str, &str, &str)] = &[
    ("base64", "socket", "os"),
    ("base64", "requests", "subprocess"),
    ("ctypes", "socket", "base64"),
    ("os", "base64", "smtplib"),
    ("os", "socket", "subprocess"),
    ("ctypes", "os", "subprocess"),
    ("base64", "os", "subprocess"),
];

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

    let mut suspicious_pairs = 0usize;
    for &(a, b) in SUSPICIOUS_PAIRS {
        if import_roots.contains(a) && import_roots.contains(b) {
            suspicious_pairs += 1;
        }
    }
    record.insert(
        "import.suspicious_pair_count",
        suspicious_pairs as f64,
    );

    let mut suspicious_triples = 0usize;
    for &(a, b, c) in SUSPICIOUS_TRIPLES {
        if import_roots.contains(a) && import_roots.contains(b) && import_roots.contains(c) {
            suspicious_triples += 1;
        }
    }
    record.insert(
        "import.suspicious_triple_count",
        suspicious_triples as f64,
    );

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
