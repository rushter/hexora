use crate::schema::FeatureRecord;
use hexora_semantic::analysis::AnalyzedSource;
use hexora_semantic::model::Transformation;
use hexora_semantic::taint::TaintKind;
use std::collections::HashSet;

pub(crate) fn extract_semantic_features(
    record: &mut FeatureRecord,
    analyzed: &AnalyzedSource<'_, '_>,
) {
    let taint_map = analyzed.indexer.model.taint_map.borrow();
    record.insert("semantic.tainted_nodes", taint_map.len() as f64);
    let mut multi_taint = 0usize;
    let mut total_taint_kinds = 0usize;
    for taints in taint_map.values() {
        if taints.len() >= 2 {
            multi_taint += 1;
        }
        total_taint_kinds += taints.len();
        for taint in taints {
            record.add(format!("taint.{}", taint_name(*taint)), 1.0);
        }
    }
    let tainted_count = taint_map.len();
    record.insert("semantic.multi_taint_nodes", multi_taint as f64);
    record.insert(
        "semantic.taint_richness",
        if tainted_count > 0 {
            total_taint_kinds as f64 / tainted_count as f64
        } else {
            0.0
        },
    );

    let decoded_nodes = analyzed.indexer.model.decoded_nodes.borrow();
    record.insert("semantic.decoded_nodes", decoded_nodes.len() as f64);
    let mut seen_transforms = HashSet::new();
    for transformation in decoded_nodes.values() {
        seen_transforms.insert(transformation_name(*transformation));
        record.add(
            format!("transform.{}", transformation_name(*transformation)),
            1.0,
        );
    }
    record.insert("semantic.encoding_diversity", seen_transforms.len() as f64);

    record.insert(
        "semantic.qualified_calls",
        analyzed.indexer.model.call_qualified_names.len() as f64,
    );
    for qn in analyzed.indexer.model.call_qualified_names.values() {
        if qn.is_shell_command() {
            record.add("call.shell_exec", 1.0);
        }
        if qn.is_code_exec() {
            record.add("call.code_exec", 1.0);
        }
        if qn.is_exfiltration_sink() {
            record.add("call.exfiltration_sink", 1.0);
        }
        if qn.is_download_request() {
            record.add("call.download_request", 1.0);
        }
        if qn.is_env_access() {
            record.add("call.env_access", 1.0);
        }
        if qn.is_suspicious_builtin() {
            record.add("call.suspicious_builtin", 1.0);
        }
        if qn.is_import_call() {
            record.add("call.import_call", 1.0);
        }
        if qn.is_getattr()
            || qn.is_eval()
            || qn.is_import_call()
            || matches!(qn.segments_slice(), [n] if matches!(n.as_str(), "exec" | "compile"))
            || matches!(qn.segments_slice(), [p, n]
                if matches!(p.as_str(), "builtins" | "__builtins__")
                && matches!(n.as_str(), "exec" | "compile"))
        {
            record.add("call.dynamic_count", 1.0);
        }
        if qn.is_stdlib_call() {
            record.add(format!("call.{}", qn.as_str()), 1.0);
        }
    }
}

pub(crate) fn taint_name(taint: TaintKind) -> String {
    match taint {
        TaintKind::Literal => "literal".to_string(),
        TaintKind::Decoded => "decoded".to_string(),
        TaintKind::Deobfuscated => "deobfuscated".to_string(),
        TaintKind::FileSourced => "file_sourced".to_string(),
        TaintKind::NetworkSourced => "network_sourced".to_string(),
        TaintKind::Fingerprinting => "fingerprinting".to_string(),
        TaintKind::EnvVariables => "env_variables".to_string(),
        TaintKind::InternalParameter(index) => format!("internal_parameter_{index}"),
    }
}

pub(crate) fn transformation_name(transformation: Transformation) -> &'static str {
    match transformation {
        Transformation::Base64 => "base64",
        Transformation::Hex => "hex",
        Transformation::Concat => "concat",
        Transformation::Join => "join",
        Transformation::Subscript => "subscript",
        Transformation::FString => "fstring",
        Transformation::Other => "other",
    }
}
