use crate::schema::FeatureRecord;
use hexora_semantic::analysis::AnalyzedSource;
use hexora_semantic::model::Transformation;
use hexora_semantic::name::QualifiedName;
use hexora_semantic::taint::TaintKind;
use rustc_hash::FxHashMap;

type PredicateEntry = (fn(&QualifiedName) -> bool, &'static str);

const TAINT_FEATURE_NAMES: [&str; 7] = [
    "taint.literal",
    "taint.decoded",
    "taint.deobfuscated",
    "taint.file_sourced",
    "taint.network_sourced",
    "taint.fingerprinting",
    "taint.env_variables",
];

const TRANSFORM_FEATURE_NAMES: [&str; 7] = [
    "transform.base64",
    "transform.hex",
    "transform.concat",
    "transform.join",
    "transform.subscript",
    "transform.fstring",
    "transform.other",
];

fn taint_kind_index(taint: TaintKind) -> Option<usize> {
    match taint {
        TaintKind::Literal => Some(0),
        TaintKind::Decoded => Some(1),
        TaintKind::Deobfuscated => Some(2),
        TaintKind::FileSourced => Some(3),
        TaintKind::NetworkSourced => Some(4),
        TaintKind::Fingerprinting => Some(5),
        TaintKind::EnvVariables => Some(6),
        TaintKind::InternalParameter(_) => None,
    }
}

fn transformation_index(transformation: Transformation) -> usize {
    match transformation {
        Transformation::Base64 => 0,
        Transformation::Hex => 1,
        Transformation::Concat => 2,
        Transformation::Join => 3,
        Transformation::Subscript => 4,
        Transformation::FString => 5,
        Transformation::Other => 6,
    }
}

pub(crate) fn extract_semantic_features(
    record: &mut FeatureRecord,
    analyzed: &AnalyzedSource<'_, '_>,
) {
    let taint_map = analyzed.indexer.model.taint_map.borrow();
    let mut taint_counts = [0usize; 7];
    let mut param_taint_counts = FxHashMap::default();
    let mut multi_taint = 0usize;
    let mut total_taint_kinds = 0usize;
    for taints in taint_map.values() {
        if taints.len() >= 2 {
            multi_taint += 1;
        }
        total_taint_kinds += taints.len();
        for taint in taints {
            if let Some(index) = taint_kind_index(*taint) {
                taint_counts[index] += 1;
            } else if let TaintKind::InternalParameter(index) = *taint {
                *param_taint_counts.entry(index).or_insert(0) += 1;
            }
        }
    }
    let tainted_count = taint_map.len();
    record.insert("semantic.tainted_nodes", tainted_count as f64);
    record.insert("semantic.multi_taint_nodes", multi_taint as f64);
    record.insert(
        "semantic.taint_richness",
        if tainted_count > 0 {
            total_taint_kinds as f64 / tainted_count as f64
        } else {
            0.0
        },
    );
    for (index, &count) in taint_counts.iter().enumerate() {
        if count > 0 {
            record.add(TAINT_FEATURE_NAMES[index], count as f64);
        }
    }
    for (index, count) in param_taint_counts {
        record.add(format!("taint.internal_parameter_{index}"), count as f64);
    }

    let decoded_nodes = analyzed.indexer.model.decoded_nodes.borrow();
    let mut transform_counts = [0usize; 7];
    for transformation in decoded_nodes.values() {
        transform_counts[transformation_index(*transformation)] += 1;
    }
    record.insert("semantic.decoded_nodes", decoded_nodes.len() as f64);
    let mut encoding_diversity = 0usize;
    for (index, &count) in transform_counts.iter().enumerate() {
        if count > 0 {
            encoding_diversity += 1;
            record.add(TRANSFORM_FEATURE_NAMES[index], count as f64);
        }
    }
    record.insert("semantic.encoding_diversity", encoding_diversity as f64);

    record.insert(
        "semantic.qualified_calls",
        analyzed.indexer.model.call_qualified_names.len() as f64,
    );
    const SIMPLE_PREDICATES: &[PredicateEntry] = &[
        (QualifiedName::is_shell_command, "call.shell_exec"),
        (QualifiedName::is_code_exec, "call.code_exec"),
        (
            QualifiedName::is_exfiltration_sink,
            "call.exfiltration_sink",
        ),
        (QualifiedName::is_download_request, "call.download_request"),
        (QualifiedName::is_env_access, "call.env_access"),
        (
            QualifiedName::is_suspicious_builtin,
            "call.suspicious_builtin",
        ),
        (QualifiedName::is_import_call, "call.import_call"),
        (QualifiedName::is_indirect_exec, "call.indirect_exec"),
        (QualifiedName::is_os_fingerprint, "call.os_fingerprint"),
        (QualifiedName::is_clipboard_read, "call.clipboard_read"),
        (
            QualifiedName::is_screenshot_capture,
            "call.screenshot_capture",
        ),
        (QualifiedName::is_dll_injection, "call.dll_injection"),
        (QualifiedName::is_pathlib_write, "call.pathlib_write"),
        (QualifiedName::is_module_registry, "call.module_registry"),
        (
            QualifiedName::is_io_resource_constructor,
            "call.io_resource_ctor",
        ),
        (QualifiedName::is_vars_function, "call.vars_function"),
    ];
    let mut predicate_counts = [0usize; SIMPLE_PREDICATES.len()];
    let mut dynamic_count = 0usize;
    let mut stdlib_calls = FxHashMap::default();
    for qn in analyzed.indexer.model.call_qualified_names.values() {
        for (i, (pred, _)) in SIMPLE_PREDICATES.iter().enumerate() {
            if pred(qn) {
                predicate_counts[i] += 1;
            }
        }
        if qn.is_getattr()
            || qn.is_eval()
            || qn.is_import_call()
            || matches!(qn.segments_slice(), [n] if matches!(n.as_str(), "exec" | "compile"))
            || matches!(qn.segments_slice(), [p, n]
                if matches!(p.as_str(), "builtins" | "__builtins__")
                && matches!(n.as_str(), "exec" | "compile"))
        {
            dynamic_count += 1;
        }
        if qn.is_stdlib_call() {
            *stdlib_calls.entry(qn.as_str()).or_insert(0) += 1;
        }
    }
    for (i, &count) in predicate_counts.iter().enumerate() {
        if count > 0 {
            record.add(SIMPLE_PREDICATES[i].1, count as f64);
        }
    }
    if dynamic_count > 0 {
        record.add("call.dynamic_count", dynamic_count as f64);
    }
    for (name, count) in stdlib_calls {
        record.add(format!("call.{name}"), count as f64);
    }
}
