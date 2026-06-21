use crate::schema::FeatureRecord;
use hexora_semantic::analysis::AnalyzedSource;
use hexora_semantic::model::Transformation;
use hexora_semantic::name::QualifiedName;
use hexora_semantic::taint::TaintKind;
use std::borrow::Cow;
use std::collections::HashSet;

type PredicateEntry = (fn(&QualifiedName) -> bool, &'static str);

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
    for qn in analyzed.indexer.model.call_qualified_names.values() {
        for (pred, name) in SIMPLE_PREDICATES {
            if pred(qn) {
                record.add(*name, 1.0);
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
            record.add("call.dynamic_count", 1.0);
        }
        if qn.is_stdlib_call() {
            record.add(format!("call.{}", qn.as_str()), 1.0);
        }
    }
}

pub(crate) fn taint_name(taint: TaintKind) -> Cow<'static, str> {
    match taint {
        TaintKind::Literal => Cow::Borrowed("literal"),
        TaintKind::Decoded => Cow::Borrowed("decoded"),
        TaintKind::Deobfuscated => Cow::Borrowed("deobfuscated"),
        TaintKind::FileSourced => Cow::Borrowed("file_sourced"),
        TaintKind::NetworkSourced => Cow::Borrowed("network_sourced"),
        TaintKind::Fingerprinting => Cow::Borrowed("fingerprinting"),
        TaintKind::EnvVariables => Cow::Borrowed("env_variables"),
        TaintKind::InternalParameter(index) => Cow::Owned(format!("internal_parameter_{index}")),
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
