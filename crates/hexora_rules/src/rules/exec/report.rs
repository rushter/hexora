use crate::checker::Checker;
use crate::pipeline::audit_source;
use crate::result::{AuditConfidence, AuditItem, Rule};
use hexora_semantic::taint::TaintKind;

use ruff_python_ast as ast;

use super::ExecKind;
use super::signals::{
    contains_dangerous_exec, contains_suspicious_exec_arguments, contains_suspicious_expr,
    get_call_suspicious_taint, get_suspicious_taint, is_aliased_code_exec_call,
    is_explicit_builtin_code_exec_call, is_plain_deobfuscated_subprocess_callable,
    is_plain_lookup_exec_source, is_plain_reflection_call_result, is_reflection_like_exec_source,
    should_cap_plain_argv_shell_exec, should_promote_exec_confidence,
};
use super::subjects::{
    PythonExecInfo, get_direct_code_exec_source, get_execution_subjects, get_python_exec_info,
};

struct ExecAnalysis<'a> {
    kind: ExecKind,
    direct_code_source: Option<&'a ast::Expr>,
    python_exec: PythonExecInfo<'a>,
    call_taint: Option<TaintKind>,
    is_highly_suspicious: bool,
    contains_dangerous_command: bool,
    has_only_plain_subjects: bool,
    should_cap_plain_shell_confidence: bool,
    direct_source_is_plain_lookup: bool,
    direct_source_is_reflection_like: bool,
    func_is_plain_reflection_call_result: bool,
    is_plain_deobfuscated_subprocess: bool,
}

impl<'a> ExecAnalysis<'a> {
    fn new(checker: &Checker<'_>, call: &'a ast::ExprCall, kind: ExecKind) -> Self {
        let direct_code_source = get_direct_code_exec_source(checker, call);
        let python_exec = get_python_exec_info(checker, call);
        let execution_subjects = get_execution_subjects(checker, call);
        let has_only_plain_subjects = execution_subjects
            .iter()
            .all(|expr| !contains_suspicious_expr(checker, expr));
        let call_taint = get_call_suspicious_taint(checker, call);
        let is_plain_deobfuscated_subprocess = call_taint == Some(TaintKind::Deobfuscated)
            && checker
                .indexer
                .resolve_qualified_name(&call.func)
                .is_some_and(|qn| qn.starts_with(&["subprocess"]))
            && is_plain_deobfuscated_subprocess_callable(checker, &call.func)
            && execution_subjects
                .iter()
                .all(|expr| !contains_suspicious_expr(checker, expr));

        Self {
            kind,
            direct_code_source,
            python_exec,
            call_taint,
            is_highly_suspicious: contains_suspicious_exec_arguments(checker, call),
            contains_dangerous_command: contains_dangerous_exec(checker, call),
            has_only_plain_subjects,
            should_cap_plain_shell_confidence: should_cap_plain_argv_shell_exec(checker, call),
            direct_source_is_plain_lookup: direct_code_source
                .is_some_and(|expr| is_plain_lookup_exec_source(checker, expr, 0)),
            direct_source_is_reflection_like: direct_code_source
                .is_some_and(|expr| is_reflection_like_exec_source(checker, expr, 0)),
            func_is_plain_reflection_call_result: is_plain_reflection_call_result(
                checker, &call.func,
            ),
            is_plain_deobfuscated_subprocess,
        }
    }

    fn is_python_code_execution(&self) -> bool {
        self.python_exec.is_python_code_execution()
    }

    fn base_kind(&self) -> ExecKind {
        if self.kind == ExecKind::Shell && !self.is_python_code_execution() {
            ExecKind::Shell
        } else {
            ExecKind::Code
        }
    }

    fn is_dangerous_shell_exec(&self) -> bool {
        self.kind == ExecKind::Shell
            && self.contains_dangerous_command
            && !self.is_python_code_execution()
    }

    fn should_cap_confidence(&self) -> bool {
        match self.kind {
            ExecKind::Shell => {
                (!self.is_python_code_execution() && self.should_cap_plain_shell_confidence)
                    || self.is_plain_deobfuscated_subprocess
            }
            ExecKind::Code => {
                self.direct_source_is_plain_lookup
                    || self.direct_source_is_reflection_like
                    || self.func_is_plain_reflection_call_result
            }
        }
    }
}

struct AuditDecision {
    rule: Rule,
    description: String,
    confidence: AuditConfidence,
}

fn get_taint_metadata(taint: TaintKind) -> (AuditConfidence, &'static str, &'static str) {
    match taint {
        TaintKind::Decoded | TaintKind::Deobfuscated => (
            AuditConfidence::High,
            "possibly obfuscated shell command",
            "possibly obfuscated code",
        ),
        TaintKind::NetworkSourced => (
            AuditConfidence::High,
            "shell command from network-sourced data",
            "code from network-sourced data",
        ),
        TaintKind::FileSourced => (
            AuditConfidence::High,
            "shell command from file-sourced data",
            "code from file-sourced data",
        ),
        TaintKind::Fingerprinting => (
            AuditConfidence::Medium,
            "shell command with system fingerprinting data",
            "code with system fingerprinting data",
        ),
        TaintKind::EnvVariables => (
            AuditConfidence::Medium,
            "shell command with environment variables",
            "code with environment variables",
        ),
        _ => (
            AuditConfidence::High,
            "unwanted shell command",
            "obfuscated code",
        ),
    }
}

fn audit_nested_code_expr(checker: &mut Checker, call: &ast::ExprCall, code_expr: &ast::Expr) {
    if let Some(code_str) = hexora_semantic::resolver::string_from_expr(code_expr, &checker.indexer)
    {
        if let Ok(mut sub_results) = audit_source(&code_str, None) {
            for item in &mut sub_results {
                item.location = Some(call.range);
            }
            checker.audit_results.extend(sub_results);
        }
    }
}

fn record_execution_leak(checker: &mut Checker, label: &str, leaked_params: Vec<usize>) {
    for idx in leaked_params {
        checker.indexer.add_parameter_leak(idx, label.to_string());
    }
}

fn collect_execution_leaked_params(checker: &Checker, call: &ast::ExprCall) -> Vec<usize> {
    get_execution_subjects(checker, call)
        .iter()
        .flat_map(|expr| checker.indexer.get_taint(expr).into_iter())
        .filter_map(|taint| match taint {
            TaintKind::InternalParameter(idx) => Some(idx),
            _ => None,
        })
        .collect()
}

fn is_obfuscated(checker: &Checker, call: &ast::ExprCall, label: &str) -> bool {
    label == "map" || contains_suspicious_exec_arguments(checker, call)
}

fn get_audit_info(
    kind: ExecKind,
    taint: Option<TaintKind>,
    is_highly_suspicious: bool,
) -> (Rule, String, AuditConfidence) {
    let has_obfuscation_taint = taint.is_some_and(|t| t != TaintKind::EnvVariables);
    let is_obf = has_obfuscation_taint || is_highly_suspicious;
    let rule = match (kind, is_obf) {
        (ExecKind::Shell, true) => Rule::ObfuscatedShellExec,
        (ExecKind::Code, true) => Rule::ObfuscatedCodeExec,
        (ExecKind::Shell, false) => Rule::ShellExec,
        (ExecKind::Code, false) => Rule::CodeExec,
    };

    let type_str = if kind.is_shell() {
        "shell command"
    } else {
        "code"
    };
    let (description, confidence) = match (taint, is_highly_suspicious) {
        (Some(t), _) => {
            let (conf, shell_desc, code_desc) = get_taint_metadata(t);
            (
                format!(
                    "Execution of {}.",
                    if kind.is_shell() {
                        shell_desc
                    } else {
                        code_desc
                    }
                ),
                conf,
            )
        }
        (None, true) => (
            format!("Execution of obfuscated {}.", type_str),
            AuditConfidence::High,
        ),
        (None, false) => (
            format!("Possible execution of unwanted {}.", type_str),
            AuditConfidence::Medium,
        ),
    };

    (rule, description, confidence)
}

fn dangerous_exec_decision(
    checker: &Checker,
    call: &ast::ExprCall,
    label: &str,
    analysis: &ExecAnalysis,
) -> AuditDecision {
    let is_obf = analysis.call_taint.is_some() || analysis.is_highly_suspicious;
    let confidence = if is_obfuscated(checker, call, label) {
        AuditConfidence::VeryHigh
    } else {
        AuditConfidence::High
    };

    AuditDecision {
        rule: Rule::DangerousExec,
        description: (if is_obf {
            "Execution of obfuscated dangerous command in shell"
        } else {
            "Execution of potentially dangerous command in shell"
        })
        .to_string(),
        confidence,
    }
}

fn baseline_decision(analysis: &ExecAnalysis) -> AuditDecision {
    let (rule, description, confidence) = get_audit_info(
        analysis.base_kind(),
        analysis.call_taint,
        analysis.is_highly_suspicious,
    );
    AuditDecision {
        rule,
        description,
        confidence,
    }
}

fn apply_python_exec_adjustments(
    checker: &mut Checker,
    call: &ast::ExprCall,
    analysis: &ExecAnalysis,
    decision: &mut AuditDecision,
) {
    if !analysis.is_python_code_execution() {
        return;
    }

    decision.rule = Rule::CodeExec;
    decision.description = "Suspicious Python code execution using subprocess".to_string();
    decision.confidence = decision.confidence.max(AuditConfidence::High);

    if let Some(code_expr) = analysis.python_exec.c_code {
        audit_nested_code_expr(checker, call, code_expr);
    }
    if let Some(code_expr) = analysis.python_exec.stdin_code {
        audit_nested_code_expr(checker, call, code_expr);
        if let Some(taint) = get_suspicious_taint(checker, code_expr) {
            let (conf, _, code_desc) = get_taint_metadata(taint);
            decision.rule = Rule::ObfuscatedCodeExec;
            decision.confidence = conf;
            decision.description =
                format!("Execution of {} via Python subprocess stdin.", code_desc);
            if should_promote_exec_confidence(Some(taint), analysis.is_highly_suspicious) {
                decision.confidence = AuditConfidence::VeryHigh;
            }
        }
    }
    if let Some(script_path) = analysis.python_exec.script_path
        && let Some(taint) = get_suspicious_taint(checker, script_path)
    {
        let (conf, _, code_desc) = get_taint_metadata(taint);
        decision.rule = Rule::ObfuscatedCodeExec;
        decision.confidence = conf;
        decision.description = format!(
            "Execution of {} via Python subprocess script path.",
            code_desc
        );
        if should_promote_exec_confidence(Some(taint), analysis.is_highly_suspicious) {
            decision.confidence = AuditConfidence::VeryHigh;
        }
    }
}

fn apply_code_exec_adjustments(
    checker: &mut Checker,
    call: &ast::ExprCall,
    analysis: &ExecAnalysis,
    decision: &mut AuditDecision,
) {
    if analysis.kind != ExecKind::Code || analysis.is_python_code_execution() {
        return;
    }

    if let Some(code_expr) = analysis.direct_code_source {
        audit_nested_code_expr(checker, call, code_expr);
    }

    if is_aliased_code_exec_call(checker, call) || is_explicit_builtin_code_exec_call(call) {
        decision.confidence = decision.confidence.max(AuditConfidence::High);
    }
}

fn apply_confidence_adjustments(
    checker: &Checker,
    call: &ast::ExprCall,
    label: &str,
    analysis: &ExecAnalysis,
    decision: &mut AuditDecision,
    extra_confidence: Option<AuditConfidence>,
) {
    if is_obfuscated(checker, call, label) && analysis.call_taint != Some(TaintKind::EnvVariables) {
        decision.confidence = AuditConfidence::VeryHigh;
    }

    if analysis.should_cap_confidence() {
        decision.confidence = decision.confidence.min(AuditConfidence::High);
    }

    if let Some(extra) = extra_confidence {
        decision.confidence = decision.confidence.max(extra);
    }
}

pub(super) fn push_report(
    checker: &mut Checker,
    call: &ast::ExprCall,
    label: String,
    kind: ExecKind,
    extra_confidence: Option<AuditConfidence>,
) {
    let leaked_params = collect_execution_leaked_params(checker, call);
    let analysis = ExecAnalysis::new(checker, call, kind);
    record_execution_leak(checker, &label, leaked_params);

    let mut decision = if analysis.is_dangerous_shell_exec() {
        dangerous_exec_decision(checker, call, &label, &analysis)
    } else {
        baseline_decision(&analysis)
    };

    if !analysis.is_dangerous_shell_exec() {
        apply_python_exec_adjustments(checker, call, &analysis, &mut decision);
        apply_code_exec_adjustments(checker, call, &analysis, &mut decision);
        apply_confidence_adjustments(
            checker,
            call,
            &label,
            &analysis,
            &mut decision,
            extra_confidence,
        );
    }

    checker.audit_results.push(AuditItem {
        label,
        rule: decision.rule,
        description: decision.description,
        confidence: decision.confidence,
        location: Some(call.range),
    });
}

pub(super) fn check_leaked_exec(checker: &mut Checker, call: &ast::ExprCall, kind: ExecKind) {
    let Some(qn) = checker.indexer.resolve_qualified_name(&call.func) else {
        return;
    };
    let name = qn.as_str();
    let Some(binding) = checker.indexer.lookup_binding(&name) else {
        return;
    };

    for (param_idx, sink_name) in binding.parameter_leaks.clone() {
        let sink_qn = hexora_semantic::name::QualifiedName::new(sink_name.clone());
        if !kind.matches_qualified_name(&sink_qn) {
            continue;
        }

        let Some(arg) = call.arguments.args.get(param_idx) else {
            continue;
        };

        let arg_taint = get_suspicious_taint(checker, arg);
        let analysis = ExecAnalysis::new(checker, call, kind);
        let (rule, mut description, mut confidence) =
            get_audit_info(kind, arg_taint, analysis.is_highly_suspicious);
        confidence = confidence.max(AuditConfidence::High);
        description = format!(
            "{} (via local function {} leaking to {}).",
            &description[..description.len() - 1],
            name,
            sink_name
        );
        if is_obfuscated(checker, call, &name)
            && arg_taint.is_some_and(|t| {
                matches!(
                    t,
                    TaintKind::Decoded | TaintKind::Deobfuscated | TaintKind::NetworkSourced
                )
            })
        {
            confidence = AuditConfidence::VeryHigh;
        }

        if kind == ExecKind::Shell && arg_taint.is_none() && analysis.has_only_plain_subjects {
            confidence = confidence.min(AuditConfidence::High);
        }

        if kind == ExecKind::Code && is_reflection_like_exec_source(checker, arg, 0) {
            confidence = confidence.min(AuditConfidence::High);
        }

        checker.audit_results.push(AuditItem {
            label: name.clone(),
            rule,
            description,
            confidence,
            location: Some(call.range),
        });
    }
}
