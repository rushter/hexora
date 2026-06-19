use crate::schema::FeatureRecord;
use hexora_io::locator::Locator;
use hexora_rules::result::{AuditConfidence, AuditItem, Rule};
use hexora_semantic::analysis::AnalyzedSource;
use hexora_semantic::model::Transformation;
use hexora_semantic::scope::BindingKind;
use hexora_semantic::taint::TaintKind;
use ruff_python_ast::visitor::source_order::{
    SourceOrderVisitor, TraversalSignal, walk_expr, walk_stmt,
};
use ruff_python_ast::{AnyNodeRef, Expr, Stmt};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

pub fn extract_features(
    analyzed: &AnalyzedSource<'_, '_>,
    source: &str,
    items: &[AuditItem],
) -> FeatureRecord {
    let mut record = FeatureRecord::new();
    extract_source_features(&mut record, analyzed.locator, source);
    extract_ast_features(&mut record, analyzed);
    extract_import_features(&mut record, analyzed);
    extract_semantic_features(&mut record, analyzed);
    extract_rule_features(&mut record, items);
    record.insert("meta.feature_count", record.len() as f64);
    record
}

pub fn extract_features_from_source(code: &str, file_path: &Path) -> Result<FeatureRecord, String> {
    let prepared = hexora_semantic::analysis::prepare_source(code)?;
    let items = hexora_rules::audit_prepared(&prepared, Some(file_path))?;
    let features =
        prepared.with_original_indexed(|analyzed| extract_features(&analyzed, code, &items));
    Ok(features)
}

fn extract_source_features(record: &mut FeatureRecord, _locator: &Locator<'_>, source: &str) {
    let lines: Vec<&str> = source.lines().collect();
    let num_lines = lines.len() as f64;
    let num_nonempty_lines = lines.iter().filter(|line| !line.trim().is_empty()).count() as f64;
    let num_comment_lines = lines
        .iter()
        .filter(|line| line.trim_start().starts_with('#'))
        .count() as f64;
    let longest_line = lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(0) as f64;
    let total_line_length = lines.iter().map(|line| line.chars().count()).sum::<usize>() as f64;
    let ascii_chars = source.chars().filter(|ch| ch.is_ascii()).count() as f64;
    let total_chars = source.chars().count() as f64;

    record.insert("source.num_lines", num_lines);
    record.insert("source.num_nonempty_lines", num_nonempty_lines);
    record.insert("source.num_comment_lines", num_comment_lines);
    record.insert("source.num_bytes", source.len() as f64);
    record.insert("source.longest_line", longest_line);
    record.insert(
        "source.avg_line_length",
        if num_lines > 0.0 {
            total_line_length / num_lines
        } else {
            0.0
        },
    );
    record.insert(
        "source.non_ascii_ratio",
        if total_chars > 0.0 {
            1.0 - (ascii_chars / total_chars)
        } else {
            0.0
        },
    );

    let mut string_stats = StringStats::default();
    for line in &lines {
        if !line.is_empty() {
            string_stats.observe(line);
        }
    }

    record.insert("source.max_line_entropy", string_stats.max_entropy);
    record.insert("source.mean_line_entropy", string_stats.mean_entropy());
}

fn extract_ast_features(record: &mut FeatureRecord, analyzed: &AnalyzedSource<'_, '_>) {
    let mut collector = AstFeatureCollector::default();
    collector.visit_body(analyzed.ast);

    record.insert("ast.max_depth", collector.max_depth as f64);
    record.insert("ast.num_functions", collector.num_functions as f64);
    record.insert(
        "ast.num_async_functions",
        collector.num_async_functions as f64,
    );
    record.insert("ast.num_classes", collector.num_classes as f64);
    record.insert("ast.num_calls", collector.num_calls as f64);
    record.insert("ast.num_imports", collector.num_imports as f64);
    record.insert("ast.num_import_froms", collector.num_import_froms as f64);

    for (kind, count) in collector.stmt_counts {
        record.insert(format!("stmt.{kind}"), count as f64);
    }
    for (kind, count) in collector.expr_counts {
        record.insert(format!("expr.{kind}"), count as f64);
    }

    let mut string_stats = StringStats::default();
    for expr in collector.string_literals {
        string_stats.observe(&expr);
    }
    record.insert("literal.num_strings", string_stats.count as f64);
    record.insert("literal.max_string_length", string_stats.max_len as f64);
    record.insert("literal.mean_string_length", string_stats.mean_len());
    record.insert("literal.max_string_entropy", string_stats.max_entropy);
    record.insert("literal.mean_string_entropy", string_stats.mean_entropy());
}

fn extract_import_features(record: &mut FeatureRecord, analyzed: &AnalyzedSource<'_, '_>) {
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

fn extract_semantic_features(record: &mut FeatureRecord, analyzed: &AnalyzedSource<'_, '_>) {
    let taint_map = analyzed.indexer.model.taint_map.borrow();
    record.insert("semantic.tainted_nodes", taint_map.len() as f64);
    for taints in taint_map.values() {
        for taint in taints {
            record.add(format!("taint.{}", taint_name(*taint)), 1.0);
        }
    }

    let decoded_nodes = analyzed.indexer.model.decoded_nodes.borrow();
    record.insert("semantic.decoded_nodes", decoded_nodes.len() as f64);
    for transformation in decoded_nodes.values() {
        record.add(
            format!("transform.{}", transformation_name(*transformation)),
            1.0,
        );
    }

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
    }
}

fn extract_rule_features(record: &mut FeatureRecord, items: &[AuditItem]) {
    record.insert("rule.total_hits", items.len() as f64);

    let mut per_rule = BTreeMap::new();
    for rule in Rule::iter() {
        per_rule.insert(rule.code(), RuleStats::default());
    }
    let mut total_score = 0.0;
    let mut max_score: f64 = 0.0;
    let mut min_score = f64::INFINITY;

    for item in items {
        let score = confidence_score(item.confidence);
        total_score += score;
        max_score = max_score.max(score);
        min_score = min_score.min(score);

        record.add(
            format!("confidence.{:?}", item.confidence).to_lowercase(),
            1.0,
        );

        let stats = per_rule.entry(item.rule.code()).or_default();
        stats.count += 1;
        stats.sum += score;
        stats.max = stats.max.max(score);
        stats.min = stats.min.min(score);
    }

    record.insert("rule.score_sum", total_score);
    record.insert("rule.score_max", max_score);
    record.insert(
        "rule.score_min",
        if items.is_empty() { 0.0 } else { min_score },
    );

    for (code, stats) in per_rule {
        record.insert(format!("rule.count.{code}"), stats.count as f64);
        record.insert(format!("rule.conf_sum.{code}"), stats.sum);
        record.insert(format!("rule.conf_max.{code}"), stats.max);
        record.insert(
            format!("rule.conf_min.{code}"),
            if stats.count == 0 { 0.0 } else { stats.min },
        );
    }
}

#[derive(Debug, Default)]
struct AstFeatureCollector {
    depth: usize,
    max_depth: usize,
    stmt_counts: BTreeMap<&'static str, usize>,
    expr_counts: BTreeMap<&'static str, usize>,
    num_functions: usize,
    num_async_functions: usize,
    num_classes: usize,
    num_calls: usize,
    num_imports: usize,
    num_import_froms: usize,
    string_literals: Vec<String>,
}

impl AstFeatureCollector {
    fn bump_stmt(&mut self, name: &'static str) {
        *self.stmt_counts.entry(name).or_insert(0) += 1;
    }

    fn bump_expr(&mut self, name: &'static str) {
        *self.expr_counts.entry(name).or_insert(0) += 1;
    }

    fn enter(&mut self) {
        self.depth += 1;
        self.max_depth = self.max_depth.max(self.depth);
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn visit_body(&mut self, body: &[Stmt]) {
        for stmt in body {
            self.visit_stmt(stmt);
        }
    }
}

impl<'a> SourceOrderVisitor<'a> for AstFeatureCollector {
    fn enter_node(&mut self, _node: AnyNodeRef<'a>) -> TraversalSignal {
        self.enter();
        TraversalSignal::Traverse
    }

    fn leave_node(&mut self, _node: AnyNodeRef<'a>) {
        self.leave();
    }

    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        self.bump_stmt(stmt_kind_name(stmt));
        match stmt {
            Stmt::FunctionDef(function) => {
                self.num_functions += 1;
                if function.is_async {
                    self.num_async_functions += 1;
                }
            }
            Stmt::ClassDef(_) => self.num_classes += 1,
            Stmt::Import(_) => self.num_imports += 1,
            Stmt::ImportFrom(_) => self.num_import_froms += 1,
            _ => {}
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        self.bump_expr(expr_kind_name(expr));
        match expr {
            Expr::Call(_) => self.num_calls += 1,
            Expr::StringLiteral(value) => self.string_literals.push(value.value.to_string()),
            Expr::BytesLiteral(value) => {
                let bytes = value
                    .value
                    .iter()
                    .flat_map(|part| part.as_slice().iter().copied())
                    .collect::<Vec<u8>>();
                self.string_literals
                    .push(String::from_utf8_lossy(&bytes).into_owned());
            }
            _ => {}
        }
        walk_expr(self, expr);
    }
}

#[derive(Debug, Clone, Copy)]
struct RuleStats {
    count: usize,
    sum: f64,
    max: f64,
    min: f64,
}

impl Default for RuleStats {
    fn default() -> Self {
        Self {
            count: 0,
            sum: 0.0,
            max: 0.0,
            min: f64::INFINITY,
        }
    }
}

#[derive(Debug, Default)]
struct StringStats {
    count: usize,
    total_len: usize,
    max_len: usize,
    total_entropy: f64,
    max_entropy: f64,
}

impl StringStats {
    fn observe(&mut self, value: &str) {
        self.count += 1;
        self.total_len += value.chars().count();
        self.max_len = self.max_len.max(value.chars().count());
        let entropy = shannon_entropy(value);
        self.total_entropy += entropy;
        self.max_entropy = self.max_entropy.max(entropy);
    }

    fn mean_len(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.total_len as f64 / self.count as f64
        }
    }

    fn mean_entropy(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.total_entropy / self.count as f64
        }
    }
}

fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }

    let mut counts = BTreeMap::new();
    let len = value.chars().count() as f64;
    for ch in value.chars() {
        *counts.entry(ch).or_insert(0usize) += 1;
    }

    counts
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            -(p * p.log2())
        })
        .sum()
}

fn confidence_score(confidence: AuditConfidence) -> f64 {
    confidence as u8 as f64
}

fn taint_name(taint: TaintKind) -> String {
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

fn transformation_name(transformation: Transformation) -> &'static str {
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

fn stmt_kind_name(stmt: &Stmt) -> &'static str {
    match stmt {
        Stmt::FunctionDef(_) => "FunctionDef",
        Stmt::ClassDef(_) => "ClassDef",
        Stmt::Return(_) => "Return",
        Stmt::Delete(_) => "Delete",
        Stmt::Assign(_) => "Assign",
        Stmt::TypeAlias(_) => "TypeAlias",
        Stmt::AugAssign(_) => "AugAssign",
        Stmt::AnnAssign(_) => "AnnAssign",
        Stmt::For(node) => {
            if node.is_async {
                "AsyncFor"
            } else {
                "For"
            }
        }
        Stmt::While(_) => "While",
        Stmt::If(_) => "If",
        Stmt::With(node) => {
            if node.is_async {
                "AsyncWith"
            } else {
                "With"
            }
        }
        Stmt::Match(_) => "Match",
        Stmt::Raise(_) => "Raise",
        Stmt::Try(_) => "Try",
        Stmt::Assert(_) => "Assert",
        Stmt::Import(_) => "Import",
        Stmt::ImportFrom(_) => "ImportFrom",
        Stmt::Global(_) => "Global",
        Stmt::Nonlocal(_) => "Nonlocal",
        Stmt::Expr(_) => "Expr",
        Stmt::Pass(_) => "Pass",
        Stmt::Break(_) => "Break",
        Stmt::Continue(_) => "Continue",
        Stmt::IpyEscapeCommand(_) => "IpyEscapeCommand",
    }
}

fn expr_kind_name(expr: &Expr) -> &'static str {
    match expr {
        Expr::BoolOp(_) => "BoolOp",
        Expr::Named(_) => "Named",
        Expr::BinOp(_) => "BinOp",
        Expr::UnaryOp(_) => "UnaryOp",
        Expr::Lambda(_) => "Lambda",
        Expr::If(_) => "If",
        Expr::Dict(_) => "Dict",
        Expr::Set(_) => "Set",
        Expr::ListComp(_) => "ListComp",
        Expr::SetComp(_) => "SetComp",
        Expr::DictComp(_) => "DictComp",
        Expr::Generator(_) => "Generator",
        Expr::Await(_) => "Await",
        Expr::Yield(_) => "Yield",
        Expr::YieldFrom(_) => "YieldFrom",
        Expr::Compare(_) => "Compare",
        Expr::Call(_) => "Call",
        Expr::FString(_) => "FString",
        Expr::StringLiteral(_) => "StringLiteral",
        Expr::BytesLiteral(_) => "BytesLiteral",
        Expr::NumberLiteral(_) => "NumberLiteral",
        Expr::BooleanLiteral(_) => "BooleanLiteral",
        Expr::NoneLiteral(_) => "NoneLiteral",
        Expr::EllipsisLiteral(_) => "EllipsisLiteral",
        Expr::Attribute(_) => "Attribute",
        Expr::Subscript(_) => "Subscript",
        Expr::Starred(_) => "Starred",
        Expr::Name(_) => "Name",
        Expr::List(_) => "List",
        Expr::Tuple(_) => "Tuple",
        Expr::Slice(_) => "Slice",
        Expr::IpyEscapeCommand(_) => "IpyEscapeCommand",
        _ => "Other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_features_from_source_valid_python() {
        let code = "x = 1\nprint(x)\n";
        let file_path = Path::new("test.py");
        let result = extract_features_from_source(code, file_path);
        assert!(result.is_ok());
        let features = result.unwrap();
        assert!(features.len() > 0);
        assert!(features.get("source.num_lines").is_some());
        assert!(features.get("meta.feature_count").is_some());
    }

    #[test]
    fn test_extract_features_from_source_empty_string() {
        let code = "";
        let file_path = Path::new("empty.py");
        let result = extract_features_from_source(code, file_path);
        assert!(result.is_ok());
        let features = result.unwrap();
        assert_eq!(features.get("source.num_lines").unwrap_or(0.0), 0.0);
    }

    #[test]
    fn test_extract_features_from_source_contains_base64() {
        let code = r#"
import base64
payload = base64.b64decode("cHJpbnQoMSk=")
exec(payload)
"#;
        let file_path = Path::new("test_payload.py");
        let result = extract_features_from_source(code, file_path);
        assert!(result.is_ok());
        let features = result.unwrap();
        assert!(features.len() > 0);
        let has_rule_hits = features.get("rule.total_hits").unwrap_or(0.0) > 0.0;
        assert!(has_rule_hits, "Expected rule hits but got none");
    }
}
