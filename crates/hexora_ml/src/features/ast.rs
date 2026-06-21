use crate::features::StringStats;
use crate::schema::FeatureRecord;
use hexora_semantic::analysis::AnalyzedSource;
use memchr::memmem;
use ruff_python_ast::visitor::source_order::{
    SourceOrderVisitor, TraversalSignal, walk_expr, walk_stmt,
};
use ruff_python_ast::{AnyNodeRef, Expr, Stmt};
use std::collections::BTreeMap;

const VERSION_FILE_NAMES: &[&str] = &["__init__.py", "version.py", "__version__.py", "about.py"];

pub(crate) fn extract_ast_features(record: &mut FeatureRecord, analyzed: &AnalyzedSource<'_, '_>) {
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

    let cyclomatic_complexity = 1 + collector.cyclomatic_complexity;
    record.insert("ast.cyclomatic_complexity", cyclomatic_complexity as f64);
    record.insert(
        "ast.cyclomatic_complexity_per_fn",
        cyclomatic_complexity as f64 / collector.num_functions.max(1) as f64,
    );

    for (kind, count) in collector.stmt_counts {
        record.insert(format!("stmt.{kind}"), count as f64);
    }
    for (kind, count) in collector.expr_counts {
        record.insert(format!("expr.{kind}"), count as f64);
    }
    for (name, count) in &collector.operator_counts {
        record.insert(format!("expr.op.{name}"), *count as f64);
    }

    let mut string_stats = StringStats::default();
    for expr in &collector.string_literals {
        string_stats.observe(expr);
    }
    record.insert("literal.num_strings", string_stats.count as f64);
    record.insert("literal.max_string_length", string_stats.max_len as f64);
    record.insert("literal.mean_string_length", string_stats.mean_len());
    record.insert("literal.max_string_entropy", string_stats.max_entropy);
    record.insert("literal.mean_string_entropy", string_stats.mean_entropy());

    let has_version_file = collector.string_literals.iter().any(|s| {
        VERSION_FILE_NAMES
            .iter()
            .any(|&name| memmem::find(s.as_bytes(), name.as_bytes()).is_some())
    });
    if has_version_file {
        record.set_flag("contain_version_file");
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
    cyclomatic_complexity: usize,
    operator_counts: BTreeMap<&'static str, usize>,
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
            Stmt::If(stmt_if) => {
                self.cyclomatic_complexity += 1;
                self.cyclomatic_complexity += stmt_if
                    .elif_else_clauses
                    .iter()
                    .filter(|c| c.test.is_some())
                    .count();
            }
            Stmt::While(_) | Stmt::For(_) => self.cyclomatic_complexity += 1,
            Stmt::Try(stmt_try) => {
                self.cyclomatic_complexity += stmt_try.handlers.len();
            }
            Stmt::Match(stmt_match) => {
                self.cyclomatic_complexity += stmt_match.cases.len();
                self.cyclomatic_complexity += stmt_match
                    .cases
                    .iter()
                    .filter(|c| c.guard.is_some())
                    .count();
            }
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
            Expr::BinOp(binop) => {
                let name = operator_name(&binop.op);
                *self.operator_counts.entry(name).or_insert(0) += 1;
            }
            Expr::BoolOp(bool_op) => {
                self.cyclomatic_complexity += bool_op.values.len().saturating_sub(1);
            }
            Expr::If(_) => self.cyclomatic_complexity += 1,
            _ => {}
        }
        walk_expr(self, expr);
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

fn operator_name(op: &ruff_python_ast::Operator) -> &'static str {
    match op {
        ruff_python_ast::Operator::Add => "Add",
        ruff_python_ast::Operator::Sub => "Sub",
        ruff_python_ast::Operator::Mult => "Mult",
        ruff_python_ast::Operator::Div => "Div",
        ruff_python_ast::Operator::Mod => "Mod",
        ruff_python_ast::Operator::Pow => "Pow",
        ruff_python_ast::Operator::FloorDiv => "FloorDiv",
        ruff_python_ast::Operator::BitAnd => "BitAnd",
        ruff_python_ast::Operator::BitOr => "BitOr",
        ruff_python_ast::Operator::BitXor => "BitXor",
        ruff_python_ast::Operator::LShift => "LShift",
        ruff_python_ast::Operator::RShift => "RShift",
        ruff_python_ast::Operator::MatMult => "MatMult",
    }
}
