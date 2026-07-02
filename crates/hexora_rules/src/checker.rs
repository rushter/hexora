use crate::result::AuditItem;
use crate::rules::comments::check_comments;
use crate::rules::{expression, install_hook, statement};
use hexora_io::locator::Locator;
use hexora_semantic::index::NodeIndexer;
use ruff_python_ast;
use ruff_python_ast::visitor::Visitor;
use ruff_python_ast::{self as ast, Expr, Stmt};

pub struct Checker<'a> {
    pub audit_results: Vec<AuditItem>,
    pub locator: &'a Locator<'a>,
    pub indexer: NodeIndexer<'a>,
    is_setup_py: bool,
    install_hook_suspicious_stack: Vec<bool>,
}

impl<'a> Checker<'a> {
    pub(crate) fn new(locator: &'a Locator, indexer: NodeIndexer<'a>, is_setup_py: bool) -> Self {
        Self {
            audit_results: Vec::new(),
            locator,
            indexer,
            is_setup_py,
            install_hook_suspicious_stack: Vec::new(),
        }
    }

    pub(crate) fn is_setup_py(&self) -> bool {
        self.is_setup_py
    }

    pub fn visit_body(&mut self, body: &'a [Stmt]) {
        for stmt in body {
            self.visit_stmt(stmt);
        }
    }
    pub fn check_comments(&mut self) {
        check_comments(self);
    }

    fn enter_install_hook_class(&mut self) {
        self.install_hook_suspicious_stack.push(false);
    }

    fn exit_install_hook_class(&mut self) {
        self.install_hook_suspicious_stack.pop();
    }

    pub(crate) fn inside_install_hook(&self) -> bool {
        !self.install_hook_suspicious_stack.is_empty()
    }

    pub(crate) fn record_install_hook_suspicious(&mut self) {
        if let Some(flag) = self.install_hook_suspicious_stack.last_mut() {
            *flag = true;
        }
    }

    pub(crate) fn install_hook_has_suspicious(&self) -> bool {
        self.install_hook_suspicious_stack
            .last()
            .copied()
            .unwrap_or(false)
    }
}

impl<'a> Visitor<'a> for Checker<'a> {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        self.indexer.handle_stmt_pre(stmt);
        if self.is_setup_py()
            && let Stmt::ClassDef(class_def) = stmt
            && install_hook::is_install_hook_base_class(class_def, &self.indexer)
        {
            self.enter_install_hook_class();
            ast::visitor::walk_stmt(self, stmt);
            statement::analyze(stmt, self);
            install_hook::check_class_def(self, class_def);
            self.exit_install_hook_class();
            self.indexer.handle_stmt_post(stmt);
            return;
        }

        ast::visitor::walk_stmt(self, stmt);
        statement::analyze(stmt, self);
        self.indexer.handle_stmt_post(stmt);
    }

    fn visit_expr(&mut self, expr: &'a Expr) {
        self.indexer.handle_expr_pre(expr);
        ast::visitor::walk_expr(self, expr);
        self.indexer.handle_expr_post(expr);
        expression::analyze(expr, self);
        install_hook::check_expr_for_install_hook(self, expr);
    }
}
