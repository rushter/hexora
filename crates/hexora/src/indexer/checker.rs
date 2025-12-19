use crate::audit::result::AuditItem;
use crate::indexer::index::{NodeIndexer, ScopeKind};
use crate::indexer::locator::Locator;
use crate::rules::comments::check_comments;
use crate::rules::{expression, statement};
use ruff_python_ast;
use ruff_python_ast::visitor::Visitor;
use ruff_python_ast::{self as ast, Expr, Stmt};

pub struct Checker<'a> {
    pub imports: Vec<&'a Stmt>,
    pub audit_results: Vec<AuditItem>,
    pub locator: &'a Locator<'a>,
    pub indexer: NodeIndexer<'a>,
}

impl<'a> Checker<'a> {
    pub fn new(locator: &'a Locator, indexer: NodeIndexer<'a>) -> Self {
        Self {
            imports: Vec::new(),
            audit_results: Vec::new(),
            locator,
            indexer,
        }
    }

    pub fn visit_body(&mut self, body: &'a [Stmt]) {
        for stmt in body {
            self.visit_stmt(stmt);
        }
    }
    pub fn check_comments(&mut self) {
        check_comments(self);
    }
}

impl<'a> Visitor<'a> for Checker<'a> {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        match stmt {
            Stmt::FunctionDef(_) => {
                self.indexer.push_scope(ScopeKind::Function);
                ast::visitor::walk_stmt(self, stmt);
                statement::analyze(stmt, self);
                self.indexer.pop_scope();
            }
            Stmt::ClassDef(_) => {
                self.indexer.push_scope(ScopeKind::Class);
                ast::visitor::walk_stmt(self, stmt);
                statement::analyze(stmt, self);
                self.indexer.pop_scope();
            }
            _ => {
                ast::visitor::walk_stmt(self, stmt);
                statement::analyze(stmt, self);
            }
        }
    }
    fn visit_expr(&mut self, expr: &'a Expr) {
        ast::visitor::walk_expr(self, expr);
        expression::analyze(expr, self);
    }
}
