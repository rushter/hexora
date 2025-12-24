use crate::indexer::taint::TaintState;
use ruff_python_ast::{Expr, StmtFunctionDef};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone)]
pub enum BindingKind {
    Builtin,
    Import,
    Assignment,
    Function,
}

#[derive(Debug, Clone)]
pub struct SymbolBinding<'a> {
    pub kind: BindingKind,
    pub imported_path: Option<Vec<String>>,
    pub value_expr: Option<&'a Expr>,
    pub assigned_expressions: Vec<&'a Expr>,
    pub function_def: Option<&'a StmtFunctionDef>,
    pub taint: TaintState,
    pub return_taint: TaintState,
}

impl<'a> SymbolBinding<'a> {
    pub fn builtin() -> Self {
        Self {
            kind: BindingKind::Builtin,
            imported_path: None,
            value_expr: None,
            assigned_expressions: Vec::new(),
            function_def: None,
            taint: HashSet::new(),
            return_taint: HashSet::new(),
        }
    }

    pub fn import(path: Vec<String>) -> Self {
        Self {
            kind: BindingKind::Import,
            imported_path: Some(path),
            value_expr: None,
            assigned_expressions: Vec::new(),
            function_def: None,
            taint: HashSet::new(),
            return_taint: HashSet::new(),
        }
    }

    pub fn assignment(value_expr: Option<&'a Expr>) -> Self {
        let assigned_expressions = if let Some(expr) = value_expr {
            vec![expr]
        } else {
            Vec::new()
        };
        Self {
            kind: BindingKind::Assignment,
            imported_path: None,
            value_expr,
            assigned_expressions,
            function_def: None,
            taint: HashSet::new(),
            return_taint: HashSet::new(),
        }
    }

    pub fn function(func: &'a StmtFunctionDef) -> Self {
        Self {
            kind: BindingKind::Function,
            imported_path: None,
            value_expr: None,
            assigned_expressions: Vec::new(),
            function_def: Some(func),
            taint: HashSet::new(),
            return_taint: HashSet::new(),
        }
    }

    pub fn add_assigned_expression(&mut self, expr: &'a Expr) {
        self.assigned_expressions.push(expr);
        self.value_expr = Some(expr);
    }
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum ScopeKind {
    Module,
    Class,
    Function,
}

pub struct Scope<'a> {
    pub kind: ScopeKind,
    pub symbols: HashMap<String, SymbolBinding<'a>>,
    pub parent_scope: Option<usize>,
}

impl<'a> Scope<'a> {
    pub fn new(kind: ScopeKind, parent_scope: Option<usize>) -> Self {
        Self {
            kind,
            symbols: HashMap::with_capacity(32),
            parent_scope,
        }
    }
}
