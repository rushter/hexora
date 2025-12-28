use crate::indexer::name::QualifiedName;
use crate::indexer::taint::TaintState;
use ruff_python_ast::Expr;
use ruff_python_ast::name::Name;
use ruff_text_size::TextRange;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

pub type NodeId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transformation {
    Base64,
    Hex,
    Concat,
    Join,
    Subscript,
    FString,
    Other,
}

pub struct SemanticModel<'a> {
    pub expr_mapping: HashMap<NodeId, Vec<&'a Expr>>,
    pub call_qualified_names: HashMap<NodeId, QualifiedName>,
    pub comments: Vec<TextRange>,
    pub decoded_nodes: RefCell<HashMap<NodeId, Transformation>>,
    pub taint_map: RefCell<HashMap<NodeId, TaintState>>,
    pub resolve_cache: RefCell<HashMap<NodeId, Option<Vec<Name>>>>,
    pub currently_resolving: RefCell<HashSet<NodeId>>,
    pub transformed_exprs_cache: RefCell<HashMap<NodeId, Vec<Expr>>>,
}

impl<'a> SemanticModel<'a> {
    pub fn new() -> Self {
        Self {
            expr_mapping: HashMap::with_capacity(512),
            call_qualified_names: HashMap::with_capacity(512),
            comments: Vec::with_capacity(25),
            decoded_nodes: RefCell::default(),
            taint_map: RefCell::default(),
            resolve_cache: RefCell::default(),
            currently_resolving: RefCell::default(),
            transformed_exprs_cache: RefCell::default(),
        }
    }

    pub fn clear(&mut self) {
        self.expr_mapping.clear();
        self.call_qualified_names.clear();
        self.resolve_cache.get_mut().clear();
        self.currently_resolving.get_mut().clear();
        self.transformed_exprs_cache.get_mut().clear();
    }
}

impl<'a> Default for SemanticModel<'a> {
    fn default() -> Self {
        Self::new()
    }
}
