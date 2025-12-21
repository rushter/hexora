use crate::indexer::name::QualifiedName;
use ruff_python_ast::Expr;
use ruff_text_size::TextRange;
use std::cell::RefCell;
use std::collections::HashMap;

pub type NodeId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transformation {
    Base64,
    Hex,
    Other,
}

pub struct SemanticModel<'a> {
    pub expr_mapping: HashMap<NodeId, Vec<&'a Expr>>,
    pub call_qualified_names: HashMap<NodeId, QualifiedName>,
    pub comments: Vec<TextRange>,
    pub decoded_nodes: RefCell<HashMap<NodeId, Transformation>>,
}

impl<'a> SemanticModel<'a> {
    pub fn new() -> Self {
        Self {
            expr_mapping: HashMap::with_capacity(512),
            call_qualified_names: HashMap::with_capacity(512),
            comments: Vec::with_capacity(25),
            decoded_nodes: RefCell::default(),
        }
    }

    pub fn clear(&mut self) {
        self.expr_mapping.clear();
        self.call_qualified_names.clear();
    }
}

impl<'a> Default for SemanticModel<'a> {
    fn default() -> Self {
        Self::new()
    }
}
