use crate::indexer::index::NodeIndexer;
use crate::indexer::locator::Locator;
use ruff_python_ast::visitor::transformer;
use ruff_python_ast::visitor::transformer::Transformer;
use ruff_python_ast::{self as ast};
use std::cell::RefCell;
use std::collections::HashSet;

/// This module rewrites string literals to their raw contents.
/// We want to have string values unchanged.
pub struct NodeTransformer<'a> {
    pub locator: &'a Locator<'a>,
    pub indexer: RefCell<NodeIndexer<'a>>,
    pub updated_strings: RefCell<HashSet<u32>>,
}

impl<'a> NodeTransformer<'a> {
    pub fn new(locator: &'a Locator, indexer: NodeIndexer<'a>) -> Self {
        Self {
            locator,
            indexer: RefCell::new(indexer),
            updated_strings: RefCell::default(),
        }
    }
}

impl<'a> Transformer for NodeTransformer<'a> {
    fn visit_expr(&self, expr: &mut ast::Expr) {
        transformer::walk_expr(self, expr);
        self.transform_strings(expr);
    }
}
