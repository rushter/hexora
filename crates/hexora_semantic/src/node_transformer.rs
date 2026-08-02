use crate::index::NodeIndexer;
use hexora_io::locator::Locator;
use ruff_python_ast::visitor::transformer;
use ruff_python_ast::visitor::transformer::Transformer;
use ruff_python_ast::{self as ast};
use rustc_hash::FxHashSet;
use std::cell::RefCell;

/// This module rewrites string literals to their raw contents.
/// We want to have string values unchanged.
pub struct NodeTransformer<'a, 'b> {
    pub locator: &'a Locator<'a>,
    pub indexer: &'b NodeIndexer<'a>,
    pub updated_strings: RefCell<FxHashSet<u32>>,
}

impl<'a, 'b> NodeTransformer<'a, 'b> {
    pub fn new(locator: &'a Locator, indexer: &'b NodeIndexer<'a>) -> Self {
        Self {
            locator,
            indexer,
            updated_strings: RefCell::default(),
        }
    }
}

impl<'a, 'b> Transformer for NodeTransformer<'a, 'b> {
    fn visit_expr(&self, expr: &mut ast::Expr) {
        transformer::walk_expr(self, expr);
        self.transform_strings(expr);
    }
}
