use crate::name::QualifiedName;
use crate::taint::TaintState;
use ruff_python_ast::Expr;
use ruff_text_size::TextRange;
use std::cell::RefCell;

pub type NodeId = u32;

/// Node IDs are assigned from a counter seeded at this value; everything
/// below is reserved for builtins / special cases.
pub const NODE_ID_BASE: NodeId = 1000;

/// A dense map keyed by [`NodeId`].
///
/// Node IDs are handed out monotonically from a counter, so a `Vec` indexed
/// by `id - NODE_ID_BASE` gives O(1) lookups without hashing.
#[derive(Debug, Clone)]
pub struct NodeMap<T> {
    slots: Vec<Option<T>>,
    len: usize,
}

impl<T> Default for NodeMap<T> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            len: 0,
        }
    }
}

impl<T> NodeMap<T> {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn get(&self, id: NodeId) -> Option<&T> {
        self.slots
            .get((id - NODE_ID_BASE) as usize)
            .and_then(Option::as_ref)
    }

    #[inline]
    pub fn get_mut(&mut self, id: NodeId) -> Option<&mut T> {
        self.slots
            .get_mut((id - NODE_ID_BASE) as usize)
            .and_then(Option::as_mut)
    }

    pub fn insert(&mut self, id: NodeId, value: T) -> Option<T> {
        let idx = (id - NODE_ID_BASE) as usize;
        self.resize_to(idx);
        let old = self.slots[idx].replace(value);
        if old.is_none() {
            self.len += 1;
        }
        old
    }

    pub fn remove(&mut self, id: NodeId) -> Option<T> {
        let idx = (id - NODE_ID_BASE) as usize;
        if idx >= self.slots.len() {
            return None;
        }
        let old = self.slots[idx].take();
        if old.is_some() {
            self.len -= 1;
        }
        old
    }

    /// Returns a mutable reference to the entry at `id`, creating it with
    /// `T::default()` if absent.
    pub fn entry(&mut self, id: NodeId) -> &mut T
    where
        T: Default,
    {
        let idx = (id - NODE_ID_BASE) as usize;
        self.resize_to(idx);
        let slot = &mut self.slots[idx];
        if slot.is_none() {
            *slot = Some(T::default());
            self.len += 1;
        }
        slot.as_mut().expect("slot was just initialized")
    }

    fn resize_to(&mut self, idx: usize) {
        if self.slots.len() <= idx {
            self.slots.resize_with(idx + 1, || None);
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        self.slots.clear();
        self.len = 0;
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.slots.iter().filter_map(Option::as_ref)
    }

    pub fn iter(&self) -> impl Iterator<Item = (NodeId, &T)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| slot.as_ref().map(|v| (NODE_ID_BASE + i as u32, v)))
    }
}

/// A dense set of [`NodeId`]s, the `NodeMap` counterpart for membership tests.
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct NodeSet {
    slots: Vec<bool>,
    len: usize,
}


impl NodeSet {
    /// Inserts `id`, returning `true` if it was not already present.
    pub fn insert(&mut self, id: NodeId) -> bool {
        let idx = (id - NODE_ID_BASE) as usize;
        if self.slots.len() <= idx {
            self.slots.resize(idx + 1, false);
        }
        let was_present = std::mem::replace(&mut self.slots[idx], true);
        if !was_present {
            self.len += 1;
        }
        !was_present
    }

    pub fn remove(&mut self, id: NodeId) -> bool {
        let idx = (id - NODE_ID_BASE) as usize;
        if idx >= self.slots.len() {
            return false;
        }
        let was_present = std::mem::replace(&mut self.slots[idx], false);
        if was_present {
            self.len -= 1;
        }
        was_present
    }

    #[inline]
    pub fn contains(&self, id: NodeId) -> bool {
        self.slots
            .get((id - NODE_ID_BASE) as usize)
            .copied()
            .unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn clear(&mut self) {
        self.slots.clear();
        self.len = 0;
    }
}

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
    pub expr_mapping: NodeMap<Vec<&'a Expr>>,
    pub call_qualified_names: NodeMap<QualifiedName>,
    pub comments: Vec<TextRange>,
    pub decoded_nodes: RefCell<NodeMap<Transformation>>,
    pub taint_map: RefCell<NodeMap<TaintState>>,
    pub currently_resolving: RefCell<NodeSet>,
    pub transformed_exprs_cache: RefCell<NodeMap<Vec<Expr>>>,
    pub import_module_imports: RefCell<Vec<(TextRange, String)>>,
}

impl<'a> SemanticModel<'a> {
    pub fn new() -> Self {
        Self {
            expr_mapping: NodeMap::new(),
            call_qualified_names: NodeMap::new(),
            comments: Vec::with_capacity(25),
            decoded_nodes: RefCell::default(),
            taint_map: RefCell::default(),
            currently_resolving: RefCell::default(),
            transformed_exprs_cache: RefCell::default(),
            import_module_imports: RefCell::default(),
        }
    }

    pub fn clear(&mut self) {
        self.expr_mapping.clear();
        self.call_qualified_names.clear();
        self.currently_resolving.get_mut().clear();
        self.transformed_exprs_cache.get_mut().clear();
    }
}

impl<'a> Default for SemanticModel<'a> {
    fn default() -> Self {
        Self::new()
    }
}
