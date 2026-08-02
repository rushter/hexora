use crate::index::NodeIndexer;
use crate::model::{NodeMap, Transformation};
use crate::node_transformer::NodeTransformer;
use crate::taint::TaintState;
use hexora_io::locator::Locator;
use ruff_python_ast::visitor::source_order::SourceOrderVisitor;
use ruff_python_ast::visitor::transformer::Transformer;
use ruff_python_ast::{self as ast, Stmt};
use ruff_text_size::TextRange;

pub struct PreparedAnalysis<'src> {
    pub locator: Locator<'src>,
    original_ast: Vec<Stmt>,
    pub transformed_ast: Vec<Stmt>,
    comments: Vec<TextRange>,
    decoded_nodes: NodeMap<Transformation>,
    taint_map: NodeMap<TaintState>,
    import_module_imports: Vec<(TextRange, String)>,
}

pub struct AnalyzedSource<'src, 'ast> {
    pub locator: &'ast Locator<'src>,
    pub ast: &'ast [Stmt],
    pub transformed_ast: &'ast [Stmt],
    pub indexer: &'ast NodeIndexer<'ast>,
}

pub fn prepare_source(source: &str) -> Result<PreparedAnalysis<'_>, String> {
    let parsed = ruff_python_parser::parse_unchecked_source(source, ast::PySourceType::Python);
    let locator = Locator::new(source);
    let python_ast = parsed.suite();
    let original_ast = python_ast.to_vec();

    let mut indexer = NodeIndexer::new();
    indexer.visit_body(python_ast);
    indexer.index_comments(parsed.tokens());

    let mut transformed_ast = python_ast.to_vec();
    let transformer = NodeTransformer::new(&locator, &indexer);
    transformer.visit_body(&mut transformed_ast);
    let comments = transformer.indexer.model.comments.clone();
    let decoded_nodes = transformer.indexer.model.decoded_nodes.borrow().clone();
    let taint_map = transformer.indexer.model.taint_map.borrow().clone();
    let import_module_imports = transformer
        .indexer
        .model
        .import_module_imports
        .borrow()
        .clone();
    drop(transformer);

    Ok(PreparedAnalysis {
        locator,
        original_ast,
        transformed_ast,
        comments,
        decoded_nodes,
        taint_map,
        import_module_imports,
    })
}

impl<'src> PreparedAnalysis<'src> {
    /// Build the semantic model once over the transformed AST and share it with all consumers
    /// (rules and ML feature extraction) during a single pass.
    pub fn with_indexed<R>(&self, f: impl for<'ast> FnOnce(AnalyzedSource<'src, 'ast>) -> R) -> R {
        let mut indexer = NodeIndexer::new();
        indexer.model.comments = self.comments.clone();
        *indexer.model.decoded_nodes.borrow_mut() = self.decoded_nodes.clone();
        *indexer.model.taint_map.borrow_mut() = self.taint_map.clone();
        *indexer.model.import_module_imports.borrow_mut() = self.import_module_imports.clone();
        indexer.visit_body(&self.transformed_ast);
        f(AnalyzedSource {
            locator: &self.locator,
            ast: &self.original_ast,
            transformed_ast: &self.transformed_ast,
            indexer: &indexer,
        })
    }
}
