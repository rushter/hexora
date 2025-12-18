use crate::indexer::index::NodeIndexer;
use ruff_python_ast as ast;
use ruff_text_size::TextRange;

/// Returns the range of an expression.
#[inline]
pub fn get_expression_range(expr: &ast::Expr) -> TextRange {
    match expr {
        ast::Expr::BoolOp(node) => node.range,
        ast::Expr::Named(node) => node.range,
        ast::Expr::BinOp(node) => node.range,
        ast::Expr::UnaryOp(node) => node.range,
        ast::Expr::Lambda(node) => node.range,
        ast::Expr::If(node) => node.range,
        ast::Expr::Dict(node) => node.range,
        ast::Expr::Set(node) => node.range,
        ast::Expr::ListComp(node) => node.range,
        ast::Expr::SetComp(node) => node.range,
        ast::Expr::DictComp(node) => node.range,
        ast::Expr::Generator(node) => node.range,
        ast::Expr::Await(node) => node.range,
        ast::Expr::Yield(node) => node.range,
        ast::Expr::YieldFrom(node) => node.range,
        ast::Expr::Compare(node) => node.range,
        ast::Expr::Call(node) => node.range,
        ast::Expr::FString(node) => node.range,
        ast::Expr::TString(node) => node.range,
        ast::Expr::StringLiteral(node) => node.range,
        ast::Expr::BytesLiteral(node) => node.range,
        ast::Expr::NumberLiteral(node) => node.range,
        ast::Expr::BooleanLiteral(node) => node.range,
        ast::Expr::NoneLiteral(node) => node.range,
        ast::Expr::EllipsisLiteral(node) => node.range,
        ast::Expr::Attribute(node) => node.range,
        ast::Expr::Subscript(node) => node.range,
        ast::Expr::Starred(node) => node.range,
        ast::Expr::Name(node) => node.range,
        ast::Expr::List(node) => node.range,
        ast::Expr::Tuple(node) => node.range,
        ast::Expr::Slice(node) => node.range,
        ast::Expr::IpyEscapeCommand(node) => node.range,
    }
}

#[allow(clippy::len_without_is_empty)]
pub trait ListLike {
    fn elements(&self) -> &Vec<ast::Expr>;
    fn range(&self) -> TextRange;
    fn len(&self) -> usize {
        self.elements().len()
    }
}

impl ListLike for ast::ExprList {
    fn elements(&self) -> &Vec<ast::Expr> {
        &self.elts
    }
    fn range(&self) -> TextRange {
        self.range
    }
}

impl ListLike for ast::ExprTuple {
    fn elements(&self) -> &Vec<ast::Expr> {
        &self.elts
    }
    fn range(&self) -> TextRange {
        self.range
    }
}

// Extract the raw string value from a string or bytes literal expression.
// Note: Our `indexer::strings::StringTransformer`
// transformed all strings to StringLiteral with raw values.
// It makes it easier to process.
#[inline]
pub(crate) fn string_from_expr(expr: &ast::Expr, indexer: &NodeIndexer) -> Option<String> {
    match expr {
        ast::Expr::StringLiteral(ast::ExprStringLiteral { value, .. }) => Some(value.to_string()),
        ast::Expr::Name(ast::ExprName { node_index, .. }) => {
            let external_expr = indexer.get_exprs_by_index(node_index)?;
            let mut string = String::new();
            for expr in external_expr {
                match expr {
                    ast::Expr::StringLiteral(ast::ExprStringLiteral { value, .. }) => {
                        string.push_str(value.to_str());
                    }
                    _ => continue,
                }
            }
            Some(string)
        }
        _ => None,
    }
}
