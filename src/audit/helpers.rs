use ruff_python_ast as ast;
use ruff_python_ast::Expr;
use ruff_text_size::TextRange;

/// Returns the range of an expression.
#[inline]
pub fn get_expression_range(expr: &Expr) -> TextRange {
    match expr {
        Expr::BoolOp(node) => node.range,
        Expr::Named(node) => node.range,
        Expr::BinOp(node) => node.range,
        Expr::UnaryOp(node) => node.range,
        Expr::Lambda(node) => node.range,
        Expr::If(node) => node.range,
        Expr::Dict(node) => node.range,
        Expr::Set(node) => node.range,
        Expr::ListComp(node) => node.range,
        Expr::SetComp(node) => node.range,
        Expr::DictComp(node) => node.range,
        Expr::Generator(node) => node.range,
        Expr::Await(node) => node.range,
        Expr::Yield(node) => node.range,
        Expr::YieldFrom(node) => node.range,
        Expr::Compare(node) => node.range,
        Expr::Call(node) => node.range,
        Expr::FString(node) => node.range,
        Expr::TString(node) => node.range,
        Expr::StringLiteral(node) => node.range,
        Expr::BytesLiteral(node) => node.range,
        Expr::NumberLiteral(node) => node.range,
        Expr::BooleanLiteral(node) => node.range,
        Expr::NoneLiteral(node) => node.range,
        Expr::EllipsisLiteral(node) => node.range,
        Expr::Attribute(node) => node.range,
        Expr::Subscript(node) => node.range,
        Expr::Starred(node) => node.range,
        Expr::Name(node) => node.range,
        Expr::List(node) => node.range,
        Expr::Tuple(node) => node.range,
        Expr::Slice(node) => node.range,
        Expr::IpyEscapeCommand(node) => node.range,
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
