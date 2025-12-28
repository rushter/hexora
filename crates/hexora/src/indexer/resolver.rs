use crate::indexer::index::NodeIndexer;
use crate::indexer::model::NodeId;
use crate::indexer::name::QualifiedName;
use crate::indexer::scope::{BindingKind, SymbolBinding};
use ruff_python_ast::name::Name;
use ruff_python_ast::visitor::Visitor;
use ruff_python_ast::{
    self as ast, Expr, ExprAttribute, ExprBinOp, ExprCall, ExprName, ExprSubscript, HasNodeIndex,
    Operator, StmtFunctionDef,
};
use ruff_text_size::TextRange;

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
        ast::Expr::BinOp(ast::ExprBinOp {
            left,
            op: ast::Operator::Add,
            right,
            ..
        }) => {
            let l = string_from_expr(left, indexer).unwrap_or_default();
            let r = string_from_expr(right, indexer).unwrap_or_default();
            if l.is_empty() && r.is_empty() {
                None
            } else {
                Some(l + &r)
            }
        }
        ast::Expr::BinOp(ast::ExprBinOp {
            left,
            op: ast::Operator::Mod,
            ..
        }) => string_from_expr(left, indexer),
        ast::Expr::FString(f) => {
            let mut res = String::new();
            for part in &f.value {
                match part {
                    ast::FStringPart::Literal(lit) => res.push_str(&lit.value),
                    ast::FStringPart::FString(fstring) => {
                        for element in &fstring.elements {
                            match element {
                                ast::InterpolatedStringElement::Literal(lit) => {
                                    res.push_str(lit.as_ref());
                                }
                                ast::InterpolatedStringElement::Interpolation(interp) => {
                                    if let Some(s) = string_from_expr(&interp.expression, indexer) {
                                        res.push_str(&s);
                                    } else if let ast::Expr::Name(name) = interp.expression.as_ref()
                                    {
                                        res.push_str(&format!("{{{}}}", name.id.as_str()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if res.is_empty() { None } else { Some(res) }
        }
        ast::Expr::Name(ast::ExprName { node_index, .. }) => {
            let external_expr = indexer.get_exprs_by_index(node_index)?;
            let mut string = String::new();
            let mut found = false;
            for expr in external_expr {
                if let Some(s) = string_from_expr(expr, indexer) {
                    string.push_str(&s);
                    found = true;
                }
            }
            if found { Some(string) } else { None }
        }
        _ => None,
    }
}

impl<'a> NodeIndexer<'a> {
    pub fn resolve_expr_import_path(&self, expr: &Expr) -> Option<Vec<Name>> {
        self.resolve_expr_import_path_internal(expr, None)
    }

    pub(crate) fn resolve_expr_import_path_internal(
        &self,
        expr: &Expr,
        context: Option<(&'a ExprCall, &'a StmtFunctionDef)>,
    ) -> Option<Vec<Name>> {
        let node_id = expr.node_index().load().as_u32()?;
        if context.is_none() {
            if let Some(res) = self.model.resolve_cache.borrow().get(&node_id) {
                return res.clone();
            }
        }

        if !self.model.currently_resolving.borrow_mut().insert(node_id) {
            return None;
        }

        let res = match expr {
            Expr::Name(name) => self.resolve_name_path(name, context),
            Expr::Attribute(attr) => self.resolve_attribute_path(attr, context),
            Expr::Subscript(sub) => self.resolve_subscript_path(sub, context),
            Expr::BinOp(binop) if matches!(binop.op, Operator::Add) => {
                self.resolve_binop_path(binop, context)
            }
            Expr::StringLiteral(s) => Some(vec![Name::from(s.value.to_str())]),
            Expr::Call(call) => self.resolve_call_path(call, context),
            _ => None,
        };

        self.model.currently_resolving.borrow_mut().remove(&node_id);

        if context.is_none() {
            self.model
                .resolve_cache
                .borrow_mut()
                .insert(node_id, res.clone());
        }
        res
    }

    fn resolve_subscript_path(
        &self,
        sub: &ExprSubscript,
        context: Option<(&'a ExprCall, &'a StmtFunctionDef)>,
    ) -> Option<Vec<Name>> {
        let mut value_path = self.resolve_expr_import_path_internal(&sub.value, context)?;
        let qn = QualifiedName::from_segments(value_path.clone());

        if qn.is_module_registry() {
            return self.resolve_expr_import_path_internal(&sub.slice, context);
        }

        if qn.last() == Some("__dict__") {
            value_path.pop();
            let mut path = value_path;
            let attr_path = self.resolve_expr_import_path_internal(&sub.slice, context)?;
            path.push(Name::from(
                attr_path
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(""),
            ));
            Some(path)
        } else {
            None
        }
    }

    fn resolve_name_path(
        &self,
        name: &ExprName,
        context: Option<(&'a ExprCall, &'a StmtFunctionDef)>,
    ) -> Option<Vec<Name>> {
        if let Some((call, func)) = context {
            for (i, param) in func.parameters.args.iter().enumerate() {
                if param.name() == name.id.as_str() && i < call.arguments.args.len() {
                    return self.resolve_expr_import_path_internal(&call.arguments.args[i], None);
                }
            }
        }

        let node_id = name.node_index().load().as_u32()?;
        let last_expr = self
            .model
            .expr_mapping
            .get(&node_id)
            .and_then(|exprs| exprs.last());

        if let Some(last_expr) = last_expr {
            self.resolve_expr_import_path_internal(last_expr, context)
        } else {
            self.resolve_binding_import_path(name.id.as_str())
        }
    }

    fn resolve_attribute_path(
        &self,
        attr: &ExprAttribute,
        context: Option<(&'a ExprCall, &'a StmtFunctionDef)>,
    ) -> Option<Vec<Name>> {
        let mut base_path = self.resolve_expr_import_path_internal(&attr.value, context)?;
        base_path.push(Name::from(attr.attr.as_str()));
        Some(base_path)
    }

    fn resolve_binop_path(
        &self,
        binop: &ExprBinOp,
        context: Option<(&'a ExprCall, &'a StmtFunctionDef)>,
    ) -> Option<Vec<Name>> {
        let l = self.resolve_expr_import_path_internal(&binop.left, context)?;
        let r = self.resolve_expr_import_path_internal(&binop.right, context)?;
        Some(vec![Name::from(format!(
            "{}{}",
            l.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(""),
            r.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("")
        ))])
    }

    fn resolve_call_path(
        &self,
        call: &ExprCall,
        context: Option<(&'a ExprCall, &'a StmtFunctionDef)>,
    ) -> Option<Vec<Name>> {
        if let Some(node_id) = call.node_index().load().as_u32() {
            if let Some(exprs) = self.model.expr_mapping.get(&node_id) {
                if let Some(last_expr) = exprs.last() {
                    return self.resolve_expr_import_path_internal(last_expr, context);
                }
            }
        }

        let qn = self.resolve_qualified_name_internal(&call.func)?;

        if qn.is_import_call() && !call.arguments.args.is_empty() {
            let arg_path =
                self.resolve_expr_import_path_internal(&call.arguments.args[0], context)?;
            return Some(
                arg_path
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join("")
                    .split('.')
                    .map(Name::from)
                    .collect(),
            );
        }

        if qn.is_getattr() && call.arguments.args.len() >= 2 {
            let mut path =
                self.resolve_expr_import_path_internal(&call.arguments.args[0], context)?;
            let attr_path =
                self.resolve_expr_import_path_internal(&call.arguments.args[1], context)?;
            path.push(Name::from(
                attr_path
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(""),
            ));
            return Some(path);
        }

        if qn.is_io_resource_constructor() {
            return Some(qn.segments_slice().to_vec());
        }

        if qn.is_vars_function() {
            return Some(vec![Name::from(qn.first()?)]);
        }

        if qn.is_eval() && !call.arguments.args.is_empty() {
            let arg_path =
                self.resolve_expr_import_path_internal(&call.arguments.args[0], context)?;
            return Some(
                arg_path
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join("")
                    .split('.')
                    .map(Name::from)
                    .collect(),
            );
        }

        if qn.last() == Some("get") && !call.arguments.args.is_empty() {
            let mut segments = qn.segments_slice().to_vec();
            segments.pop();
            let base_qn = QualifiedName::from_segments(segments);
            if base_qn.is_module_registry() {
                return self.resolve_expr_import_path_internal(&call.arguments.args[0], context);
            }

            if base_qn.last() == Some("__dict__") {
                let mut path = base_qn.segments_slice().to_vec();
                path.pop();
                let attr_path =
                    self.resolve_expr_import_path_internal(&call.arguments.args[0], context)?;
                path.push(Name::from(
                    attr_path
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(""),
                ));
                return Some(path);
            }
        }

        self.resolve_function_call_path(call)
    }

    fn resolve_function_call_path(&self, call: &ExprCall) -> Option<Vec<Name>> {
        if let Expr::Name(func_name) = call.func.as_ref() {
            if let Some(binding) = self.lookup_binding(func_name.id.as_str())
                && let BindingKind::Function = binding.kind
                && let Some(func) = binding.function_def
            {
                let mut visitor = ruff_python_ast::helpers::ReturnStatementVisitor::default();
                visitor.visit_body(&func.body);

                let return_expr = visitor.returns.first().and_then(|r| r.value.as_deref());

                if let Some(ret_expr) = return_expr {
                    return self.resolve_expr_import_path_internal(ret_expr, Some((call, func)));
                }
            }
        }
        None
    }

    fn resolve_import_binding(&self, binding: &SymbolBinding) -> Option<Vec<Name>> {
        binding.imported_path.as_ref().map(|path| {
            path.iter()
                .map(|s| Name::from(s.as_str()))
                .collect::<Vec<Name>>()
        })
    }

    fn resolve_builtin_binding(&self, name: &str) -> Option<Vec<Name>> {
        Some(vec![Name::from(name)])
    }

    fn resolve_assignment_binding(&self, binding: &SymbolBinding) -> Option<Vec<Name>> {
        if let Some(value_expr) = binding.value_expr {
            self.resolve_expr_import_path(value_expr)
        } else {
            None
        }
    }

    fn resolve_binding_import_path(&self, name: &str) -> Option<Vec<Name>> {
        if let Some(binding) = self.lookup_binding(name) {
            match binding.kind {
                BindingKind::Import => self.resolve_import_binding(binding),
                BindingKind::Builtin => self.resolve_builtin_binding(name),
                BindingKind::Assignment => self.resolve_assignment_binding(binding),
                BindingKind::Function => None,
            }
        } else {
            None
        }
    }

    pub fn resolve_qualified_name<'b>(&'b self, expr: &'b Expr) -> Option<QualifiedName> {
        self.resolve_qualified_name_internal(expr)
    }

    fn resolve_qualified_name_internal<'b>(&'b self, expr: &'b Expr) -> Option<QualifiedName> {
        if let Some(mut path) = self.resolve_expr_import_path(expr) {
            if path.len() == 1 {
                let name = path.remove(0);
                if let Some(binding) = self.lookup_binding(&name)
                    && matches!(binding.kind, BindingKind::Builtin)
                {
                    return Some(QualifiedName::from_segments(vec![name]));
                }
                path.push(name);
            }
            return Some(QualifiedName::from_segments(path));
        }

        let target = match expr {
            Expr::Call(call) => &call.func,
            _ => expr,
        };
        if let Some(mut path) = self.resolve_expr_import_path(target) {
            if path.len() == 1 {
                let name = path.remove(0);
                if let Some(binding) = self.lookup_binding(&name)
                    && matches!(binding.kind, BindingKind::Builtin)
                {
                    return Some(QualifiedName::from_segments(vec![name]));
                }
                path.push(name);
            }
            Some(QualifiedName::from_segments(path))
        } else {
            self.collect_attribute_segments(target)
                .map(QualifiedName::from_segments)
        }
    }

    pub fn collect_attribute_segments(&self, expr: &Expr) -> Option<Vec<String>> {
        let mut segments = Vec::new();
        let mut current = expr;
        while let Expr::Attribute(attr) = current {
            segments.push(attr.attr.to_string());
            current = &attr.value;
        }
        if let Expr::Name(name) = current {
            segments.push(name.id.to_string());
            segments.reverse();
            Some(segments)
        } else {
            None
        }
    }

    pub fn get_call_qualified_name(&self, node_id: NodeId) -> Option<&QualifiedName> {
        self.model.call_qualified_names.get(&node_id)
    }

    pub fn get_qualified_name<T>(&self, node: &T) -> Option<&QualifiedName>
    where
        T: HasNodeIndex,
    {
        node.node_index()
            .load()
            .as_u32()
            .and_then(|id| self.get_call_qualified_name(id))
    }
}
