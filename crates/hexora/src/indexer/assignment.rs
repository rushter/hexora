use crate::indexer::index::NodeIndexer;
use crate::indexer::scope::SymbolBinding;
use ruff_python_ast::name::Name;
use ruff_python_ast::*;

impl<'a> NodeIndexer<'a> {
    pub(crate) fn handle_assign_stmt(&mut self, assign: &'a StmtAssign) {
        for target in &assign.targets {
            self.handle_assignment_target(target, &assign.value);
        }
    }

    pub(crate) fn handle_aug_assign_stmt(&mut self, aug_assign: &'a StmtAugAssign) {
        self.handle_aug_assign(&aug_assign.target, &aug_assign.value);
    }

    pub(crate) fn add_import_binding(&mut self, local: String, qualified: Vec<Name>) {
        let sym = SymbolBinding::import(qualified);
        self.current_scope_mut().symbols.insert(local, sym);
    }

    pub(crate) fn handle_import_stmt(&mut self, import_stmt: &StmtImport) {
        for alias in &import_stmt.names {
            let local = alias
                .asname
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| alias.name.split('.').next().unwrap().to_string());
            let qualified: Vec<Name> = alias.name.split('.').map(Name::from).collect();
            self.add_import_binding(local, qualified);
        }
    }

    pub(crate) fn handle_import_from_stmt(&mut self, import_from_stmt: &StmtImportFrom) {
        let base = import_from_stmt.module.as_deref().unwrap_or("");
        for alias in &import_from_stmt.names {
            if alias.name.as_str() == "*" {
                continue;
            }
            let local = alias
                .asname
                .as_ref()
                .map(|s| s.to_string())
                .unwrap_or_else(|| alias.name.to_string());
            let mut qualified: Vec<Name> = Vec::new();
            if import_from_stmt.level > 0 {
                qualified.push(Name::from(
                    ".".repeat((import_from_stmt.level - 1) as usize),
                ));
            }
            if !base.is_empty() {
                qualified.extend(base.split('.').map(Name::from));
            }
            qualified.push(Name::from(alias.name.as_str()));
            self.add_import_binding(local, qualified);
        }
    }

    pub(crate) fn handle_aug_assign(&mut self, target: &'a Expr, value: &'a Expr) {
        match target {
            Expr::Name(ExprName { id, .. }) => {
                let taint = self.get_taint(value);
                if let Some(symbol) = self.current_scope_mut().symbols.get_mut(id.as_str()) {
                    symbol.add_assigned_expression(value);
                    symbol.taint.extend(taint);
                }
            }
            Expr::Attribute(attr) => {
                self.handle_self_attribute_assignment(attr, value);
            }
            _ => {}
        }
    }

    pub(crate) fn handle_name_assignment(&mut self, name: &ExprName, value: &'a Expr) {
        let taint = self.get_taint(value);
        let symbols = &mut self.current_scope_mut().symbols;
        if let Some(symbol) = symbols.get_mut(name.id.as_str()) {
            symbol.add_assigned_expression(value);
            symbol.taint.extend(taint);
        } else {
            let mut symbol = SymbolBinding::assignment(Some(value));
            symbol.taint = taint;
            symbols.insert(name.id.to_string(), symbol);
        }
    }

    pub(crate) fn handle_self_attribute_assignment(
        &mut self,
        attr: &ExprAttribute,
        value: &'a Expr,
    ) {
        if let Expr::Name(ExprName { id: base_name, .. }) = &*attr.value
            && base_name.as_str() == "self"
            && let Some(idx) = self.find_class_scope()
        {
            let taint = self.get_taint(value);
            let symbols = &mut self.scope_stack[idx].symbols;
            if let Some(symbol) = symbols.get_mut(attr.attr.as_str()) {
                symbol.add_assigned_expression(value);
                symbol.taint.extend(taint);
            } else {
                let mut symbol = SymbolBinding::assignment(Some(value));
                symbol.taint = taint;
                symbols.insert(attr.attr.to_string(), symbol);
            }
        }
    }

    pub(crate) fn handle_attribute_assignment(&mut self, attr: &ExprAttribute, value: &'a Expr) {
        self.handle_self_attribute_assignment(attr, value);
    }

    pub(crate) fn handle_sequence_assignment(&mut self, target_elts: &[&'a Expr], value: &'a Expr) {
        if let Some(value_elts) = match value {
            Expr::Tuple(ExprTuple { elts, .. }) | Expr::List(ExprList { elts, .. }) => Some(elts),
            _ => None,
        } {
            if target_elts.len() == value_elts.len() {
                for i in 0..target_elts.len() {
                    self.handle_assignment_target(target_elts[i], &value_elts[i]);
                }
            }
        } else {
            for elt in target_elts.iter() {
                self.handle_assignment_target(elt, value);
            }
        }
    }

    pub(crate) fn handle_assignment_target(&mut self, target: &'a Expr, value: &'a Expr) {
        match target {
            Expr::Name(name) => self.handle_name_assignment(name, value),
            Expr::Attribute(attr) => self.handle_attribute_assignment(attr, value),
            Expr::Subscript(sub) => self.handle_subscript_assignment(sub, value),
            Expr::Tuple(ExprTuple { elts, .. }) | Expr::List(ExprList { elts, .. }) => {
                let target_refs: Vec<&'a Expr> = elts.iter().collect();
                self.handle_sequence_assignment(&target_refs, value)
            }
            _ => {}
        }
    }

    pub(crate) fn handle_subscript_assignment(&mut self, sub: &ExprSubscript, value: &'a Expr) {
        if let Expr::Name(name) = sub.value.as_ref() {
            self.handle_name_assignment(name, value);
        }
    }
}
