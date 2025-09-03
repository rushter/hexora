use crate::audit::resolver::resolve_assignment_to_imports;
use crate::audit::result::AuditItem;
use crate::indexer::semantic::add_binding;
use crate::rules::{expression, statement};
use ruff_linter::Locator;
use ruff_python_ast;
use ruff_python_ast::helpers::collect_import_from_member;
use ruff_python_ast::identifier::*;
use ruff_python_ast::visitor::Visitor;
use ruff_python_ast::{self as ast, Expr, Stmt};
use ruff_python_semantic::{
    BindingFlags, BindingKind, FromImport, Import, SemanticModel, StarImport, SubmoduleImport,
};

pub struct Checker<'a> {
    pub semantic: SemanticModel<'a>,
    pub imports: Vec<&'a Stmt>,
    pub audit_results: Vec<AuditItem>,
    pub locator: &'a Locator<'a>,
}

impl<'a> Checker<'a> {
    pub fn new(semantic: SemanticModel<'a>, locator: &'a Locator) -> Self {
        Self {
            semantic,
            imports: Vec::new(),
            audit_results: Vec::new(),
            locator,
        }
    }

    pub const fn semantic(&self) -> &SemanticModel<'a> {
        &self.semantic
    }

    pub fn visit_body(&mut self, body: &'a [Stmt]) {
        for stmt in body {
            self.visit_stmt(stmt);
        }
    }
}

impl<'a> Visitor<'a> for Checker<'a> {
    fn visit_stmt(&mut self, stmt: &'a Stmt) {
        self.semantic.push_node(stmt);
        match stmt {
            Stmt::Assign(assign) => {
                ast::visitor::walk_stmt(self, stmt);
                resolve_assignment_to_imports(assign, self);
            }
            Stmt::Import(ast::StmtImport {
                names,
                range: _,
                node_index: _,
            }) => {
                self.imports.push(stmt);

                for alias in names {
                    let module = alias.name.split('.').next().unwrap();

                    self.semantic.add_module(module);

                    if alias.asname.is_none() && alias.name.contains('.') {
                        let qualified_name = ast::name::QualifiedName::user_defined(&alias.name);
                        add_binding(
                            &mut self.semantic,
                            module,
                            alias.identifier(),
                            BindingKind::SubmoduleImport(SubmoduleImport {
                                qualified_name: Box::new(qualified_name),
                            }),
                            BindingFlags::EXTERNAL,
                        );
                    } else {
                        let mut flags = BindingFlags::EXTERNAL;
                        if alias.asname.is_some() {
                            flags |= BindingFlags::ALIAS;
                        }
                        if alias
                            .asname
                            .as_ref()
                            .is_some_and(|asname| asname.as_str() == alias.name.as_str())
                        {
                            flags |= BindingFlags::EXPLICIT_EXPORT;
                        }

                        let name = alias.asname.as_ref().unwrap_or(&alias.name);
                        let qualified_name = ast::name::QualifiedName::user_defined(&alias.name);
                        add_binding(
                            &mut self.semantic,
                            name,
                            alias.identifier(),
                            BindingKind::Import(Import {
                                qualified_name: Box::new(qualified_name),
                            }),
                            flags,
                        );
                    }
                }
            }
            Stmt::ImportFrom(ast::StmtImportFrom {
                names,
                module,
                level,
                range: _,
                node_index: _,
            }) => {
                self.imports.push(stmt);

                let module = module.as_deref();
                let level = *level;

                // Mark the top-level module as "seen" by the semantic model.
                if level == 0
                    && let Some(module) = module.and_then(|module| module.split('.').next())
                {
                    self.semantic.add_module(module);
                }

                for alias in names {
                    if let Some("__future__") = module {
                        let name = alias.asname.as_ref().unwrap_or(&alias.name);
                        add_binding(
                            &mut self.semantic,
                            name,
                            alias.identifier(),
                            BindingKind::FutureImport,
                            BindingFlags::empty(),
                        );
                    } else if &alias.name == "*" {
                        self.semantic
                            .current_scope_mut()
                            .add_star_import(StarImport { level, module });
                    } else {
                        let mut flags = BindingFlags::EXTERNAL;
                        if alias.asname.is_some() {
                            flags |= BindingFlags::ALIAS;
                        }
                        if alias
                            .asname
                            .as_ref()
                            .is_some_and(|asname| asname.as_str() == alias.name.as_str())
                        {
                            flags |= BindingFlags::EXPLICIT_EXPORT;
                        }

                        // Given `from foo import bar`, `name` would be "bar" and `qualified_name` would
                        // be "foo.bar". Given `from foo import bar as baz`, `name` would be "baz"
                        // and `qualified_name` would be "foo.bar".
                        let name = alias.asname.as_ref().unwrap_or(&alias.name);

                        // Attempt to resolve any relative imports; but if we don't know the current
                        // module path, or the relative import extends beyond the package root,
                        // fallback to a literal representation (e.g., `[".", "foo"]`).
                        let qualified_name = collect_import_from_member(level, module, &alias.name);
                        add_binding(
                            &mut self.semantic,
                            name,
                            alias.identifier(),
                            BindingKind::FromImport(FromImport {
                                qualified_name: Box::new(qualified_name),
                            }),
                            flags,
                        );
                    }
                }
            }
            _ => ast::visitor::walk_stmt(self, stmt),
        }
        statement::analyze(stmt, self);
    }
    fn visit_expr(&mut self, expr: &'a Expr) {
        // info!("visit_expr: {:?}", expr);
        self.semantic.push_node(expr);

        ast::visitor::walk_expr(self, expr);
        expression::analyze(expr, self);
    }
}
