use crate::audit::resolver::resolve_assigment_to_imports;
use crate::audit::result::{AuditItem, AuditResult};
use crate::io::list_python_files;
use crate::rules::{expression, statement};
use itertools::Itertools;
use log::error;
use ruff_linter::Locator;
use ruff_python_ast;
use ruff_python_ast::helpers::collect_import_from_member;
use ruff_python_ast::identifier::*;
use ruff_python_ast::visitor::Visitor;
use ruff_python_ast::{self as ast, Expr, Stmt};
use ruff_python_semantic::{
    BindingFlags, BindingId, BindingKind, FromImport, Import, Module, ModuleKind, ModuleSource,
    SemanticModel, StarImport, SubmoduleImport,
};
use ruff_python_stdlib::builtins::{MAGIC_GLOBALS, python_builtins};
use ruff_text_size::TextRange;
use std::path::Path;

const PYTHON_MINOR_VERSION: u8 = 13;

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

    fn bind_builtins(&mut self) {
        let mut bind_builtin = |builtin| {
            let binding_id = self.semantic.push_builtin();
            let scope = self.semantic.global_scope_mut();
            scope.add(builtin, binding_id);
        };
        let standard_builtins = python_builtins(PYTHON_MINOR_VERSION, false);
        for builtin in standard_builtins {
            bind_builtin(builtin);
        }
        for builtin in MAGIC_GLOBALS {
            bind_builtin(builtin);
        }
    }

    pub fn add_binding(
        &mut self,
        name: &'a str,
        range: TextRange,
        kind: BindingKind<'a>,
        mut flags: BindingFlags,
    ) -> BindingId {
        // Determine the scope to which the binding belongs.
        // Per [PEP 572](https://peps.python.org/pep-0572/#scope-of-the-target), named
        // expressions in generators and comprehensions bind to the scope that contains the
        // outermost comprehension.
        let scope_id = if kind.is_named_expr_assignment() {
            self.semantic
                .scopes
                .ancestor_ids(self.semantic.scope_id)
                .find_or_last(|scope_id| !self.semantic.scopes[*scope_id].kind.is_generator())
                .unwrap_or(self.semantic.scope_id)
        } else {
            self.semantic.scope_id
        };

        if self.semantic.in_exception_handler() {
            flags |= BindingFlags::IN_EXCEPT_HANDLER;
        }
        if self.semantic.in_assert_statement() {
            flags |= BindingFlags::IN_ASSERT_STATEMENT;
        }

        // Create the `Binding`.
        let binding_id = self.semantic.push_binding(range, kind, flags);

        // If the name is private, mark is as such.
        if name.starts_with('_') {
            self.semantic.bindings[binding_id].flags |= BindingFlags::PRIVATE_DECLARATION;
        }

        // If there's an existing binding in this scope, copy its references.
        if let Some(shadowed_id) = self.semantic.scopes[scope_id].get(name) {
            // If this is an annotation, and we already have an existing value in the same scope,
            // don't treat it as an assignment, but track it as a delayed annotation.
            if self.semantic.binding(binding_id).kind.is_annotation() {
                self.semantic
                    .add_delayed_annotation(shadowed_id, binding_id);
                return binding_id;
            }

            // Avoid shadowing builtins.
            let shadowed = &self.semantic.bindings[shadowed_id];
            if !matches!(
                shadowed.kind,
                BindingKind::Builtin | BindingKind::Deletion | BindingKind::UnboundException(_)
            ) {
                let references = shadowed.references.clone();
                let is_global = shadowed.is_global();
                let is_nonlocal = shadowed.is_nonlocal();

                // If the shadowed binding was global, then this one is too.
                if is_global {
                    self.semantic.bindings[binding_id].flags |= BindingFlags::GLOBAL;
                }

                // If the shadowed binding was non-local, then this one is too.
                if is_nonlocal {
                    self.semantic.bindings[binding_id].flags |= BindingFlags::NONLOCAL;
                }

                self.semantic.bindings[binding_id].references = references;
            }
        } else if let Some(shadowed_id) = self
            .semantic
            .scopes
            .ancestors(scope_id)
            .skip(1)
            .filter(|scope| scope.kind.is_function() || scope.kind.is_module())
            .find_map(|scope| scope.get(name))
        {
            // Otherwise, if there's an existing binding in a parent scope, mark it as shadowed.
            self.semantic
                .shadowed_bindings
                .insert(binding_id, shadowed_id);
        }

        // Add the binding to the scope.
        let scope = &mut self.semantic.scopes[scope_id];
        scope.add(name, binding_id);

        binding_id
    }

    fn visit_body(&mut self, body: &'a [Stmt]) {
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
                resolve_assigment_to_imports(assign, self);
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
                        self.add_binding(
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
                        self.add_binding(
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
                        self.add_binding(
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
                        self.add_binding(
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
        self.semantic.push_node(expr);

        ast::visitor::walk_expr(self, expr);
        expression::analyze(expr, self);
    }
}

/// Parse a Python file and perform audit.
pub fn audit_file(file_path: &Path) -> Result<AuditResult, String> {
    let source_code = std::fs::read_to_string(file_path);
    if let Ok(source_code) = source_code {
        let audit_items = audit_source(file_path, source_code.clone());
        if let Ok(audit_items) = audit_items {
            Ok(AuditResult {
                path: file_path.to_path_buf(),
                items: audit_items,
                source_code,
            })
        } else {
            Err(audit_items.err().unwrap())
        }
    } else {
        Err(format!("Unable to read file: {}", file_path.display()))
    }
}

/// Audit multiple files lazily and return an iterator of results.
pub fn audit_path(file_path: &Path) -> Result<impl Iterator<Item = AuditResult>, &str> {
    if let Some(files) = list_python_files(file_path) {
        let iter = files
            .into_iter()
            .filter_map(|path_buf| match audit_file(&path_buf) {
                Ok(result) => Some(result),
                Err(e) => {
                    error!("Error auditing file {}: {}", path_buf.display(), e);
                    None
                }
            });
        Ok(iter)
    } else {
        Err("No Python files found")
    }
}

fn audit_source(file_path: &Path, source: String) -> Result<Vec<AuditItem>, String> {
    let parsed = ruff_python_parser::parse_unchecked_source(&source, ast::PySourceType::Python);
    let locator = Locator::new(&source);
    let python_ast = parsed.suite();
    let module = Module {
        kind: ModuleKind::Module,
        source: ModuleSource::File(file_path),
        python_ast,
        name: None,
    };
    let semantic = SemanticModel::new(&[], file_path, module);
    let mut checker = Checker::new(semantic, &locator);
    checker.bind_builtins();
    checker.visit_body(python_ast);
    Ok(checker.audit_results)
}
