use itertools::Itertools;
use ruff_python_semantic::{BindingFlags, BindingId, BindingKind, SemanticModel};
use ruff_python_stdlib::builtins::{MAGIC_GLOBALS, python_builtins};
use ruff_text_size::TextRange;

const PYTHON_MINOR_VERSION: u8 = 13;

pub fn add_binding<'a>(
    semantic_model: &mut SemanticModel<'a>,
    name: &'a str,
    range: TextRange,
    kind: BindingKind<'a>,
    flags: BindingFlags,
) -> BindingId {
    // Determine the scope to which the binding belongs.
    // Per [PEP 572](https://peps.python.org/pep-0572/#scope-of-the-target), named
    // expressions in generators and comprehensions bind to the scope that contains the
    // outermost comprehension.
    let scope_id = if kind.is_named_expr_assignment() {
        let current_scope_id = semantic_model.scope_id;
        semantic_model
            .scopes
            .ancestor_ids(current_scope_id)
            .find_or_last(|scope_id| !semantic_model.scopes[*scope_id].kind.is_generator())
            .unwrap_or(current_scope_id)
    } else {
        semantic_model.scope_id
    };

    let binding_id = semantic_model.push_binding(range, kind, flags);
    let scope = &mut semantic_model.scopes[scope_id];
    scope.add(name, binding_id);

    binding_id
}

pub fn bind_builtins(semantic_model: &mut SemanticModel) {
    let mut bind_builtin = |builtin| {
        let binding_id = semantic_model.push_builtin();
        let scope = semantic_model.global_scope_mut();
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
