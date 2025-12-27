use crate::indexer::index::NodeIndexer;
use crate::indexer::resolver::get_expression_range;
use crate::indexer::taint::TaintKind;
use hexora_io::locator::Locator;
use ruff_python_ast::visitor::source_order::SourceOrderVisitor;
use ruff_python_ast::*;
use ruff_python_ast::{Expr, PySourceType, Stmt};
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use unindent::unindent;

fn convert_to_strings<'a>(
    locator: &Locator<'a>,
    mappings: &HashMap<u32, Vec<&Expr>>,
) -> HashMap<u32, Vec<&'a str>> {
    let mut result: HashMap<u32, Vec<&'a str>> = HashMap::new();

    for (node_id, exprs) in mappings.iter() {
        let res: Vec<&str> = exprs
            .iter()
            .map(|e| locator.slice(get_expression_range(e)))
            .collect();
        result.insert(*node_id, res);
    }
    result
}

fn get_result(source: &str) -> HashMap<u32, Vec<&str>> {
    let parsed = ruff_python_parser::parse_unchecked_source(source, PySourceType::Python);
    let locator = Locator::new(source);
    let python_ast = parsed.suite();
    let mut indexer = NodeIndexer::new();
    indexer.visit_body(python_ast);
    convert_to_strings(&locator, &indexer.model.expr_mapping)
}

fn with_indexer<F, R>(source: &str, f: F) -> R
where
    F: FnOnce(&mut NodeIndexer, &[Stmt]) -> R,
{
    let parsed = ruff_python_parser::parse_unchecked_source(source, PySourceType::Python);
    let suite = parsed.suite();
    let mut indexer = NodeIndexer::new();
    indexer.visit_body(suite);
    f(&mut indexer, suite)
}

fn resolve_call_at_index(
    indexer: &mut NodeIndexer,
    suite: &[Stmt],
    index: usize,
) -> Option<String> {
    if let Stmt::Expr(StmtExpr { value, .. }) = &suite[index] {
        if let Expr::Call(_) = &**value {
            indexer.resolve_qualified_name(value).map(|qn| qn.as_str())
        } else {
            None
        }
    } else {
        None
    }
}

#[test]
fn test_simple_case() {
    let source = unindent(
        r#"
            a = "print"+"(123)"+";"+"123"
            b = "".join(["cc", a,"b"])"#,
    );

    let expected = HashMap::from([(1025, vec![r#""print"+"(123)"+";"+"123""#])]);
    let actual = get_result(&source);
    assert_eq!(expected, actual);
}
#[test]
fn test_correct_scoping() {
    let source = unindent(
        r#"
            c = 'first'
            def func():
                c = '10'
                c += '_trials'
                c += '_of_20'
                d = ['a',c,'b']


            def test_func_2():
                e = ['a', c, 'b']
            "#,
    );
    let expected = HashMap::from([
        (1025, vec!["'10'", "'_trials'", "'_of_20'"]),
        (1036, vec!["'first'"]),
    ]);
    let actual = get_result(&source);
    assert_eq!(expected, actual);
}
#[test]
fn test_class_scoping() {
    let source = unindent(
        r#"
            class Test:
                def __init__(self):
                    self.c = 'nope'
                def test_func(self):
                    f = ['a', self.c, 'b']
            "#,
    );
    let expected = HashMap::from([(1026, vec!["'nope'"])]);
    let actual = get_result(&source);
    assert_eq!(expected, actual);
}

#[test]
fn test_resolve_from_import_call() {
    let source = unindent(
        r#"
            from os import popen
            popen('asd')
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 1);
        assert_eq!(resolved.as_deref(), Some("os.popen"));
    });
}

#[test]
fn test_resolve_import_attr_call() {
    let source = unindent(
        r#"
            import os
            os.popen('asd')
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 1);
        assert_eq!(resolved.as_deref(), Some("os.popen"));
    });
}

#[test]
fn test_resolve_alias_chain_import_call() {
    let source = unindent(
        r#"
            import subprocess
            s = subprocess
            k = s
            k.check_output(["pinfo -m", ' ', "ABC"])
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 3);
        assert_eq!(resolved.as_deref(), Some("subprocess.check_output"));
    });
}

#[test]
fn test_resolve_builtin_direct_and_module() {
    let source = unindent(
        r#"
            eval("1+2")
            import builtins
            builtins.len([1,2,3])
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved0 = resolve_call_at_index(indexer, suite, 0);
        let got = resolved0.expect("expected qualified name");
        assert_eq!(
            got, "1+2",
            "expected builtin eval qualified name to be '1+2', got {got}"
        );

        let resolved2 = resolve_call_at_index(indexer, suite, 2);
        assert_eq!(resolved2.as_deref(), Some("builtins.len"));
    });
}

#[test]
fn test_resolve_unknown_name() {
    let source = unindent(
        r#"
            full_length([1,2,3])
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 0);
        assert_eq!(resolved.as_deref(), Some("full_length"));
    });
}

#[test]
fn test_scope_resolution_outside_function() {
    let source = unindent(
        r#"
            import subprocess

            def test():
                s = subprocess.call

            s(["uname -a"])
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 2);
        assert_eq!(resolved.as_deref(), Some("s"));
    });
}

#[test]
fn test_contains_builtins() {
    let indexer = NodeIndexer::new();
    let has_eval = indexer
        .scope_stack
        .first()
        .unwrap()
        .symbols
        .contains_key("eval");
    let has_getattr = indexer
        .scope_stack
        .first()
        .unwrap()
        .symbols
        .contains_key("getattr");
    assert!(
        has_eval && has_getattr,
        "Builtins should be bound in NodeIndexer global scope"
    );
}

#[test]
fn test_contains_magic_vars() {
    let indexer = NodeIndexer::new();
    let has_dunder_name = indexer
        .scope_stack
        .first()
        .unwrap()
        .symbols
        .contains_key("__name__");
    assert!(
        has_dunder_name,
        "Magic globals like __name__ should be bound"
    );
}

#[test]
fn test_sequence_unpacking_insufficient_values() {
    let source = "a, b = [1]";
    with_indexer(source, |indexer, _suite| {
        let scope = &indexer.scope_stack[0];
        assert!(!scope.symbols.contains_key("a"));
        assert!(!scope.symbols.contains_key("b"));
    });
}

#[test]
fn test_sequence_unpacking_extra_values() {
    let source = "a, b = [1, 2, 3]";
    with_indexer(source, |indexer, _suite| {
        let scope = &indexer.scope_stack[0];
        assert!(!scope.symbols.contains_key("a"));
        assert!(!scope.symbols.contains_key("b"));
    });
}

#[test]
fn test_sequence_unpacking_exact_match() {
    let source = "a, b = [1, 2]";
    with_indexer(source, |indexer, _suite| {
        let scope = &indexer.scope_stack[0];
        let a_binding = scope.symbols.get("a").unwrap();
        assert_eq!(a_binding.assigned_expressions.len(), 1);
        let b_binding = scope.symbols.get("b").unwrap();
        assert_eq!(b_binding.assigned_expressions.len(), 1);
    });
}

#[test]
fn test_aug_assign_attribute() {
    let source = unindent(
        r#"
            class Test:
                def __init__(self):
                    self.x = 1
                def test_func(self):
                    self.x += 2
                    y = self.x
            "#,
    );
    let expected = HashMap::from([(1027, vec!["1", "2"])]);
    let actual = get_result(&source);
    assert_eq!(expected, actual);
}

#[test]
fn test_aug_assign_attribute_no_prior() {
    let source = unindent(
        r#"
            class Test:
                def test_func(self):
                    self.x += 2
                    y = self.x
            "#,
    );
    let expected = HashMap::from([(1016, vec!["2"])]);
    let actual = get_result(&source);
    assert_eq!(expected, actual);
}

#[test]
fn test_clear_state() {
    let source = "a = 1; b = a";
    let parsed = ruff_python_parser::parse_unchecked_source(source, PySourceType::Python);
    let mut indexer = NodeIndexer::new();
    indexer.visit_body(parsed.suite());

    assert!(!indexer.model.expr_mapping.is_empty());
    let old_index = indexer.index.load(Ordering::Relaxed);
    assert!(old_index > 1000);

    indexer.clear_state();
    assert!(indexer.model.expr_mapping.is_empty());
    assert!(indexer.model.call_qualified_names.is_empty());
    assert!(indexer.model.comments.is_empty());
    assert_eq!(indexer.index.load(Ordering::Relaxed), 1000);
    assert_eq!(indexer.scope_stack.len(), 1);
    assert!(indexer.scope_stack[0].symbols.contains_key("print"));
}

#[test]
fn test_resolve_import_dunder() {
    let source = unindent(
        r#"
            os = __import__("os")
            os.system("ls")
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 1);
        assert_eq!(resolved.as_deref(), Some("os.system"));
    });
}

#[test]
fn test_resolve_importlib() {
    let source = unindent(
        r#"
            import importlib
            os = importlib.import_module("os")
            os.system("ls")
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 2);
        assert_eq!(resolved.as_deref(), Some("os.system"));
    });
}

#[test]
fn test_resolve_getattr() {
    let source = unindent(
        r#"
            import os
            s = getattr(os, "system")
            s("ls")
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 2);
        assert_eq!(resolved.as_deref(), Some("os.system"));
    });
}

#[test]
fn test_resolve_getattr_nested() {
    let source = unindent(
        r#"
            getattr(__import__("os"), "system")("ls")
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 0);
        assert_eq!(resolved.as_deref(), Some("os.system"));
    });
}

#[test]
fn test_resolve_function_return() {
    let source = unindent(
        r#"
            import os
            def get_os():
                return os
            get_os().system("ls")
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 2);
        assert_eq!(resolved.as_deref(), Some("os.system"));
    });
}

#[test]
fn test_resolve_function_return_parameterized() {
    let source = unindent(
        r#"
            import os
            def get_mod(m):
                return m
            get_mod(os).system("ls")
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 2);
        assert_eq!(resolved.as_deref(), Some("os.system"));
    });
}

#[test]
fn test_resolve_vars_subscript() {
    let source = unindent(
        r#"
            vars()["os"].system("ls")
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 0);
        assert_eq!(resolved.as_deref(), Some("os.system"));
    });
}

#[test]
fn test_resolve_binop_import() {
    let source = unindent(
        r#"
            __import__("o" + "s").system("ls")
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 0);
        assert_eq!(resolved.as_deref(), Some("os.system"));
    });
}

#[test]
fn test_resolve_import_multi_segment_arg() {
    let source = unindent(
        r#"
            __import__("os." + "path").join("a")
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 0);
        assert_eq!(resolved.as_deref(), Some("os.path.join"));
    });
}

#[test]
fn test_resolve_binop_multi_segment() {
    let source = unindent(
        r#"
            __import__("os.pa" + "th" + ".join")
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 0);
        assert_eq!(resolved.as_deref(), Some("os.path.join"));
    });
}

#[test]
fn test_taint_propagation_basic() {
    let source = unindent(
        r#"
            import os
            x = os.getenv("FOO")
            y = x
            z = y + "bar"
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        if let Stmt::Assign(StmtAssign { value, .. }) = &suite[3] {
            let taints = indexer.get_taint(value);
            assert!(taints.contains(&TaintKind::EnvVariables));
        } else {
            panic!("Expected assignment at index 3");
        }
    });
}

#[test]
fn test_taint_method_mutation() {
    let source = unindent(
        r#"
            import os
            l = []
            l.append(os.getenv("FOO"))
            x = l
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        if let Stmt::Assign(StmtAssign { value, .. }) = &suite[3] {
            let taints = indexer.get_taint(value);
            assert!(taints.contains(&TaintKind::EnvVariables));
        } else {
            panic!("Expected assignment at index 3");
        }
    });
}

#[test]
fn test_taint_function_return() {
    let source = unindent(
        r#"
            import os
            def f(x):
                return x
            a = f(os.getenv("FOO"))
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        if let Stmt::Assign(StmtAssign { value, .. }) = &suite[2] {
            let taints = indexer.get_taint(value);
            assert!(taints.contains(&TaintKind::EnvVariables));
        } else {
            panic!("Expected assignment at index 2");
        }
    });
}

#[test]
fn test_taint_comprehension() {
    let source = unindent(
        r#"
            import os
            res = [x for x in [os.getenv("FOO")]]
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        if let Stmt::Assign(StmtAssign { value, .. }) = &suite[1] {
            let taints = indexer.get_taint(value);
            assert!(taints.contains(&TaintKind::EnvVariables));
        } else {
            panic!("Expected assignment at index 1");
        }
    });
}

#[test]
fn test_taint_attribute() {
    let source = unindent(
        r#"
            import os
            x = os.environ["FOO"]
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        if let Stmt::Assign(StmtAssign { value, .. }) = &suite[1] {
            let taints = indexer.get_taint(value);
            assert!(taints.contains(&TaintKind::EnvVariables));
        } else {
            panic!("Expected assignment at index 1");
        }
    });
}

#[test]
fn test_resolve_relative_import() {
    let source = unindent(
        r#"
            from . import utils
            utils.do_something()
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 1);
        assert_eq!(resolved.as_deref(), Some(".utils.do_something"));
    });
}

#[test]
fn test_resolve_relative_import_nested() {
    let source = unindent(
        r#"
            from ..module import func
            func()
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 1);
        assert_eq!(resolved.as_deref(), Some("..module.func"));
    });
}

#[test]
fn test_taint_for_loop() {
    let source = unindent(
        r#"
            import os
            for x in [os.getenv("FOO")]:
                y = x
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let for_stmt = &suite[1];
        if let Stmt::For(f) = for_stmt {
            if let Stmt::Assign(assign) = &f.body[0] {
                let taints = indexer.get_taint(&assign.value);
                assert!(taints.contains(&TaintKind::EnvVariables));
            }
        }
    });
}

#[test]
fn test_taint_dict_update() {
    let source = unindent(
        r#"
            import os
            d = {}
            d.update({"key": os.getenv("BAR")})
            val = d["key"]
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        if let Stmt::Assign(assign) = &suite[3] {
            let taints = indexer.get_taint(&assign.value);
            assert!(taints.contains(&TaintKind::EnvVariables));
        }
    });
}

#[test]
fn test_taint_fingerprinting_platform() {
    let source = unindent(
        r#"
            import platform
            node = platform.node()
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        if let Stmt::Assign(assign) = &suite[1] {
            let taints = indexer.get_taint(&assign.value);
            assert!(taints.contains(&TaintKind::Fingerprinting));
        }
    });
}

#[test]
fn test_taint_starred_expression() {
    let source = unindent(
        r#"
            import os
            x = [os.getenv("FOO")]
            y = [*x]
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        if let Stmt::Assign(assign) = &suite[2] {
            let taints = indexer.get_taint(&assign.value);
            assert!(taints.contains(&TaintKind::EnvVariables));
        }
    });
}

#[test]
fn test_taint_dict_unpacking() {
    let source = unindent(
        r#"
            import os
            x = {"a": os.getenv("FOO")}
            y = {**x}
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        if let Stmt::Assign(assign) = &suite[2] {
            let taints = indexer.get_taint(&assign.value);
            assert!(taints.contains(&TaintKind::EnvVariables));
        }
    });
}

#[test]
fn test_taint_with_open() {
    let source = unindent(
        r#"
            with open("test.txt", "r") as f:
                content = f.read()
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let with_stmt = &suite[0];
        if let Stmt::With(w) = with_stmt {
            if let Stmt::Assign(assign) = &w.body[0] {
                let taints = indexer.get_taint(&assign.value);
                assert!(taints.contains(&TaintKind::FileSourced));
            }
        }
    });
}

#[test]
fn test_taint_dict_get() {
    let source = unindent(
        r#"
            import os
            d = {"key": os.getenv("BAR")}
            val = d.get("key")
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        if let Stmt::Assign(assign) = &suite[2] {
            let taints = indexer.get_taint(&assign.value);
            assert!(taints.contains(&TaintKind::EnvVariables));
        }
    });
}

#[test]
fn test_shadowing_builtin() {
    let source = unindent(
        r#"
            eval = print
            eval("hello")
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 1);
        assert_eq!(resolved.as_deref(), Some("print"));
    });
}

#[test]
fn test_resolve_sys_modules_subscript() {
    let source = unindent(
        r#"
            import sys
            sys.modules["os"].system("ls")
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        let resolved = resolve_call_at_index(indexer, suite, 1);
        assert_eq!(resolved.as_deref(), Some("os.system"));
    });
}

#[test]
fn test_taint_list_pop() {
    let source = unindent(
        r#"
            import os
            l = [os.getenv("X")]
            x = l.pop()
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        if let Stmt::Assign(assign) = &suite[2] {
            let taints = indexer.get_taint(&assign.value);
            assert!(taints.contains(&TaintKind::EnvVariables));
        }
    });
}

#[test]
fn test_taint_list_extend() {
    let source = unindent(
        r#"
            import os
            l = []
            l.extend([os.getenv("X")])
            res = l
            "#,
    );
    with_indexer(&source, |indexer, suite| {
        if let Stmt::Assign(assign) = &suite[3] {
            let taints = indexer.get_taint(&assign.value);
            assert!(taints.contains(&TaintKind::EnvVariables));
        }
    });
}
