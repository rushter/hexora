use ruff_python_ast::*;
use std::collections::HashSet;

use crate::indexer::name::QualifiedName;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaintKind {
    Literal,
    Decoded,
    Deobfuscated,
    FileSourced,
    NetworkSourced,
    Fingerprinting,
}

pub type TaintState = HashSet<TaintKind>;

pub fn get_call_taint(segments: &[&str]) -> Option<TaintKind> {
    match segments {
        // Decoding / Deobfuscation
        ["base64", "b64decode" | "urlsafe_b64decode"]
        | ["binascii", "a2b_base64" | "unhexlify"]
        | ["bytes", "fromhex"]
        | ["zlib", "decompress"]
        | ["codecs", "decode"]
        | ["marshal", "loads"]
        | ["pickle", "loads"] => Some(TaintKind::Decoded),

        // File Sourced Data
        ["open"] | ["pathlib", "Path", "read_text" | "read_bytes"] => Some(TaintKind::FileSourced),

        // Network Sourced Data
        ["requests", "get" | "post" | "request"]
        | ["urllib", "request", "urlopen"]
        | ["http", "client", "HTTPConnection", "request"]
        | ["socket", "socket", "recv" | "recvfrom"] => Some(TaintKind::NetworkSourced),

        // OS / Environment Fingerprinting
        ["os", "uname" | "getlogin" | "getuid" | "getgid"]
        | ["getpass", "getuser"]
        | [
            "platform",
            "system" | "platform" | "version" | "release" | "node" | "processor" | "machine"
            | "architecture" | "uname",
        ]
        | ["socket", "gethostname" | "getfqdn" | "gethostbyname"]
        | ["uuid", "getnode"] => Some(TaintKind::Fingerprinting),

        _ => None,
    }
}

pub fn get_attribute_taint(segments: &[&str]) -> Vec<TaintKind> {
    match segments {
        ["os", "environ"] | ["sys", "argv"] | ["sys", "platform"] => {
            vec![TaintKind::Fingerprinting]
        }
        _ => vec![],
    }
}

pub fn should_propagate_taint(segments: &[&str]) -> bool {
    match segments {
        // Taint-stopping functions (explicitly known NOT to return tainted data based on input)
        ["len" | "int" | "float" | "bool" | "isinstance" | "type"] => false,
        _ => true,
    }
}

pub fn compute_expr_taint(
    expr: &Expr,
    get_taint: impl Fn(&Expr) -> TaintState,
    resolve_qualified_name: impl Fn(&Expr) -> Option<QualifiedName>,
) -> TaintState {
    let mut taints = TaintState::new();

    match expr {
        Expr::StringLiteral(_) | Expr::BytesLiteral(_) => {
            taints.insert(TaintKind::Literal);
        }
        Expr::BinOp(binop) => match binop.op {
            Operator::Add
            | Operator::Mod
            | Operator::Mult
            | Operator::BitOr
            | Operator::BitAnd
            | Operator::BitXor
            | Operator::LShift
            | Operator::RShift => {
                taints.extend(get_taint(&binop.left));
                taints.extend(get_taint(&binop.right));
            }
            _ => {}
        },
        Expr::UnaryOp(unop) => {
            taints.extend(get_taint(&unop.operand));
        }
        Expr::BoolOp(boolop) => {
            for value in &boolop.values {
                taints.extend(get_taint(value));
            }
        }
        Expr::If(if_expr) => {
            taints.extend(get_taint(&if_expr.body));
            taints.extend(get_taint(&if_expr.orelse));
        }
        Expr::Compare(comp) => {
            taints.extend(get_taint(&comp.left));
            for comparator in &comp.comparators {
                taints.extend(get_taint(comparator));
            }
        }
        Expr::Call(call) => {
            let qn = resolve_qualified_name(expr);
            if let Some(qn) = &qn {
                if let Some(taint) = get_call_taint(&qn.segments()) {
                    taints.insert(taint);
                }
            }

            // Propagate taint from arguments for certain functions
            let should_propagate = if let Some(qn) = qn {
                // skip functions that can't carry malicious stuff .e.g. len(), int(), etc.
                should_propagate_taint(&qn.segments())
            } else {
                // if we can't resolve, propagate taint from arguments
                true
            };

            if should_propagate {
                for arg in &call.arguments.args {
                    taints.extend(get_taint(arg));
                }
                for kw in &call.arguments.keywords {
                    taints.extend(get_taint(&kw.value));
                }

                // Propagate from receiver for common methods
                if let Expr::Attribute(attr) = call.func.as_ref() {
                    let method = attr.attr.as_str();
                    if matches!(
                        method,
                        "pop" | "get" | "copy" | "union" | "intersection" | "values" | "items"
                    ) {
                        taints.extend(get_taint(&attr.value));
                    }
                }
            }
        }
        Expr::Attribute(attr) => {
            if let Some(qn) = resolve_qualified_name(expr) {
                for taint in get_attribute_taint(&qn.segments()) {
                    taints.insert(taint);
                }
            }
            taints.extend(get_taint(&attr.value));
        }
        Expr::List(list) => {
            for elt in &list.elts {
                taints.extend(get_taint(elt));
            }
        }
        Expr::Set(set) => {
            for elt in &set.elts {
                taints.extend(get_taint(elt));
            }
        }
        Expr::Dict(dict) => {
            for item in &dict.items {
                if let Some(key) = &item.key {
                    taints.extend(get_taint(key));
                }
                taints.extend(get_taint(&item.value));
            }
        }
        Expr::Tuple(tuple) => {
            for elt in &tuple.elts {
                taints.extend(get_taint(elt));
            }
        }
        Expr::Subscript(sub) => {
            taints.extend(get_taint(&sub.value));
        }
        Expr::FString(fstring) => {
            taints.insert(TaintKind::Literal);
            for part in &fstring.value {
                if let FStringPart::FString(inner) = part {
                    for element in &inner.elements {
                        if let InterpolatedStringElement::Interpolation(interp) = element {
                            taints.extend(get_taint(&interp.expression));
                        }
                    }
                }
            }
        }
        Expr::ListComp(lc) => {
            taints.extend(get_taint(&lc.elt));
        }
        Expr::SetComp(sc) => {
            taints.extend(get_taint(&sc.elt));
        }
        Expr::DictComp(dc) => {
            taints.extend(get_taint(&dc.value));
        }
        Expr::Generator(r#gen) => {
            taints.extend(get_taint(&r#gen.elt));
        }
        Expr::Await(aw) => {
            taints.extend(get_taint(&aw.value));
        }
        Expr::Yield(y) => {
            if let Some(value) = &y.value {
                taints.extend(get_taint(value));
            }
        }
        Expr::YieldFrom(yf) => {
            taints.extend(get_taint(&yf.value));
        }
        Expr::Starred(s) => {
            taints.extend(get_taint(&s.value));
        }
        Expr::Named(n) => {
            taints.extend(get_taint(&n.value));
        }
        _ => {}
    }

    taints
}

pub fn get_method_mutation_taint(
    call: &ExprCall,
    get_taint: impl Fn(&Expr) -> TaintState,
) -> Option<(&Expr, TaintState)> {
    if let Expr::Attribute(attr) = call.func.as_ref() {
        let method = attr.attr.as_str();
        if matches!(
            method,
            "append" | "extend" | "insert" | "reverse" | "update" | "add"
        ) {
            let mut taint = TaintState::new();
            if method != "reverse" {
                for arg in &call.arguments.args {
                    taint.extend(get_taint(arg));
                }
                for kw in &call.arguments.keywords {
                    taint.extend(get_taint(&kw.value));
                }
            }
            return Some((attr.value.as_ref(), taint));
        }
    }
    None
}
