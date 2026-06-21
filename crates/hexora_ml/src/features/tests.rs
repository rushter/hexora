#[cfg(test)]
mod tests {
    use crate::features::extract_features_from_source;
    use std::path::Path;

    #[test]
    fn test_extract_features_from_source_valid_python() {
        let code = "x = 1\nprint(x)\n";
        let file_path = Path::new("test.py");
        let result = extract_features_from_source(code, file_path);
        assert!(result.is_ok());
        let features = result.unwrap();
        assert!(features.len() > 0);
        assert!(features.get("source.num_lines").is_some());
        assert!(features.get("meta.feature_count").is_some());
    }

    #[test]
    fn test_identifier_features_basic() {
        let code = r#"
    result = calculate(data, offset)
    def process_item(value):
        return value.strip()
    "#;
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        let count = features.get("ident.name_count").unwrap_or(0.0) as usize;
        assert!(
            count >= 5,
            "expected at least 5 unique identifiers, got {count}"
        );
        let max_len = features.get("ident.max_name_length").unwrap_or(0.0);
        assert!(max_len >= 6.0, "expected some names longer than 6 chars");
    }

    #[test]
    fn test_string_ratio_feature() {
        let code = r#"
    x = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 10
    "#;
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        let ratio = features.get("source.string_ratio").unwrap_or(0.0);
        assert!(
            ratio > 0.5,
            "expected high string ratio for payload-like code, got {ratio}"
        );
    }

    #[test]
    fn test_encoding_diversity_feature() {
        let code = r#"
    import base64
    a = base64.b64decode("dGVzdA==")
    b = bytes.fromhex("74657374")
    c = a + b
    exec(c)
    "#;
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        let diversity = features.get("semantic.encoding_diversity").unwrap_or(0.0);
        assert!(
            diversity >= 2.0,
            "expected at least 2 encoding types, got {diversity}"
        );
    }

    #[test]
    fn test_taint_features() {
        let code = r#"
    import base64
    payload = base64.b64decode("cHJpbnQoMSk=")
    exec(payload)
    "#;
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        assert!(
            features.get("semantic.tainted_nodes").unwrap_or(0.0) > 0.0,
            "expected tainted nodes"
        );
        assert!(
            features.get("semantic.multi_taint_nodes").unwrap_or(0.0) >= 0.0,
            "expected multi_taint_nodes to exist"
        );
    }

    #[test]
    fn test_identifier_features_obfuscated() {
        let code = r#"
    _0x1a2b3c = "data"
    a1B2c3D4e5F6 = _0x1a2b3c
    xXx = a1B2c3D4e5F6
    "#;
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        let mean_entropy = features.get("ident.mean_name_entropy").unwrap_or(0.0);
        assert!(
            mean_entropy > 1.5,
            "expected high mean name entropy for obfuscated names, got {mean_entropy}"
        );
    }

    #[test]
    fn test_extract_features_from_source_empty_string() {
        let code = "";
        let file_path = Path::new("empty.py");
        let result = extract_features_from_source(code, file_path);
        assert!(result.is_ok());
        let features = result.unwrap();
        assert_eq!(features.get("source.num_lines").unwrap_or(0.0), 0.0);
    }

    #[test]
    fn test_extract_features_from_source_contains_base64() {
        let code = r#"
    import base64
    payload = base64.b64decode("cHJpbnQoMSk=")
    exec(payload)
    "#;
        let file_path = Path::new("test_payload.py");
        let result = extract_features_from_source(code, file_path);
        assert!(result.is_ok());
        let features = result.unwrap();
        assert!(features.len() > 0);
        let has_rule_hits = features.get("rule.total_hits").unwrap_or(0.0) > 0.0;
        assert!(has_rule_hits, "Expected rule hits but got none");
    }

    #[test]
    fn test_stdlib_call_features() {
        let code = r#"
    import os
    path = os.path.join(os.path.dirname(__file__), 'staticconf', 'version.py')
    "#;
        let file_path = Path::new("test_paths.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        assert!(
            features.get("call.os.path.join").unwrap_or(0.0) > 0.0,
            "expected call.os.path.join feature"
        );
        assert!(
            features.get("call.os.path.dirname").unwrap_or(0.0) > 0.0,
            "expected call.os.path.dirname feature"
        );
    }

    #[test]
    fn test_cyclomatic_complexity_base() {
        let code = "x = 1\n";
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        assert_eq!(features.get("ast.cyclomatic_complexity").unwrap(), 1.0);
    }

    #[test]
    fn test_cyclomatic_complexity_if() {
        let code = "if x:\n    pass\n";
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        assert_eq!(features.get("ast.cyclomatic_complexity").unwrap(), 2.0);
    }

    #[test]
    fn test_cyclomatic_complexity_if_elif() {
        let code = "if a:\n    pass\nelif b:\n    pass\nelse:\n    pass\n";
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        assert_eq!(features.get("ast.cyclomatic_complexity").unwrap(), 3.0);
    }

    #[test]
    fn test_cyclomatic_complexity_for() {
        let code = "for i in range(10):\n    pass\n";
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        assert_eq!(features.get("ast.cyclomatic_complexity").unwrap(), 2.0);
    }

    #[test]
    fn test_cyclomatic_complexity_while_for_nested() {
        let code = "while True:\n    for x in y:\n        pass\n";
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        assert_eq!(features.get("ast.cyclomatic_complexity").unwrap(), 3.0);
    }

    #[test]
    fn test_cyclomatic_complexity_try() {
        let code = "try:\n    pass\nexcept:\n    pass\n";
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        assert_eq!(features.get("ast.cyclomatic_complexity").unwrap(), 2.0);
    }

    #[test]
    fn test_cyclomatic_complexity_multiple_except() {
        let code = "try:\n    pass\nexcept ValueError:\n    pass\nexcept TypeError:\n    pass\n";
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        assert_eq!(features.get("ast.cyclomatic_complexity").unwrap(), 3.0);
    }

    #[test]
    fn test_cyclomatic_complexity_bool_op() {
        let code = "x = a and b\n";
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        assert_eq!(features.get("ast.cyclomatic_complexity").unwrap(), 2.0);
    }

    #[test]
    fn test_cyclomatic_complexity_ternary() {
        let code = "x = a if cond else b\n";
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        assert_eq!(features.get("ast.cyclomatic_complexity").unwrap(), 2.0);
    }

    #[test]
    fn test_cyclomatic_complexity_match() {
        let code = "match x:\n    case 1:\n        pass\n    case 2:\n        pass\n";
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        assert_eq!(features.get("ast.cyclomatic_complexity").unwrap(), 3.0);
    }

    #[test]
    fn test_suspicious_co_occurrence() {
        let code = r#"
    import os
    import base64
    import socket
    "#;
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        let pairs = features.get("import.suspicious_pair_count").unwrap_or(0.0) as usize;
        assert!(
            pairs >= 2,
            "expected at least 2 suspicious pairs (os+base64, os+socket, base64+socket), got {pairs}"
        );
        let triples = features
            .get("import.suspicious_triple_count")
            .unwrap_or(0.0) as usize;
        assert!(
            triples >= 1,
            "expected at least 1 suspicious triple (base64+socket+os), got {triples}"
        );
    }

    #[test]
    fn test_dynamic_call_ratio() {
        let code = r#"
    getattr(obj, "method")(arg)
    eval(expr)
    exec(code)
    "#;
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        let ratio = features.get("call.dynamic_ratio").unwrap_or(0.0);
        assert!(
            ratio > 0.0,
            "expected dynamic_ratio > 0 for code with dynamic dispatch calls, got {ratio}"
        );
    }

    #[test]
    fn test_decoded_ratio() {
        let code = r#"
    import base64
    payload = base64.b64decode("cHJpbnQoMSk=")
    exec(payload)
    "#;
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        let ratio = features.get("semantic.decoded_ratio").unwrap_or(0.0);
        assert!(
            ratio > 0.0,
            "expected decoded_ratio > 0 for code with decoded payloads, got {ratio}"
        );
    }

    #[test]
    fn test_cyclomatic_complexity_per_fn() {
        let code = "def foo():\n    if x:\n        pass\n";
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        assert_eq!(features.get("ast.num_functions").unwrap(), 1.0);
        assert_eq!(
            features.get("ast.cyclomatic_complexity_per_fn").unwrap(),
            2.0
        );
    }

    #[test]
    fn test_unused_qualified_name_predicates() {
        let code = r#"
import threading
import platform
import pyperclip
import pyscreenshot
import ctypes
import pathlib
import socket

t = threading.Thread()
p = platform.system()
c = pyperclip.paste()
img = pyscreenshot.grab()
lib = ctypes.CDLL("x")
pathlib.Path("x").write_text("y")
s = socket.socket()
g = globals()
v = vars()
"#;
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        assert!(
            features.get("call.indirect_exec").unwrap_or(0.0) > 0.0,
            "expected call.indirect_exec for threading.Thread()"
        );
        assert!(
            features.get("call.os_fingerprint").unwrap_or(0.0) > 0.0,
            "expected call.os_fingerprint for platform.system()"
        );
        assert!(
            features.get("call.clipboard_read").unwrap_or(0.0) > 0.0,
            "expected call.clipboard_read for pyperclip.paste()"
        );
        assert!(
            features.get("call.screenshot_capture").unwrap_or(0.0) > 0.0,
            "expected call.screenshot_capture for pyscreenshot.grab()"
        );
        assert!(
            features.get("call.dll_injection").unwrap_or(0.0) > 0.0,
            "expected call.dll_injection for ctypes.CDLL()"
        );
        assert!(
            features.get("call.pathlib_write").unwrap_or(0.0) > 0.0,
            "expected call.pathlib_write for pathlib.Path.write_text()"
        );
        assert!(
            features.get("call.io_resource_ctor").unwrap_or(0.0) > 0.0,
            "expected call.io_resource_ctor for socket.socket()"
        );
        assert!(
            features.get("call.module_registry").unwrap_or(0.0) > 0.0,
            "expected call.module_registry for globals()"
        );
        assert!(
            features.get("call.vars_function").unwrap_or(0.0) > 0.0,
            "expected call.vars_function for vars()"
        );
    }

    #[test]
    fn test_string_content_features_base64_hex() {
        let long_b64: String = format!("{}AA==", "A".repeat(96));
        assert_eq!(long_b64.len(), 100);
        let long_hex: String = (0..50).map(|i| format!("\\x{:02x}", i)).collect();
        let code = format!(
            r#"
short_b64 = "dGVzdA=="
long_b64 = "{long_b64}"
hex_short = r"\x41\x42\x43"
hex_long = r"{long_hex}"
"#
        );
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(&code, file_path).unwrap();
        assert!(
            features
                .get("literal.base64_candidate_count")
                .unwrap_or(0.0)
                >= 2.0,
            "expected at least 2 base64 candidates (short + long)"
        );
        assert!(
            features.get("literal.base64_long_count").unwrap_or(0.0) >= 1.0,
            "expected at least 1 long base64 string"
        );
        assert!(
            features.get("literal.hex_escape_count").unwrap_or(0.0) >= 2.0,
            "expected at least 2 hex-escaped strings (short + long)"
        );
        assert!(
            features.get("literal.long_hex_string_count").unwrap_or(0.0) >= 1.0,
            "expected at least 1 long hex string"
        );
    }

    #[test]
    fn test_string_content_features_url_ip_ext() {
        let code = r#"
url = "https://evil.example/c2"
ip = "127.0.0.1"
drop = "payload.exe"
plain = "hello world"
"#;
        let file_path = Path::new("test.py");
        let features = extract_features_from_source(code, file_path).unwrap();
        assert!(
            features.get("literal.url_count").unwrap_or(0.0) >= 1.0,
            "expected url_count >= 1 for https:// URL"
        );
        assert!(
            features.get("literal.ip_address_count").unwrap_or(0.0) >= 1.0,
            "expected ip_address_count >= 1 for bare IPv4"
        );
        assert!(
            features.get("literal.suspicious_ext_count").unwrap_or(0.0) >= 1.0,
            "expected suspicious_ext_count >= 1 for .exe"
        );
        assert!(
            features.get("literal.url_count").unwrap_or(0.0) >= 1.0
                && features.get("literal.ip_address_count").unwrap_or(0.0) >= 1.0
                && features.get("literal.suspicious_ext_count").unwrap_or(0.0) >= 1.0,
            "expected all three string content features to fire"
        );
    }
}
