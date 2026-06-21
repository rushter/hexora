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
        assert!(count >= 5, "expected at least 5 unique identifiers, got {count}");
        let max_len = features.get("ident.max_name_length").unwrap_or(0.0);
        assert!(max_len >= 6.0, "expected some names longer than 6 chars");
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
}
