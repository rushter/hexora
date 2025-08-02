use crate::audit::helpers::ListLike;
use crate::audit::parse::Checker;
use crate::audit::result::{AuditConfidence, AuditItem, Rule};
use itertools::Itertools;
use memchr::memmem;
use once_cell::sync::Lazy;
use ruff_python_ast as ast;
use ruff_python_ast::str::raw_contents;
use ruff_text_size::Ranged;
use serde::Serialize;

const MAX_PREVIEW_LENGTH: usize = 16;
const LITERALS_PREVIEW_MAX_COUNT: usize = 5;
const MIN_HEXED_STRING_LENGTH: usize = 100;
const MIN_BASE64_STRING_LENGTH: usize = 100;
const MIN_HEXED_LITERALS: u16 = 10;
const MIN_INT_LITERALS: u16 = 20;
const MIN_LITERAL_LENGTH: usize = 8;
const MAX_LITERAL_LENGTH: usize = 512;

#[derive(Debug, Serialize)]
pub struct SuspiciousLiteral {
    pattern: String,
    description: String,
    confidence: AuditConfidence,
    rule: Rule,
}

static SUSPICIOUS_LITERALS: Lazy<Vec<SuspiciousLiteral>> = Lazy::new(|| {
    let apps = [
        "1Password",
        "Armory",
        "binance",
        "Bitcoin",
        "Bitwarden",
        "Coinbase",
        "Discord",
        "Electrum",
        "exodus.wallet",
        "Guarda",
        "Jaxx",
        "KeePass",
        "LastPass",
        "Ledger",
        "Metamask",
        "Telegram",
        "TREZOR",
    ];
    let paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/.ssh/id_rsa",
        "/.ssh/authorized_keys",
        ".bitcoin/",
        ".ethereum",
        "/proc/",
        "/.aws/",
        ".netrc",
    ];
    let browser_path = [
        "Opera Software",
        "Google/Chrome",
        "Chromium/User Data/",
        "BraveSoftware/Brave-Browser",
        "Yandex/YandexBrowser",
        "Vivaldi/User Data",
        "Application Support/Vivaldi/",
        "Microsoft/Edge",
        "Mozilla/Firefox",
        "Cookies/Cookies",
        "Default/Extensions",
        "Default/Network/Cookies",
        "Default/Cookies",
        "Default/History",
        "Login Data/",
        "Web Data/",
        "Local State/",
        "Bookmarks/",
        "cookies.sqlite",
        "Local Storage/leveldb",
        "Discord/Local Storage/leveldb",
        "Safari/LocalStorage/",
        "Library/Safari",
        "Application Support/Chromium/",
    ];

    let mut m = vec![
        SuspiciousLiteral {
            pattern: "POST / HTTP/1".to_string(),
            description: "Suspicious raw POST request. Potential exploitation.".to_string(),
            confidence: AuditConfidence::Medium,
            rule: Rule::SuspiciousLiteral,
        },
        SuspiciousLiteral {
            pattern: "GET / HTTP/1.".to_string(),
            description: "Suspicious raw GET request. Potential exploitation.".to_string(),
            confidence: AuditConfidence::Medium,
            rule: Rule::SuspiciousLiteral,
        },
        SuspiciousLiteral {
            pattern: "uname -a".to_string(),
            description: "Suspicious command. Reconnaissance checks.".to_string(),
            confidence: AuditConfidence::Medium,
            rule: Rule::SuspiciousLiteral,
        },
        SuspiciousLiteral {
            pattern: "/bin/sh".to_string(),
            description: "Suspicious command. Potential exploitation.".to_string(),
            confidence: AuditConfidence::Medium,
            rule: Rule::SuspiciousLiteral,
        },
        SuspiciousLiteral {
            pattern: "CVE-".to_string(),
            description: "Literal mentions CVE. Potential exploitation.".to_string(),
            confidence: AuditConfidence::Medium,
            rule: Rule::CVEInLiteral,
        },
        SuspiciousLiteral {
            pattern: "../../..".to_string(),
            description: "Path travelsal".to_string(),
            confidence: AuditConfidence::High,
            rule: Rule::PathTraversal,
        },
    ];
    for path in browser_path.iter() {
        m.push(SuspiciousLiteral {
            pattern: path.to_string(),
            description: format!("Potential enumeration of {} browser path.", path),
            confidence: AuditConfidence::High,
            rule: Rule::BrowserEnumeration,
        });
    }
    for app in apps {
        m.push(SuspiciousLiteral {
            pattern: app.to_string(),
            description: format!("Potential enumeration of {} app", app),
            confidence: AuditConfidence::High,
            rule: Rule::AppEnumeration,
        });
    }
    for path in paths {
        m.push(SuspiciousLiteral {
            pattern: path.to_string(),
            description: format!("Potential enumeration of {} on file system.", path),
            confidence: AuditConfidence::High,
            rule: Rule::PathEnumeration,
        });
    }
    m
});

fn is_hexed_string(literal: &str) -> bool {
    if !literal.starts_with('\\') {
        return false;
    }

    if literal.len() < MIN_HEXED_STRING_LENGTH {
        return false;
    };
    let re = regex::Regex::new(r"^(\\x[0-9a-fA-F]{2})+$").unwrap();
    re.is_match(literal)
}

fn is_base64_string(literal: &str) -> bool {
    if literal.len() < MIN_BASE64_STRING_LENGTH {
        return false;
    };
    let re = regex::Regex::new(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)$")
        .unwrap();
    re.is_match(literal)
}

fn raw_string_literal(string_like: ast::StringLike, checker: &Checker) -> Option<String> {
    match string_like {
        ast::StringLike::String(ast::ExprStringLiteral { value, .. }) => {
            if value.is_empty() {
                return None;
            }
            Some(
                value
                    .iter()
                    .map(|r| r.range)
                    .filter_map(|range| raw_contents(checker.locator.slice(range)))
                    .join(""),
            )
        }
        ast::StringLike::Bytes(ast::ExprBytesLiteral { value, .. }) => {
            if value.is_empty() {
                return None;
            }
            Some(
                value
                    .iter()
                    .map(|r| r.range)
                    .filter_map(|range| raw_contents(checker.locator.slice(range)))
                    .join(""),
            )
        }
        ast::StringLike::FString(ast::ExprFString { value, .. }) => Some(
            value
                .iter()
                .filter_map(|range| raw_contents(checker.locator.slice(range)))
                .join(""),
        ),
        _ => None,
    }
}

fn literal_preview(value: &str, max_length: usize) -> String {
    if value.len() > max_length {
        format!(
            "{}...{}",
            &value[..max_length / 2],
            &value[value.len() - max_length / 2..]
        )
    } else {
        value.to_string()
    }
}

pub fn check_literal(checker: &mut Checker, string_like: ast::StringLike) {
    if let Some(literal) = raw_string_literal(string_like, checker) {
        if is_hexed_string(&literal) {
            checker.audit_results.push(AuditItem {
                label: literal_preview(&literal, MAX_PREVIEW_LENGTH),
                rule: Rule::HexedString,
                description: "Hexed string found, potentially dangerous payload/shellcode."
                    .to_string(),
                confidence: AuditConfidence::Medium,
                location: Some(string_like.range()),
            });
            return;
        }
        if is_base64_string(&literal) {
            checker.audit_results.push(AuditItem {
                label: literal_preview(&literal, MAX_PREVIEW_LENGTH),
                rule: Rule::Base64String,
                description: "Base64 encoded string found, potentially obfuscated code."
                    .to_string(),
                confidence: AuditConfidence::Medium,
                location: Some(string_like.range()),
            });
            return;
        }
        check_suspicious_literal(checker, &literal, string_like);
    }
}

pub fn check_int_literals<T>(checker: &mut Checker, list: &T)
where
    T: ListLike,
{
    let mut num_hex_literals: u16 = 0;
    let mut preview_literals: Vec<&str> = Vec::new();
    let mut num_int_literals: u16 = 0;
    let mut is_hex_literal: bool = false;

    for element in list.elements() {
        match element {
            ast::Expr::NumberLiteral(number) => {
                let raw_value = checker.locator.slice(number.range);
                if raw_value.starts_with("0x") {
                    if !is_hex_literal {
                        is_hex_literal = true;
                    }
                    num_hex_literals += 1;
                    if preview_literals.len() < LITERALS_PREVIEW_MAX_COUNT {
                        preview_literals.push(raw_value);
                    }
                } else {
                    if is_hex_literal {
                        break;
                    }
                    num_int_literals += 1;
                    if preview_literals.len() < LITERALS_PREVIEW_MAX_COUNT {
                        preview_literals.push(raw_value);
                    }
                }
            }
            _ => break,
        }
        if num_hex_literals > MIN_HEXED_LITERALS {
            checker.audit_results.push(AuditItem {
                label: format!("[{}, ... ]", preview_literals.join(", ")),
                rule: Rule::HexedLiterals,
                description:
                    "Sequence hex literals found, potentially dangerous payload/shellcode."
                        .to_string(),
                confidence: AuditConfidence::Medium,
                location: Some(list.range()),
            });
            return;
        }
        if num_int_literals > MIN_INT_LITERALS {
            checker.audit_results.push(AuditItem {
                label: format!("[{}, ... ]", preview_literals.join(", ")),
                rule: Rule::IntLiterals,
                description: "Sequence of int literals found, potentially obfuscated code."
                    .to_string(),
                confidence: AuditConfidence::Medium,
                location: Some(list.range()),
            });
            return;
        };
    }
}

fn normalize_literal(literal: &str) -> String {
    literal.replace("\\\\", "/").replace('\\', "/")
}

pub fn check_suspicious_literal(
    checker: &mut Checker,
    literal: &str,
    string_like: ast::StringLike,
) {
    let normalized_literal = normalize_literal(literal);
    if normalized_literal.len() < MIN_LITERAL_LENGTH
        || normalized_literal.len() > MAX_LITERAL_LENGTH
    {
        return;
    }
    for suspicious_literal in SUSPICIOUS_LITERALS.iter() {
        let name = &suspicious_literal.pattern;
        if memmem::find(normalized_literal.as_bytes(), name.as_bytes()).is_some() {
            checker.audit_results.push(AuditItem {
                label: suspicious_literal.pattern.clone(),
                rule: suspicious_literal.rule.clone(),
                description: suspicious_literal.description.clone(),
                confidence: suspicious_literal.confidence,
                location: Some(string_like.range()),
            });
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::result::Rule;
    use crate::rules::literal::normalize_literal;
    use crate::rules::test::*;
    use test_case::test_case;

    #[test_case("literal_01.py", Rule::HexedString, vec!["\\x31\\xc0...\\x80\\x00", "\\xeb\\x0d...\\xd4\\x99"])]
    #[test_case("literal_02.py", Rule::Base64String, vec!["dHJ5Ogog...NTMiKSk="])]
    #[test_case("literal_03.py", Rule::HexedLiterals, vec!["[0x00, 0x00, 0x00, 0x18, 0x66, ... ]", "[0x00, 0x1A, 0x63, 0x6C, 0x69, ... ]"])]
    #[test_case("literal_03.py", Rule::IntLiterals, vec!["[40, 65, 122, 63, 77, ... ]"])]
    #[test_case("literal_04.py", Rule::BrowserEnumeration, vec!["BraveSoftware/Brave-Browser", "Opera Software"])]
    #[test_case("literal_04.py", Rule::AppEnumeration, vec!["1Password", "KeePass"])]
    #[test_case("literal_04.py", Rule::PathEnumeration, vec!["/etc/passwd"])]
    #[test_case("literal_04.py", Rule::SuspiciousLiteral, vec!["uname -a"])]
    fn test_literal(path: &str, rule: Rule, expected_names: Vec<&str>) {
        assert_audit_results_by_name(path, rule, expected_names);
    }

    #[test]
    fn test_literal_normalization() {
        assert_eq!(
            normalize_literal("C:\\Users\\admin\\Desktop\\test.txt"),
            "C:/Users/admin/Desktop/test.txt"
        );
        assert_eq!(
            normalize_literal("C:\\\\Users\\\\admin\\\\Desktop\\\\test.txt"),
            "C:/Users/admin/Desktop/test.txt"
        );
    }
}
