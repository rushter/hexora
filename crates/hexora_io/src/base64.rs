pub const MIN_BASE64_STRING_LENGTH: usize = 100;
pub const ELEVATED_BASE64_STRING_LENGTH: usize = 200;

const BASE64_CHARS: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0;
    while i < 26 {
        table[b'A' as usize + i] = true;
        table[b'a' as usize + i] = true;
        i += 1;
    }
    i = 0;
    while i < 10 {
        table[b'0' as usize + i] = true;
        i += 1;
    }
    table[b'+' as usize] = true;
    table[b'/' as usize] = true;
    table
};

#[inline]
fn is_valid_base64_encoded(s: &str) -> bool {
    let bytes = s.as_bytes();
    let len = bytes.len();
    if len == 0 || (len & 3) != 0 {
        return false;
    }
    let mut padding = 0;
    while padding < len && bytes[len - 1 - padding] == b'=' {
        padding += 1;
    }
    if padding > 2 {
        return false;
    }
    bytes[..len - padding]
        .iter()
        .all(|&b| BASE64_CHARS[b as usize])
}

#[inline]
pub fn is_base64_candidate(literal: &str) -> bool {
    literal.len() >= 8 && is_valid_base64_encoded(literal)
}

#[inline]
pub fn is_base64_string(literal: &str) -> bool {
    literal.len() >= MIN_BASE64_STRING_LENGTH && is_valid_base64_encoded(literal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_base64_candidate() {
        assert!(is_base64_candidate("dGVzdA=="));
        assert!(is_base64_candidate("dGVzdGluZw=="));
        assert!(!is_base64_candidate("short"));
        assert!(!is_base64_candidate(""));
        assert!(!is_base64_candidate("not base64!"));
    }

    #[test]
    fn test_is_base64_string() {
        let long = format!("{}AA==", "A".repeat(96));
        assert_eq!(long.len(), 100);
        assert!(is_base64_string(&long));
        assert!(!is_base64_string("dGVzdA=="));
        assert!(!is_base64_string("not base64"));
    }
}
