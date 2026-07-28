pub const MIN_HEXED_STRING_LENGTH: usize = 100;

const HEX_CHARS: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0;
    while i < 10 {
        table[b'0' as usize + i] = true;
        i += 1;
    }
    i = 0;
    while i < 6 {
        table[b'A' as usize + i] = true;
        table[b'a' as usize + i] = true;
        i += 1;
    }
    table
};

#[inline]
pub fn is_hex_escaped(literal: &str) -> bool {
    let bytes = literal.as_bytes();
    let len = bytes.len();
    if len < 4 || len & 3 != 0 {
        return false;
    }
    let mut i = 0;
    while i < len - 4 {
        if bytes[i] != b'\\'
            || bytes[i + 1] != b'x'
            || !HEX_CHARS[bytes[i + 2] as usize]
            || !HEX_CHARS[bytes[i + 3] as usize]
            || bytes[i + 4] != b'\\'
            || bytes[i + 5] != b'x'
            || !HEX_CHARS[bytes[i + 6] as usize]
            || !HEX_CHARS[bytes[i + 7] as usize]
        {
            return false;
        }
        i += 8;
    }
    if i < len {
        bytes[i] == b'\\'
            && bytes[i + 1] == b'x'
            && HEX_CHARS[bytes[i + 2] as usize]
            && HEX_CHARS[bytes[i + 3] as usize]
    } else {
        true
    }
}

#[inline]
pub fn is_hexed_string(literal: &str) -> bool {
    literal.len() >= MIN_HEXED_STRING_LENGTH && is_hex_escaped(literal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_hex_escaped() {
        assert!(is_hex_escaped("\\x41\\x42\\x43"));
        assert!(is_hex_escaped("\\xff\\x00"));
        assert!(!is_hex_escaped("abc"));
        assert!(!is_hex_escaped("\\x4"));
        assert!(!is_hex_escaped(""));
    }

    #[test]
    fn test_is_hexed_string() {
        let long_hex: String = (0..50).map(|i| format!("\\x{:02x}", i)).collect();
        assert!(is_hexed_string(&long_hex));
        assert!(!is_hexed_string("\\x41\\x42"));
        assert!(!is_hexed_string("not hex"));
        assert!(!is_hexed_string(""));
    }
}
