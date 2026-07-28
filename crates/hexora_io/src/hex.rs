pub const MIN_HEXED_STRING_LENGTH: usize = 100;

pub const HEX_DIGIT_TABLE: [u8; 256] = {
    let mut table = [0xFFu8; 256];
    let mut i = 0u8;
    while i < 10 {
        table[b'0' as usize + i as usize] = i;
        i += 1;
    }
    i = 0;
    while i < 6 {
        table[b'a' as usize + i as usize] = 10 + i;
        table[b'A' as usize + i as usize] = 10 + i;
        i += 1;
    }
    table
};

#[inline]
pub fn is_hex_escaped(literal: &str) -> bool {
    let bytes = literal.as_bytes();
    bytes.len() >= 4
        && bytes.len() & 3 == 0
        && bytes.chunks(4).all(|c| {
            c[0] == b'\\'
                && c[1] == b'x'
                && HEX_DIGIT_TABLE[c[2] as usize] != 0xFF
                && HEX_DIGIT_TABLE[c[3] as usize] != 0xFF
        })
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
