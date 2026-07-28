use crate::hex::HEX_DIGIT_TABLE;

pub const ESCAPE_TABLE: [[u8; 4]; 256] = {
    let hex = b"0123456789abcdef";
    let mut table = [[0u8; 4]; 256];
    let mut i = 0usize;
    while i < 256 {
        table[i] = [b'\\', b'x', hex[i >> 4], hex[i & 0xf]];
        i += 1;
    }
    table
};

#[inline]
pub fn bytes_to_escaped(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let mut buf = Vec::with_capacity(bytes.len() * 4);
    for &b in bytes {
        buf.extend_from_slice(&ESCAPE_TABLE[b as usize]);
    }
    String::from_utf8(buf).unwrap()
}

pub fn unescape_to_bytes(input: &str) -> Option<Vec<u8>> {
    let src = input.as_bytes();
    let len = src.len();
    let mut dst = Vec::with_capacity(len);
    let mut i = 0;
    while i < len {
        if src[i] != b'\\' {
            let start = i;
            while i < len && src[i] != b'\\' {
                i += 1;
            }
            dst.extend_from_slice(&src[start..i]);
            continue;
        }
        let escape = i + 1;
        if escape >= len {
            return None;
        }
        match src[escape] {
            b'x' => {
                let hi = escape + 1;
                if hi + 1 >= len {
                    return None;
                }
                let h1 = HEX_DIGIT_TABLE[src[hi] as usize];
                let h2 = HEX_DIGIT_TABLE[src[hi + 1] as usize];
                if h1 == 0xFF || h2 == 0xFF {
                    return None;
                }
                dst.push((h1 << 4) | h2);
                i = hi + 2;
            }
            b'n' => {
                dst.push(b'\n');
                i = escape + 1;
            }
            b'r' => {
                dst.push(b'\r');
                i = escape + 1;
            }
            b't' => {
                dst.push(b'\t');
                i = escape + 1;
            }
            b'\\' => {
                dst.push(b'\\');
                i = escape + 1;
            }
            b'\'' => {
                dst.push(b'\'');
                i = escape + 1;
            }
            b'\"' => {
                dst.push(b'\"');
                i = escape + 1;
            }
            _ => return None,
        }
    }
    Some(dst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_escaped() {
        assert_eq!(bytes_to_escaped(b""), "");
        assert_eq!(bytes_to_escaped(b"\x00"), "\\x00");
        assert_eq!(bytes_to_escaped(b"hello"), "\\x68\\x65\\x6c\\x6c\\x6f");
        assert_eq!(bytes_to_escaped(b"\xff\x01"), "\\xff\\x01");
    }

    #[test]
    fn test_unescape_to_bytes() {
        assert_eq!(unescape_to_bytes("").unwrap(), b"");
        assert_eq!(unescape_to_bytes("hello").unwrap(), b"hello");
        assert_eq!(
            unescape_to_bytes("\\x68\\x65\\x6c\\x6c\\x6f").unwrap(),
            b"hello"
        );
        assert_eq!(
            unescape_to_bytes("\\n\\r\\t\\\\\\'\\\"").unwrap(),
            b"\n\r\t\\'\""
        );
        assert_eq!(unescape_to_bytes("\\x41").unwrap(), b"A");
        assert!(unescape_to_bytes("\\x").is_none());
        assert!(unescape_to_bytes("\\xGH").is_none());
        assert!(unescape_to_bytes("\\z").is_none());
    }

    #[test]
    fn test_bytes_roundtrip() {
        let cases: &[&[u8]] = &[
            b"",
            b"\x00",
            b"hello",
            b"\xff\xfe\xfd\xfc",
            b"a",
            b"ab",
            b"abc",
            &(0u8..=255).collect::<Vec<_>>(),
        ];
        for input in cases {
            let escaped = bytes_to_escaped(input);
            let unescaped = unescape_to_bytes(&escaped).unwrap();
            assert_eq!(&unescaped, input);
        }
    }
}
