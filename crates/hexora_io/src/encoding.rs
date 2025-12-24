use base64::{Engine as _, engine::general_purpose};
use encoding_rs;
use once_cell::sync::Lazy;
use std::collections::HashMap;

pub const CP1026: [u8; 256] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x20, 0xa0, 0xe2, 0xe4, 0xe0, 0xe1, 0xe3, 0xe5, 0xe7, 0xf1, 0x24, 0x2e, 0x3c, 0x28, 0x2b, 0x7c,
    0x26, 0xe9, 0xea, 0xeb, 0xe8, 0xed, 0xee, 0xef, 0xec, 0xdf, 0x21, 0x2c, 0x25, 0x5f, 0x3e, 0x3f,
    0x2d, 0x2f, 0xc2, 0xc4, 0xc0, 0xc1, 0xc3, 0xc5, 0xc7, 0xd1, 0x5e, 0x5c, 0x2a, 0x29, 0x3b, 0x5e,
    0x2d, 0x2f, 0xc2, 0xc4, 0xc0, 0xc1, 0xc3, 0xc5, 0xc7, 0xd1, 0x60, 0x3a, 0x23, 0x40, 0x27, 0x3d,
    0x22, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0xab, 0xbb, 0xf0, 0xfd, 0xfe, 0xb1,
    0xb0, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xaa, 0xba, 0xe6, 0xb8, 0xc6, 0xa4,
    0xb5, 0x7e, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0xa1, 0xbf, 0xd0, 0xdd, 0xde, 0xae,
    0x5e, 0xa3, 0xa5, 0xb7, 0xa9, 0xa7, 0xb6, 0xbc, 0xbd, 0xbe, 0x5b, 0x5d, 0xaf, 0xa8, 0xb4, 0xd7,
    0x7b, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0xad, 0xf4, 0xf6, 0xf2, 0xf3, 0xf5,
    0x7d, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0xb9, 0xfb, 0xfc, 0xf9, 0xfa, 0xff,
    0x5c, 0xf7, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0xb2, 0xd4, 0xd6, 0xd2, 0xd3, 0xd5,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xb3, 0xdb, 0xdc, 0xd9, 0xda, 0x9f,
];

static PYTHON_TO_RUST: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    HashMap::from([
        ("037", "cp037"),
        ("1026", "cp1026"),
        ("1250", "cp1250"),
        ("1251", "cp1251"),
        ("1252", "cp1252"),
        ("1253", "cp1253"),
        ("1254", "cp1254"),
        ("1255", "cp1255"),
        ("1256", "cp1256"),
        ("1257", "cp1257"),
        ("1258", "cp1258"),
        ("646", "ascii"),
        ("866", "cp866"),
        ("8859", "iso-8859-1"),
        ("936", "gbk"),
        ("ansi_x3_4_1968", "ascii"),
        ("ansi_x3.4_1968", "ascii"),
        ("ansi_x3.4_1986", "ascii"),
        ("arabic", "iso8859-6"),
        ("ascii", "ascii"),
        ("asmo_708", "iso8859-6"),
        ("big5_tw", "big5"),
        ("big5", "big5"),
        ("chinese", "gb2312"),
        ("cp037", "cp037"),
        ("cp1026", "cp1026"),
        ("cp1250", "cp1250"),
        ("cp1251", "cp1251"),
        ("cp1252", "cp1252"),
        ("cp1253", "cp1253"),
        ("cp1254", "cp1254"),
        ("cp1255", "cp1255"),
        ("cp1256", "cp1256"),
        ("cp1257", "cp1257"),
        ("cp1258", "cp1258"),
        ("cp367", "ascii"),
        ("cp65001", "utf-8"),
        ("cp819", "iso-8859-1"),
        ("cp866", "cp866"),
        ("cp936", "gbk"),
        ("csascii", "ascii"),
        ("csbig5", "big5"),
        ("cseuckr", "euc-kr"),
        ("csibm037", "cp037"),
        ("csibm1026", "cp1026"),
        ("csibm866", "cp866"),
        ("csiso58gb231280", "gb2312"),
        ("csisolatin1", "iso-8859-1"),
        ("csisolatin2", "iso8859-2"),
        ("csisolatin3", "iso8859-3"),
        ("csisolatin4", "iso8859-4"),
        ("csisolatin5", "iso8859-9"),
        ("csisolatin6", "iso8859-10"),
        ("csisolatinarabic", "iso8859-6"),
        ("csisolatincyrillic", "iso8859-5"),
        ("csisolatingreek", "iso8859-7"),
        ("csisolatinhebrew", "iso8859-8"),
        ("cskoi8r", "koi8_r"),
        ("csshiftjis", "shift_jis"),
        ("cyrillic", "iso8859-5"),
        ("ebcdic_cp_ca", "cp037"),
        ("ebcdic_cp_nl", "cp037"),
        ("ebcdic_cp_us", "cp037"),
        ("ebcdic_cp_wt", "cp037"),
        ("ecma_114", "iso8859-6"),
        ("ecma_118", "iso8859-7"),
        ("elot_928", "iso8859-7"),
        ("euc_cn", "gb2312"),
        ("euc_jp", "euc-jp"),
        ("euc_kr", "euc-kr"),
        ("euccn", "gb2312"),
        ("eucgb2312_cn", "gb2312"),
        ("eucjp", "euc-jp"),
        ("euckr", "euc-kr"),
        ("gb18030_2000", "gb18030"),
        ("gb18030", "gb18030"),
        ("gb2312_1980", "gb2312"),
        ("gb2312_80", "gb2312"),
        ("gb2312", "gb2312"),
        ("gbk", "gbk"),
        ("greek", "iso8859-7"),
        ("greek8", "iso8859-7"),
        ("hebrew", "iso8859-8"),
        ("ibm037", "cp037"),
        ("ibm039", "cp037"),
        ("ibm1026", "cp1026"),
        ("ibm367", "ascii"),
        ("ibm819", "iso-8859-1"),
        ("ibm866", "cp866"),
        ("iso_646.irv_1991", "ascii"),
        ("iso_8859_1_1987", "iso-8859-1"),
        ("iso_8859_1", "iso-8859-1"),
        ("iso_8859_10_1992", "iso8859-10"),
        ("iso_8859_10", "iso8859-10"),
        ("iso_8859_11_2001", "iso8859-11"),
        ("iso_8859_11", "iso8859-11"),
        ("iso_8859_13", "iso8859-13"),
        ("iso_8859_14_1998", "iso8859-14"),
        ("iso_8859_14", "iso8859-14"),
        ("iso_8859_15", "iso8859-15"),
        ("iso_8859_2_1987", "iso8859-2"),
        ("iso_8859_2", "iso8859-2"),
        ("iso_8859_3_1988", "iso8859-3"),
        ("iso_8859_3", "iso8859-3"),
        ("iso_8859_4_1988", "iso8859-4"),
        ("iso_8859_4", "iso8859-4"),
        ("iso_8859_5_1988", "iso8859-5"),
        ("iso_8859_5", "iso8859-5"),
        ("iso_8859_6_1987", "iso8859-6"),
        ("iso_8859_6", "iso8859-6"),
        ("iso_8859_7_1987", "iso8859-7"),
        ("iso_8859_7", "iso8859-7"),
        ("iso_8859_8_1988", "iso8859-8"),
        ("iso_8859_8_e", "iso8859-8"),
        ("iso_8859_8_i", "iso8859-8"),
        ("iso_8859_8", "iso8859-8"),
        ("iso_8859_9_1989", "iso8859-9"),
        ("iso_8859_9", "iso8859-9"),
        ("iso_celtic", "iso8859-14"),
        ("iso_ir_100", "iso-8859-1"),
        ("iso_ir_101", "iso8859-2"),
        ("iso_ir_109", "iso8859-3"),
        ("iso_ir_110", "iso8859-4"),
        ("iso_ir_126", "iso8859-7"),
        ("iso_ir_127", "iso8859-6"),
        ("iso_ir_138", "iso8859-8"),
        ("iso_ir_144", "iso8859-5"),
        ("iso_ir_148", "iso8859-9"),
        ("iso_ir_157", "iso8859-10"),
        ("iso_ir_166", "tis-620"),
        ("iso_ir_199", "iso8859-14"),
        ("iso_ir_58", "gb2312"),
        ("iso_ir_6", "ascii"),
        ("iso646_us", "ascii"),
        ("iso8859_1", "iso-8859-1"),
        ("iso8859_10", "iso8859-10"),
        ("iso8859_11", "iso8859-11"),
        ("iso8859_13", "iso8859-13"),
        ("iso8859_14", "iso8859-14"),
        ("iso8859_15", "iso8859-15"),
        ("iso8859_2", "iso8859-2"),
        ("iso8859_3", "iso8859-3"),
        ("iso8859_4", "iso8859-4"),
        ("iso8859_5", "iso8859-5"),
        ("iso8859_6", "iso8859-6"),
        ("iso8859_7", "iso8859-7"),
        ("iso8859_8", "iso8859-8"),
        ("iso8859_9", "iso8859-9"),
        ("iso8859", "iso-8859-1"),
        ("koi8_r", "koi8_r"),
        ("korean", "euc-kr"),
        ("ks_c_5601_1987", "euc-kr"),
        ("ks_c_5601", "euc-kr"),
        ("ks_x_1001", "euc-kr"),
        ("ksc5601", "euc-kr"),
        ("ksx1001", "euc-kr"),
        ("l1", "iso-8859-1"),
        ("l2", "iso8859-2"),
        ("l3", "iso8859-3"),
        ("l4", "iso8859-4"),
        ("l5", "iso8859-9"),
        ("l6", "iso8859-10"),
        ("l7", "iso8859-13"),
        ("l8", "iso8859-14"),
        ("l9", "iso8859-15"),
        ("latin_1", "iso-8859-1"),
        ("latin_2", "iso8859-2"),
        ("latin_3", "iso8859-3"),
        ("latin_4", "iso8859-4"),
        ("latin_5", "iso8859-9"),
        ("latin_6", "iso8859-10"),
        ("latin_7", "iso8859-13"),
        ("latin_8", "iso8859-14"),
        ("latin_9", "iso8859-15"),
        ("latin", "iso-8859-1"),
        ("latin1", "iso-8859-1"),
        ("latin2", "iso8859-2"),
        ("latin3", "iso8859-3"),
        ("latin4", "iso8859-4"),
        ("latin5", "iso8859-9"),
        ("latin6", "iso8859-10"),
        ("latin7", "iso8859-13"),
        ("latin8", "iso8859-14"),
        ("latin9", "iso8859-15"),
        ("ms936", "gbk"),
        ("s_jis", "shift_jis"),
        ("shift_jis", "shift_jis"),
        ("shiftjis", "shift_jis"),
        ("sjis", "shift_jis"),
        ("thai", "iso8859-11"),
        ("tis_620_0", "tis-620"),
        ("tis_620_2529_0", "tis-620"),
        ("tis_620_2529_1", "tis-620"),
        ("tis_620", "tis-620"),
        ("tis620", "tis-620"),
        ("u_jis", "euc-jp"),
        ("u16", "utf-16"),
        ("u32", "utf-32"),
        ("u8", "utf-8"),
        ("ujis", "euc-jp"),
        ("us_ascii", "ascii"),
        ("us", "ascii"),
        ("utf_16", "utf-16"),
        ("utf_32", "utf-32"),
        ("utf_8", "utf-8"),
        ("utf", "utf-8"),
        ("utf16", "utf-16"),
        ("utf32", "utf-32"),
        ("utf8_ucs2", "utf-8"),
        ("utf8_ucs4", "utf-8"),
        ("utf8", "utf-8"),
        ("windows_1250", "cp1250"),
        ("windows_1251", "cp1251"),
        ("windows_1252", "cp1252"),
        ("windows_1253", "cp1253"),
        ("windows_1254", "cp1254"),
        ("windows_1255", "cp1255"),
        ("windows_1256", "cp1256"),
        ("windows_1257", "cp1257"),
        ("windows_1258", "cp1258"),
        ("x_mac_japanese", "shift_jis"),
        ("x_mac_korean", "euc-kr"),
        ("x_mac_simp_chinese", "gb2312"),
        ("x_mac_trad_chinese", "big5"),
    ])
});

pub fn normalize_python_encoding(encoding: &str) -> Option<&'static str> {
    PYTHON_TO_RUST.get(encoding).copied()
}

pub fn decode_bytes(bytes: &[u8], encoding: &str) -> Option<String> {
    let rust_encoding = normalize_python_encoding(encoding).unwrap_or(encoding);
    if rust_encoding == "cp1026" {
        let res: String = bytes.iter().map(|&b| CP1026[b as usize] as char).collect();
        return Some(res);
    }
    let decoder = encoding_rs::Encoding::for_label(rust_encoding.as_bytes());
    if let Some(enc) = decoder {
        let (res, _, _) = enc.decode(bytes);
        return Some(res.into_owned());
    }

    None
}

pub fn unescape_to_bytes(input: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('x') => {
                    let h1 = chars.next()?;
                    let h2 = chars.next()?;
                    let hex = format!("{}{}", h1, h2);
                    let byte = u8::from_str_radix(&hex, 16).ok()?;
                    bytes.push(byte);
                }
                Some('n') => bytes.push(b'\n'),
                Some('r') => bytes.push(b'\r'),
                Some('t') => bytes.push(b'\t'),
                Some('\\') => bytes.push(b'\\'),
                Some('\'') => bytes.push(b'\''),
                Some('\"') => bytes.push(b'\"'),
                _ => return None,
            }
        } else {
            bytes.push(c as u8);
        }
    }
    Some(bytes)
}

#[inline]
pub fn bytes_to_escaped(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\x{:02x}", b)).collect()
}

#[inline]
pub fn hex_to_escaped(input: &str) -> Option<String> {
    let filtered: String = input.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if filtered.is_empty() || !filtered.len().is_multiple_of(2) {
        return None;
    }
    filtered
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let h = chunk[0] as char;
            let l = chunk[1] as char;
            if h.is_ascii_hexdigit() && l.is_ascii_hexdigit() {
                Some(format!(
                    "\\x{}{}",
                    h.to_ascii_lowercase(),
                    l.to_ascii_lowercase()
                ))
            } else {
                None
            }
        })
        .collect()
}

pub fn base64_decode(input: &str, url_safe: bool) -> Option<Vec<u8>> {
    let input = input.trim();
    if url_safe {
        general_purpose::URL_SAFE.decode(input).ok()
    } else {
        general_purpose::STANDARD.decode(input).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_normalize_python_encoding_mappings() {
        let rust_encodings: HashSet<&str> = PYTHON_TO_RUST.values().cloned().collect();
        for &rust_enc in &rust_encodings {
            if rust_enc == "cp1026" || rust_enc == "cp037" || rust_enc == "utf-32" {
                // These encodings are not supported by encoding_rs yet
                continue;
            }
            assert!(
                encoding_rs::Encoding::for_label(rust_enc.as_bytes()).is_some(),
                "Rust encoding {} not supported by encoding_rs",
                rust_enc
            );
        }
    }

    #[test]
    fn test_decode_bytes_aliases() {
        let bytes = b"hello \xff";
        let decoded = decode_bytes(bytes, "latin1").unwrap();
        assert_eq!(decoded, "hello \u{ff}");

        let bytes = b"\x85\xa5\x81\x93";
        let decoded = decode_bytes(bytes, "1026").unwrap();
        assert_eq!(decoded, "eval");
    }
}
