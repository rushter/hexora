pub fn is_telegram_token(s: &str) -> bool {
    let bytes = s.as_bytes();
    let len = bytes.len();

    if !(44..=46).contains(&len) {
        return false;
    }

    let mut i = 0;
    while i < len && bytes[i].is_ascii_digit() {
        i += 1;
    }
    let digit_count = i;
    if !(8..=10).contains(&digit_count) {
        return false;
    }

    if i >= len || bytes[i] != b':' {
        return false;
    }
    i += 1;

    if len - i != 35 {
        return false;
    }
    bytes[i..]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_10_digit_token() {
        assert!(is_telegram_token(&format!("1234567890:{}", "A".repeat(35))));
    }

    #[test]
    fn test_valid_8_digit_token() {
        assert!(is_telegram_token(&format!("12345678:{}", "a".repeat(35))));
    }

    #[test]
    fn test_valid_9_digit_token_with_dash() {
        assert!(is_telegram_token(&format!(
            "123456789:{}-{}",
            "a".repeat(33),
            "b"
        )));
    }

    #[test]
    fn test_too_few_digits() {
        assert!(!is_telegram_token(
            "1234567:abcdefghijklmnopqrstuvwxyz012345"
        ));
    }

    #[test]
    fn test_too_many_digits() {
        assert!(!is_telegram_token(
            "12345678901:abcdefghijklmnopqrstuvwxyz012345"
        ));
    }

    #[test]
    fn test_too_few_chars_after_colon() {
        assert!(!is_telegram_token(
            "1234567890:abcdefghijklmnopqrstuvwxyz0123"
        ));
    }

    #[test]
    fn test_too_many_chars_after_colon() {
        assert!(!is_telegram_token(
            "1234567890:abcdefghijklmnopqrstuvwxyz0123456"
        ));
    }

    #[test]
    fn test_short_string() {
        assert!(!is_telegram_token("12345:abcde"));
    }

    #[test]
    fn test_empty_string() {
        assert!(!is_telegram_token(""));
    }

    #[test]
    fn test_no_colon() {
        assert!(!is_telegram_token(
            "1234567890abcdefghijklmnopqrstuvwxyz012345"
        ));
    }

    #[test]
    fn test_extra_content_before() {
        assert!(!is_telegram_token(
            "x1234567890:ABCdefGHIjklMNOpqrsTUVwxyz012345"
        ));
    }

    #[test]
    fn test_extra_content_after() {
        assert!(!is_telegram_token(
            "1234567890:ABCdefGHIjklMNOpqrsTUVwxyz012345x"
        ));
    }

    #[test]
    fn test_invalid_char_after_colon() {
        assert!(!is_telegram_token(
            "1234567890:ABCdefGHIjklMNOpqrs uvVwxyz0123"
        ));
    }
}
