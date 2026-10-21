//! Hex as the bridge prints it: lower case, and `0x`-prefixed wherever Ethereum reads the value.

/// `bytes` as lower-case hex, without a prefix.
pub fn encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 * bytes.len());
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    s
}

/// `bytes` as `0x`-prefixed lower-case hex.
pub fn prefixed(bytes: &[u8]) -> String {
    format!("0x{}", encode(bytes))
}

/// Bytes from hex in either case, with or without a `0x` prefix.
pub fn decode(text: &str) -> Result<Vec<u8>, String> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    if digits.len() % 2 != 0 || !digits.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("not a hex string".into());
    }
    Ok((0..digits.len())
        .step_by(2)
        // In range and valid: the digits are ASCII hex digits, two per byte.
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).expect("checked hex digits"))
        .collect())
}

/// Exactly `N` bytes from hex.
pub fn decode_array<const N: usize>(text: &str) -> Result<[u8; N], String> {
    decode(text)?
        .try_into()
        .map_err(|_| format!("not {N} bytes of hex"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        assert_eq!(encode(&[0x00, 0xab, 0x0f]), "00ab0f");
        assert_eq!(prefixed(&[0xab]), "0xab");
        assert_eq!(decode("0xAB0f").unwrap(), vec![0xab, 0x0f]);
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode_array::<2>("0X0102").unwrap(), [1, 2]);
        assert!(decode("abc").is_err());
        assert!(decode("0xzz").is_err());
        assert!(decode("+1").is_err());
        assert!(decode_array::<3>("0102").is_err());
    }
}
