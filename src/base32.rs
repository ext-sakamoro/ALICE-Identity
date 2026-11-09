//! Base32 text for bytes a person or a QR code carries: RFC 4648 section 6 (upper case, no padding)
//! for whole artifacts, and the Crockford alphabet for short codes read aloud.
//!
//! The RFC 4648 alphabet is upper-case letters and digits, all inside the QR code alphanumeric mode
//! (which also holds the `:` and `-` of the text prefixes), so a contact card or an invite fits a QR
//! code at 5.5 bits per character. Decoding accepts only that alphabet in upper case, without padding,
//! and refuses trailing bits that are not zero, so every text has exactly one decoding and every byte
//! string exactly one text.

/// RFC 4648 section 6
const RFC4648: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Crockford's base32 (no I, L, O, U, so a code read aloud is not misread)
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The RFC 4648 base32 text of `bytes`, upper case and without padding
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(RFC4648[((acc >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(RFC4648[((acc << (5 - bits)) & 31) as usize]));
    }
    out
}

/// The bytes of an RFC 4648 base32 text written by [`encode`]
///
/// `None` for any other text (a
/// character outside the upper-case alphabet, padding, a length no byte string encodes to, or
/// trailing bits that are not zero)
#[must_use]
pub fn decode(text: &str) -> Option<Vec<u8>> {
    // a byte string of n bytes encodes to ceil(8n / 5) characters; the lengths 1, 3 and 6 (mod 8)
    // are never produced
    if matches!(text.len() % 8, 1 | 3 | 6) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in text.bytes() {
        let v = RFC4648.iter().position(|&a| a == c)?;
        acc = (acc << 5) | u32::try_from(v).expect("an index below 32");
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).expect("masked to a byte"));
        }
        acc &= (1 << bits) - 1;
    }
    (acc == 0).then_some(out)
}

/// The Crockford base32 text of the first `chars * 5` bits of `bytes`, most significant bit first
///
/// # Panics
/// When `bytes` holds fewer than `chars * 5` bits.
#[must_use]
pub fn crockford_prefix(bytes: &[u8], chars: usize) -> String {
    assert!(
        bytes.len() * 8 >= chars * 5,
        "not enough bits for {chars} characters"
    );
    (0..chars)
        .map(|i| {
            let start = i * 5;
            let mut v = 0usize;
            for bit in start..start + 5 {
                v = (v << 1) | usize::from((bytes[bit / 8] >> (7 - bit % 8)) & 1);
            }
            char::from(CROCKFORD[v])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 section 10 test vectors (upper case, padding removed)
    #[test]
    fn rfc4648_vectors() {
        for (plain, text) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(encode(plain.as_bytes()), text);
            assert_eq!(decode(text).as_deref(), Some(plain.as_bytes()));
        }
    }

    #[test]
    fn decode_refuses_other_texts() {
        for bad in ["my", "MY=", "M", "MZX", "MZXW6Y", "MZ", "MZ1W", "MZ W6"] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
        // "MZ" would be 0x66 with non-zero trailing bits
        assert_eq!(decode("MZ"), None);
    }

    #[test]
    fn every_length_round_trips() {
        let bytes: Vec<u8> = (0..=255).collect();
        for n in 0..64 {
            let t = encode(&bytes[..n]);
            assert_eq!(decode(&t).as_deref(), Some(&bytes[..n]));
        }
    }

    #[test]
    fn crockford_reads_bits_most_significant_first() {
        assert_eq!(
            crockford_prefix(&[0x00, 0x00, 0x00, 0x00, 0x00], 8),
            "00000000"
        );
        assert_eq!(
            crockford_prefix(&[0xff, 0xff, 0xff, 0xff, 0xff], 8),
            "ZZZZZZZZ"
        );
        // 0b00001_00010_00011_00100_00101_00110_00111_01000
        assert_eq!(
            crockford_prefix(&[0x08, 0x86, 0x42, 0x98, 0xe8], 8),
            "12345678"
        );
    }
}
