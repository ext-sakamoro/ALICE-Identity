//! base58btc: the Bitcoin base58 alphabet, the encoding the multibase prefix `z` names.
//!
//! The bytes are read as one big-endian number written in base 58 with the alphabet below; each
//! leading zero byte is written as one `1` before it. Decoding accepts only that alphabet.

use crate::errors::IdentityError;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The base58btc text of `bytes`
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    // little-endian base-58 digits of the number
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &byte in &bytes[zeros..] {
        let mut carry = u32::from(byte);
        for d in &mut digits {
            carry += u32::from(*d) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(
        digits
            .iter()
            .rev()
            .map(|&d| ALPHABET[usize::from(d)] as char),
    );
    out
}

/// The bytes of base58btc `text`
///
/// # Errors
///
/// `IdentityError::InvalidDid` naming the first character outside the base58btc alphabet.
pub fn decode(text: &str) -> Result<Vec<u8>, IdentityError> {
    let ones = text.bytes().take_while(|&c| c == b'1').count();
    // little-endian bytes of the number
    let mut bytes: Vec<u8> = Vec::with_capacity(text.len());
    for c in text[ones..].chars() {
        let value = u8::try_from(c)
            .ok()
            .and_then(|b| ALPHABET.iter().position(|&a| a == b))
            .ok_or_else(|| {
                IdentityError::InvalidDid(format!("{c:?} is not a base58btc character"))
            })?;
        let mut carry = value as u32;
        for b in &mut bytes {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; ones];
    out.extend(bytes.iter().rev());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zeros_and_the_empty_input() {
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(encode(&[0, 0, 1]), "112");
        assert_eq!(decode("112").unwrap(), vec![0, 0, 1]);
    }

    #[test]
    fn known_answers() {
        // base58btc of the ASCII "hello world" (the multibase draft's example, written here as bytes)
        assert_eq!(encode(b"hello world"), "StV1DL6CwTryKyV");
        assert_eq!(decode("StV1DL6CwTryKyV").unwrap(), b"hello world");
        assert_eq!(encode(&[0xff]), "5Q");
        assert_eq!(encode(&[57]), "z");
        assert_eq!(encode(&[58]), "21");
    }
}
