//! `JWS` (JSON Web Signature) compact serialisation with `EdDSA` (`Ed25519`).
//!
//! Implements the compact form of `RFC 7515`:
//! `BASE64URL(header) || '.' || BASE64URL(payload) || '.' || BASE64URL(signature)`.
//!
//! Only the `EdDSA` algorithm (`alg = EdDSA` per `RFC 8037`) is supported —
//! signatures are produced by [`alice_sign::KeyPair`] and verified by
//! [`alice_sign::PublicKey`].
//!
//! Higher-level `JWT` structures reuse this token: the payload is a JSON
//! object carrying claims; verifiers are expected to check `iss` / `exp` /
//! `nbf` themselves.

use alice_sign::{KeyPair, PublicKey, Signature};

// ---------------------------------------------------------------------------
// Base64URL helpers (no padding)
// ---------------------------------------------------------------------------

const B64_URL_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode bytes as `Base64URL` without padding.
#[must_use]
pub fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 4);
    let mut i = 0;
    while i + 3 <= bytes.len() {
        let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8) | (bytes[i + 2] as u32);
        out.push(B64_URL_CHARS[((n >> 18) & 0x3F) as usize] as char);
        out.push(B64_URL_CHARS[((n >> 12) & 0x3F) as usize] as char);
        out.push(B64_URL_CHARS[((n >> 6) & 0x3F) as usize] as char);
        out.push(B64_URL_CHARS[(n & 0x3F) as usize] as char);
        i += 3;
    }
    match bytes.len() - i {
        1 => {
            let n = (bytes[i] as u32) << 16;
            out.push(B64_URL_CHARS[((n >> 18) & 0x3F) as usize] as char);
            out.push(B64_URL_CHARS[((n >> 12) & 0x3F) as usize] as char);
        }
        2 => {
            let n = ((bytes[i] as u32) << 16) | ((bytes[i + 1] as u32) << 8);
            out.push(B64_URL_CHARS[((n >> 18) & 0x3F) as usize] as char);
            out.push(B64_URL_CHARS[((n >> 12) & 0x3F) as usize] as char);
            out.push(B64_URL_CHARS[((n >> 6) & 0x3F) as usize] as char);
        }
        _ => {}
    }
    out
}

/// Decode a `Base64URL`-encoded string (no padding).
///
/// # Errors
///
/// Returns `None` when a character outside the URL-safe alphabet appears.
#[must_use]
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let table = build_decode_table();
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in bytes {
        let v = *table.get(b as usize)?;
        if v == 0xFF {
            return None;
        }
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

fn build_decode_table() -> [u8; 256] {
    let mut t = [0xFFu8; 256];
    for (i, c) in B64_URL_CHARS.iter().enumerate() {
        t[*c as usize] = i as u8;
    }
    t
}

// ---------------------------------------------------------------------------
// JwsHeader
// ---------------------------------------------------------------------------

/// Fixed `JOSE` header used by this crate.
///
/// `alg = EdDSA` and `typ = JWT` per `RFC 8037` and `RFC 7519`.
#[must_use]
pub fn header_json() -> String {
    "{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}".to_owned()
}

// ---------------------------------------------------------------------------
// Sign / Verify
// ---------------------------------------------------------------------------

/// Sign a `payload` byte slice (usually a UTF-8 JSON blob) and return the
/// compact `JWS` string.
#[must_use]
pub fn sign(payload: &[u8], signer: &KeyPair) -> String {
    let header = b64url_encode(header_json().as_bytes());
    let body = b64url_encode(payload);
    let signing_input = format!("{header}.{body}");
    let sig = signer.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", b64url_encode(&sig.0))
}

/// Verify a compact `JWS` token against the supplied verifying key.
///
/// Returns the decoded payload bytes when the signature checks out.
#[must_use]
pub fn verify(token: &str, verifier: &PublicKey) -> Option<Vec<u8>> {
    let mut parts = token.split('.');
    let header_b = parts.next()?;
    let payload_b = parts.next()?;
    let sig_b = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    // Header sanity check: expect exact JSON string we emit.
    let header = b64url_decode(header_b)?;
    if header != header_json().as_bytes() {
        return None;
    }
    let signing_input = format!("{header_b}.{payload_b}");
    let sig_bytes = b64url_decode(sig_b)?;
    if sig_bytes.len() != 64 {
        return None;
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature(sig_arr);
    if !verifier.verify(signing_input.as_bytes(), &sig) {
        return None;
    }
    b64url_decode(payload_b)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_roundtrip_covers_all_lengths() {
        for len in 0..=64 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 13) as u8).collect();
            let enc = b64url_encode(&bytes);
            let dec = b64url_decode(&enc).expect("decode should succeed");
            assert_eq!(dec, bytes, "roundtrip failed at len {len}");
        }
    }

    #[test]
    fn b64url_uses_url_safe_alphabet() {
        let enc = b64url_encode(&[0xFB, 0xFF, 0xFF]);
        // Result should contain '-' or '_' but never '+' / '/' / '='.
        assert!(!enc.contains('+'));
        assert!(!enc.contains('/'));
        assert!(!enc.contains('='));
    }

    #[test]
    fn b64url_decode_rejects_bad_chars() {
        assert!(b64url_decode("abc$").is_none());
    }

    #[test]
    fn header_is_fixed_json() {
        assert_eq!(header_json(), "{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}");
    }

    #[test]
    fn sign_verify_roundtrip() {
        let signer = KeyPair::from_seed([1u8; 32]);
        let payload = b"{\"sub\":\"did:example:alice\",\"iat\":1720000000}";
        let token = sign(payload, &signer);
        let decoded = verify(&token, &signer.public()).expect("verify should succeed");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let signer = KeyPair::from_seed([1u8; 32]);
        let token = sign(b"{\"sub\":\"alice\"}", &signer);
        let mut parts: Vec<&str> = token.split('.').collect();
        let bad_payload = b64url_encode(b"{\"sub\":\"attacker\"}");
        parts[1] = &bad_payload;
        let tampered = parts.join(".");
        assert!(verify(&tampered, &signer.public()).is_none());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let a = KeyPair::from_seed([1u8; 32]);
        let b = KeyPair::from_seed([2u8; 32]);
        let token = sign(b"payload", &a);
        assert!(verify(&token, &b.public()).is_none());
    }

    #[test]
    fn token_with_four_segments_is_rejected() {
        let signer = KeyPair::from_seed([1u8; 32]);
        let token = sign(b"payload", &signer);
        let broken = format!("{token}.extra");
        assert!(verify(&broken, &signer.public()).is_none());
    }

    #[test]
    fn token_with_short_signature_is_rejected() {
        let signer = KeyPair::from_seed([1u8; 32]);
        let mut token = sign(b"payload", &signer);
        // Truncate the signature segment.
        let last_dot = token.rfind('.').unwrap();
        token.truncate(last_dot + 5);
        assert!(verify(&token, &signer.public()).is_none());
    }
}
