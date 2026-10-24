//! did:key for Ed25519 public keys: `did:key:z` + base58btc(0xed 0x01 ‖ the 32 key bytes).
//!
//! Vectors: the did:key method specification (W3C CCG, "The did:key Method"), Appendix "Test
//! Vectors", section "Ed25519" and section "Ed25519 with X25519" (the Ed25519 identifier). The key
//! bytes those identifiers carry, and the identifier of the RFC 8032 section 7.1 TEST 1 public key,
//! were computed with an independent base58btc implementation (Python, standard library).

use alice_identity::did::Did;
use alice_sign::PublicKey;

fn unhex(s: &str) -> [u8; 32] {
    let v: Vec<u8> = (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect();
    v.try_into().expect("32 bytes")
}

/// (identifier, the Ed25519 public key it carries)
const VECTORS: [(&str, &str); 3] = [
    // spec, Test Vectors, Ed25519
    (
        "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
        "095f9a1a595dde755d82786864ad03dfa5a4fbd68832566364e2b65e13cc9e44",
    ),
    // spec, Test Vectors, Ed25519 with X25519 (its Ed25519 identifier)
    (
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        "2e6fcce36701dc791488e0d0b1745cc1e33a4c1c9fcc41c63bd343dbbe0970e6",
    ),
    // RFC 8032 section 7.1, TEST 1 public key
    (
        "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    ),
];

#[test]
fn a_public_key_gives_its_did_key() {
    for (did, key) in VECTORS {
        let d = Did::key_ed25519(&PublicKey(unhex(key)));
        assert_eq!(d.method, "key");
        assert_eq!(d.to_string(), did);
    }
}

#[test]
fn a_did_key_gives_back_its_public_key() {
    for (did, key) in VECTORS {
        let d = Did::parse(did).expect("a DID");
        assert_eq!(
            d.ed25519_public_key().expect("an Ed25519 did:key").0,
            unhex(key),
            "{did}"
        );
    }
}

#[test]
fn every_key_round_trips() {
    for seed in 0u8..=255 {
        let mut k = [seed; 32];
        k[0] = seed.wrapping_mul(31);
        k[31] = 0;
        let back = Did::key_ed25519(&PublicKey(k))
            .ed25519_public_key()
            .expect("round trip");
        assert_eq!(back.0, k);
    }
    // leading zero bytes in the key survive (base58btc writes each as '1' only before the value)
    let zeros = [0u8; 32];
    assert_eq!(
        Did::key_ed25519(&PublicKey(zeros))
            .ed25519_public_key()
            .expect("zeros")
            .0,
        zeros
    );
}

fn refused(did: &str) -> String {
    let d = Did::parse(did).expect("a DID");
    match d.ed25519_public_key() {
        Ok(_) => panic!("{did} was accepted"),
        Err(e) => e.to_string(),
    }
}

#[test]
fn a_wrong_multicodec_is_refused() {
    // secp256k1 (spec, Test Vectors, Secp256k1)
    let e = refused("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme");
    assert!(e.contains("not an Ed25519"), "{e}");
}

#[test]
fn a_wrong_length_is_refused() {
    // the Ed25519 multicodec followed by 31 and by 33 key bytes
    for n in [31usize, 33] {
        let mut bytes = vec![0xed, 0x01];
        bytes.extend(std::iter::repeat_n(7u8, n));
        let e = refused(&format!(
            "did:key:z{}",
            alice_identity::base58::encode(&bytes)
        ));
        assert!(e.contains("length"), "{n}: {e}");
    }
}

#[test]
fn a_character_outside_the_base58_alphabet_is_refused() {
    let (did, _) = VECTORS[0];
    for bad in ['0', 'O', 'I', 'l', '+', '/'] {
        let mut s = did.to_string();
        s.replace_range(s.len() - 1.., &bad.to_string());
        let e = refused(&s);
        assert!(e.contains("base58"), "{bad}: {e}");
    }
}

#[test]
fn another_method_or_multibase_is_refused() {
    let e = refused("did:web:example.org");
    assert!(e.contains("did:key"), "{e}");
    // base58btc is the multibase 'z'; 'u' (base64url) is not accepted
    let (did, _) = VECTORS[0];
    let e = refused(&did.replacen("did:key:z", "did:key:u", 1));
    assert!(e.contains("multibase"), "{e}");
}
