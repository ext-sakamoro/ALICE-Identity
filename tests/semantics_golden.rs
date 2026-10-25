//! Recorded-bit goldens of what the crate produces from fixed keys (ALICE-Law G4, the pins of
//! `IDENTITY_SEMANTICS_ID`, G6).
//!
//! Each scenario signs or encodes with fixed Ed25519 seeds (Ed25519 signing is deterministic) and records the
//! SHA-256 of every byte it produced. The digests are recorded from the current build: `tests/device_cert.rs`,
//! `tests/artifact.rs` and `tests/did_key.rs` are the independent oracles of the layouts, and these goldens pin
//! the bytes as a whole. Every CI leg (debug and release, x86_64 and aarch64) must reproduce them bit for bit.

use alice_identity::artifact::{sha256_payload, sign_artifact};
use alice_identity::device_cert::DeviceCert;
use alice_identity::did::Did;
use alice_identity::jws;
use alice_identity::signed_did::{ClaimSet, SignedClaim};
use alice_sign::KeyPair;

fn digest(bytes: &[u8]) -> [u8; 32] {
    alice_sign::hash_data(bytes).0
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The SHA-256 of `bytes` when it is not `expected`
fn golden_mismatch(bytes: &[u8], expected: &str) -> Option<String> {
    let got = hex(&digest(bytes));
    (got != expected).then_some(got)
}

/// A scenario that produced nothing compared nothing
fn produced(name: &str, bytes: &[u8]) {
    assert!(!bytes.is_empty(), "{name}: the scenario produced no bytes");
}

fn assert_golden(name: &str, bytes: &[u8], expected: &str) {
    produced(name, bytes);
    if let Some(got) = golden_mismatch(bytes, expected) {
        panic!("{name} golden moved: {got}, recorded {expected}");
    }
}

#[test]
fn checker_rejects_a_wrong_digest() {
    let recorded = hex(&digest(b"recorded bits"));
    assert_eq!(golden_mismatch(b"recorded bits", &recorded), None);
    assert!(golden_mismatch(b"moved bits", &recorded).is_some());
}

#[test]
#[should_panic(expected = "produced no bytes")]
fn checker_rejects_a_scenario_that_produced_nothing() {
    produced("empty", b"");
}

const ISSUED_AT: u64 = 1_800_000_000;
const NOT_AFTER: u64 = 1_800_086_400;

fn master() -> KeyPair {
    KeyPair::from_seed([7; 32])
}

fn device() -> KeyPair {
    KeyPair::from_seed([9; 32])
}

fn cert() -> DeviceCert {
    DeviceCert::issue(
        &master(),
        &Did::parse("did:alice:person-1").unwrap(),
        device().public().0,
        [0x4e; 32],
        ISSUED_AT,
        NOT_AFTER,
        [0xa5; 16],
    )
    .unwrap()
}

#[test]
fn device_certificate() {
    assert_golden(
        "device certificate",
        &cert().to_bytes(),
        "5b007b2cc3f4e2238774eed0b02fa7c710b03e8e2251916740b46427c5cda418",
    );
}

#[test]
fn artifact_signature() {
    let sig = sign_artifact(
        &device(),
        &cert(),
        b"firmware",
        &sha256_payload(b"artifact payload"),
    )
    .unwrap();
    assert_golden(
        "artifact signature",
        &sig.to_bytes(),
        "5c7e5cdbc180d7f888b1ea8e374b3a3ab3d8b6629101adfb33a654dbf2696b70",
    );
}

#[test]
fn signed_claim() {
    let mut claims = ClaimSet::new("did:alice:person-1");
    claims.insert("name", "Alice");
    claims.insert("age", "30");
    let signed = SignedClaim::issue(&KeyPair::from_seed([5; 32]), claims);
    let mut bytes = signed.claims.canonical_bytes();
    bytes.extend_from_slice(&signed.issuer_public.0);
    bytes.extend_from_slice(&signed.signature.0);
    assert_golden(
        "signed claim",
        &bytes,
        "bcd9a6d8d8f3b424a0dc9e4b493b5ac17c5c15834e18727a9ff97686c4ed4b92",
    );
}

#[test]
fn did_key() {
    let did = Did::key_ed25519(&master().public()).to_string();
    assert_golden(
        "did:key",
        did.as_bytes(),
        "f9c3f1afd7f5166ac217fe97df231353b8c3fd91f9f3b985ba033876a692c1b3",
    );
}

#[test]
fn compact_jws() {
    let token = jws::sign(b"{\"sub\":\"did:alice:person-1\"}", &master());
    assert_golden(
        "compact jws",
        token.as_bytes(),
        "afc7989ada00fc73b7b5f5965998b9d69d63e85be747a2e1910c3bba3ba12898",
    );
}
