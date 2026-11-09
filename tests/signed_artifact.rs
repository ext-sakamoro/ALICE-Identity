//! Oracle for signed artifacts: a law reference and a payload carried or stored together with the
//! artifact signature that binds them. The encoding and the bound digest are assembled here from the
//! layout in the module documentation, never taken from the code under test; the signature inside
//! is made with `sign_artifact` over that hand-built digest.
//!
//! Every way a stored or received unit can be changed must be refused by `open`, the one function
//! both a receiver and a reader of storage call: a changed law reference, a changed payload, a
//! changed signature, and a consistent rewrite (another law reference with the old signature).

use alice_identity::artifact::{
    sha256_payload, sign_artifact, ArtifactError, PayloadDigest, Revocation, SignedArtifact,
    SIGNED_ARTIFACT_VERSION,
};
use alice_identity::device_cert::{DeviceCert, DeviceCertError};
use alice_identity::did::Did;
use alice_sign::KeyPair;

const NOW: u64 = 1_800_000_100;
const CONTEXT: &[u8] = b"alice-law/e2e/trust-path/v1";
const LAW_REF: &[u8] = b"law reference bytes: union(sphere(10.0), box3d(4.0, 4.0, 4.0))";
const PAYLOAD: &[u8] = b"union(sphere(10.0), box3d(4.0, 4.0, 4.0))";

fn master() -> KeyPair {
    KeyPair::from_seed([7; 32])
}

fn device() -> KeyPair {
    KeyPair::from_seed([8; 32])
}

fn cert() -> DeviceCert {
    let subject = Did::parse("did:alice:sender").unwrap();
    DeviceCert::issue(
        &master(),
        &subject,
        device().public().0,
        [0x4e; 32],
        1_800_000_000,
        1_800_086_400,
    )
    .unwrap()
}

/// SHA-256(law_ref || SHA-256(payload)), as the layout states it
fn expected_digest(law_ref: &[u8], payload: &[u8]) -> PayloadDigest {
    let mut both = law_ref.to_vec();
    both.extend_from_slice(&alice_sign::hash_data(payload).0);
    PayloadDigest::sha256(alice_sign::hash_data(&both).0)
}

/// The encoding as the layout states it: version, law reference, payload, signature, each
/// length-prefixed (u32 BE)
fn expected_bytes(law_ref: &[u8], payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut b = vec![1u8];
    for part in [law_ref, payload, signature] {
        b.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
        b.extend_from_slice(part);
    }
    b
}

fn signed_bytes() -> Vec<u8> {
    SignedArtifact::sign(&device(), &cert(), CONTEXT, LAW_REF, PAYLOAD)
        .unwrap()
        .to_bytes()
}

fn open(bytes: &[u8]) -> Result<alice_identity::artifact::Verified, ArtifactError> {
    SignedArtifact::open(
        bytes,
        &master().public(),
        CONTEXT,
        NOW,
        Revocation::NoListAvailable,
    )
}

#[test]
fn the_encoding_is_the_layout_and_binds_law_reference_and_payload() {
    assert_eq!(SIGNED_ARTIFACT_VERSION, 1);
    // the signature over the hand-built digest, then the hand-built encoding around it
    let sig = sign_artifact(
        &device(),
        &cert(),
        CONTEXT,
        &expected_digest(LAW_REF, PAYLOAD),
    )
    .unwrap();
    let want = expected_bytes(LAW_REF, PAYLOAD, &sig.to_bytes());
    assert_eq!(signed_bytes(), want);
    // SHA-256 of the payload is the payload digest of the artifact module
    assert_eq!(
        &alice_sign::hash_data(PAYLOAD).0,
        sha256_payload(PAYLOAD).bytes()
    );
}

#[test]
fn open_gives_back_what_was_signed() {
    let v = open(&signed_bytes()).unwrap();
    assert_eq!(v.law_ref(), LAW_REF);
    assert_eq!(v.payload(), PAYLOAD);
    assert_eq!(v.signature().context(), CONTEXT);
    assert_eq!(v.signature().digest(), &expected_digest(LAW_REF, PAYLOAD));
}

/// The byte offsets of the three parts in the encoding
fn spans(b: &[u8]) -> [(usize, usize); 3] {
    let mut at = 1;
    let mut out = [(0, 0); 3];
    for slot in &mut out {
        let len = u32::from_be_bytes(b[at..at + 4].try_into().unwrap()) as usize;
        *slot = (at + 4, at + 4 + len);
        at += 4 + len;
    }
    out
}

#[test]
fn a_changed_law_reference_payload_or_signature_is_refused() {
    let good = signed_bytes();
    let [law, payload, sig] = spans(&good);
    let mut refused = 0;
    // one parameter digit in the law reference ("10.0" -> "11.0")
    let mut b = good.clone();
    let at = law.0
        + b[law.0..law.1]
            .windows(4)
            .position(|w| w == b"10.0")
            .unwrap();
    b[at + 1] = b'1';
    assert_eq!(open(&b).unwrap_err(), ArtifactError::DigestMismatch);
    refused += 1;
    // one byte of the payload
    let mut b = good.clone();
    b[payload.0] ^= 1;
    assert_eq!(open(&b).unwrap_err(), ArtifactError::DigestMismatch);
    refused += 1;
    // the last byte: the Ed25519 signature
    let mut b = good.clone();
    b[sig.1 - 1] ^= 1;
    assert_eq!(open(&b).unwrap_err(), ArtifactError::BadSignature);
    refused += 1;
    assert_eq!(refused, 3);
}

#[test]
fn a_consistent_rewrite_with_the_old_signature_is_refused() {
    // a whole new law reference and payload, well formed, kept with the signature of the old ones:
    // what someone with write access to the store but not the device key can make
    let good = signed_bytes();
    let [_, _, sig] = spans(&good);
    let other_ref: &[u8] = b"law reference bytes: union(sphere(99.0), box3d(4.0, 4.0, 4.0))";
    let other_payload: &[u8] = b"union(sphere(99.0), box3d(4.0, 4.0, 4.0))";
    let rewritten = expected_bytes(other_ref, other_payload, &good[sig.0..sig.1]);
    assert_eq!(open(&rewritten).unwrap_err(), ArtifactError::DigestMismatch);
}

#[test]
fn another_signer_purpose_or_master_is_refused() {
    let good = signed_bytes();
    // another purpose
    assert_eq!(
        SignedArtifact::open(
            &good,
            &master().public(),
            b"another/purpose/v1",
            NOW,
            Revocation::NoListAvailable
        )
        .unwrap_err(),
        ArtifactError::ContextMismatch
    );
    // another master key: the certificate does not verify
    assert!(matches!(
        SignedArtifact::open(
            &good,
            &KeyPair::from_seed([9; 32]).public(),
            CONTEXT,
            NOW,
            Revocation::NoListAvailable
        )
        .unwrap_err(),
        ArtifactError::Cert(DeviceCertError::BadSignature | _)
    ));
}

#[test]
fn bytes_that_are_not_one_signed_artifact_are_refused() {
    let good = signed_bytes();
    let mut b = good.clone();
    b[0] = 2;
    assert_eq!(open(&b).unwrap_err(), ArtifactError::UnsupportedVersion(2));
    let mut b = good.clone();
    b.push(0);
    assert!(matches!(open(&b).unwrap_err(), ArtifactError::Malformed(_)));
    for cut in [0, 1, 4, good.len() / 2, good.len() - 1] {
        assert!(
            matches!(
                open(&good[..cut]).unwrap_err(),
                ArtifactError::Malformed(_) | ArtifactError::UnsupportedVersion(_)
            ),
            "cut {cut}"
        );
    }
    // a length that points past the end
    let mut b = good;
    b[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(open(&b).unwrap_err(), ArtifactError::Malformed(_)));
}
