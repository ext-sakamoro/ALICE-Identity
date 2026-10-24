//! Oracle for artifact signatures. The signed message and the encoding are assembled here from the
//! layout in the module documentation, and the expected signature is made with alice-sign over
//! that message, so neither comes from the code under test. SHA-256 is checked against the
//! FIPS 180-2 "abc" vector.

use alice_identity::artifact::{
    sha256_payload, sign_artifact, verify_artifact, ArtifactError, ArtifactSignature, DigestAlg,
    PayloadDigest, Revocation, ARTIFACT_DOMAIN, ARTIFACT_VERSION, MAX_CONTEXT_LEN,
};
use alice_identity::cert_revocation::{CertRevocations, RevocationList};
use alice_identity::device_cert::{DeviceCert, DeviceCertError};
use alice_identity::did::Did;
use alice_sign::{KeyPair, PublicKey, Signature};

const ISSUED_AT: u64 = 1_800_000_000;
const NOT_AFTER: u64 = 1_800_086_400;
const NOW: u64 = 1_800_000_100;
const CERT_ID: [u8; 16] = [0xa5; 16];
const CONTEXT: &[u8] = b"alice-mls/artifact/v1";

fn master() -> KeyPair {
    KeyPair::from_seed([7; 32])
}

fn device() -> KeyPair {
    KeyPair::from_seed([8; 32])
}

fn cert_with(device_public: [u8; 32], cert_id: [u8; 16]) -> DeviceCert {
    let subject = Did::parse("did:alice:person-1").unwrap();
    DeviceCert::issue(
        &master(),
        &subject,
        device_public,
        ISSUED_AT,
        NOT_AFTER,
        cert_id,
    )
    .unwrap()
}

fn cert() -> DeviceCert {
    cert_with(device().public().0, CERT_ID)
}

fn digest() -> PayloadDigest {
    sha256_payload(b"the payload")
}

fn signed() -> ArtifactSignature {
    sign_artifact(&device(), &cert(), CONTEXT, &digest()).unwrap()
}

/// The signed message as the layout states it, built byte by byte: it ends with the SHA-256 of
/// the whole certificate, so the signature belongs to that certificate (issuer, subject, window)
fn expected_message(context: &[u8], digest: &[u8; 32], cert: &DeviceCert) -> Vec<u8> {
    let mut m = b"alice-identity artifact v1".to_vec();
    m.extend_from_slice(&[u8::try_from(context.len()).unwrap()]);
    m.extend_from_slice(context);
    m.extend_from_slice(&[1u8]); // SHA-256
    m.extend_from_slice(digest);
    m.extend_from_slice(&alice_sign::hash_data(&cert.to_bytes()).0);
    m
}

/// The encoding as the layout states it: version, context, digest, the certificate, signature
fn expected_bytes(context: &[u8], digest: &[u8; 32], cert: &DeviceCert, sig: &[u8; 64]) -> Vec<u8> {
    let c = cert.to_bytes();
    let mut b = vec![1u8];
    b.extend_from_slice(&[u8::try_from(context.len()).unwrap()]);
    b.extend_from_slice(context);
    b.extend_from_slice(&[1u8]);
    b.extend_from_slice(digest);
    b.extend_from_slice(&u16::try_from(c.len()).unwrap().to_be_bytes());
    b.extend_from_slice(&c);
    b.extend_from_slice(sig);
    b
}

fn verify(sig: &ArtifactSignature) -> Result<(), ArtifactError> {
    verify_artifact(
        sig,
        &master().public(),
        CONTEXT,
        &digest(),
        NOW,
        Revocation::NoListAvailable,
    )
}

#[test]
fn sha256_payload_is_sha256() {
    // FIPS 180-2 appendix B.1
    let want = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    let d = sha256_payload(b"abc");
    assert_eq!(d.alg(), DigestAlg::Sha256);
    assert_eq!(d.bytes(), &want);
    assert_eq!(PayloadDigest::sha256(want), d);
}

#[test]
fn the_signature_covers_the_documented_message_and_encodes_as_documented() {
    let d = digest();
    let msg = expected_message(CONTEXT, d.bytes(), &cert());
    let sig = device().sign(&msg).0;
    let s = signed();
    assert_eq!(ARTIFACT_DOMAIN, b"alice-identity artifact v1");
    assert_eq!(ARTIFACT_VERSION, 1);
    assert_eq!(MAX_CONTEXT_LEN, 64);
    assert_eq!(s.signed_message(), msg);
    assert_eq!(s.signature(), &sig);
    assert_eq!(s.context(), CONTEXT);
    assert_eq!(s.digest(), &d);
    assert_eq!(s.cert(), &cert());
    let want = expected_bytes(CONTEXT, d.bytes(), &cert(), &sig);
    assert_eq!(s.to_bytes(), want);
    // golden size: 1 + 1 + 21 + 1 + 32 + 2 + 181 (the device certificate) + 64
    assert_eq!(want.len(), 303);
    assert_eq!(ArtifactSignature::from_bytes(&want), Ok(s));
}

#[test]
fn a_valid_signature_verifies() {
    assert_eq!(verify(&signed()), Ok(()));
    let back = ArtifactSignature::from_bytes(&signed().to_bytes()).unwrap();
    assert_eq!(verify(&back), Ok(()));
}

#[test]
fn a_signature_made_for_one_context_does_not_verify_for_another() {
    let s = signed();
    assert_eq!(
        verify_artifact(
            &s,
            &master().public(),
            b"text-to-print/manifest/v1",
            &digest(),
            NOW,
            Revocation::NoListAvailable
        ),
        Err(ArtifactError::ContextMismatch)
    );
    // rewriting the context in the bytes does not help: the signature covers it
    let other = b"alice-mls/artifact/v2";
    let mut bytes = s.to_bytes();
    bytes[2..2 + other.len()].copy_from_slice(other);
    let moved = ArtifactSignature::from_bytes(&bytes).unwrap();
    assert_eq!(
        verify_artifact(
            &moved,
            &master().public(),
            other,
            &digest(),
            NOW,
            Revocation::NoListAvailable
        ),
        Err(ArtifactError::BadSignature)
    );
}

#[test]
fn a_signature_does_not_verify_for_another_digest() {
    let s = signed();
    let other = sha256_payload(b"another payload");
    assert_eq!(
        verify_artifact(
            &s,
            &master().public(),
            CONTEXT,
            &other,
            NOW,
            Revocation::NoListAvailable
        ),
        Err(ArtifactError::DigestMismatch)
    );
    let at = 2 + CONTEXT.len() + 1;
    let mut bytes = s.to_bytes();
    bytes[at..at + 32].copy_from_slice(other.bytes());
    let moved = ArtifactSignature::from_bytes(&bytes).unwrap();
    assert_eq!(
        verify_artifact(
            &moved,
            &master().public(),
            CONTEXT,
            &other,
            NOW,
            Revocation::NoListAvailable
        ),
        Err(ArtifactError::BadSignature)
    );
}

#[test]
fn binding_a_law_ref_into_the_digest_separates_signatures_over_the_same_payload() {
    // the pattern the API documents: bind everything to protect into the one digest
    let payload = sha256_payload(b"the mesh");
    let bound = |law_ref: &[u8]| {
        let mut joined = law_ref.to_vec();
        joined.extend_from_slice(payload.bytes());
        sha256_payload(&joined)
    };
    let a = bound(b"LOLR law A");
    let b = bound(b"LOLR law B");
    assert_ne!(a, b);
    let sa = sign_artifact(&device(), &cert(), CONTEXT, &a).unwrap();
    let sb = sign_artifact(&device(), &cert(), CONTEXT, &b).unwrap();
    assert_ne!(sa.signature(), sb.signature());
    let m = master().public();
    assert_eq!(
        verify_artifact(&sa, &m, CONTEXT, &a, NOW, Revocation::NoListAvailable),
        Ok(())
    );
    assert_eq!(
        verify_artifact(&sa, &m, CONTEXT, &b, NOW, Revocation::NoListAvailable),
        Err(ArtifactError::DigestMismatch)
    );
}

#[test]
fn a_tampered_signature_is_refused() {
    let mut bytes = signed().to_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let s = ArtifactSignature::from_bytes(&bytes).unwrap();
    assert_eq!(verify(&s), Err(ArtifactError::BadSignature));
}

#[test]
fn a_signature_does_not_move_to_another_certificate_of_the_same_device_key() {
    let s = signed();
    let other_cert = cert_with(device().public().0, [0x5a; 16]);
    let moved_bytes = expected_bytes(CONTEXT, digest().bytes(), &other_cert, s.signature());
    let moved = ArtifactSignature::from_bytes(&moved_bytes).unwrap();
    assert_eq!(verify(&moved), Err(ArtifactError::BadSignature));
}

#[test]
fn signing_needs_the_key_the_certificate_names() {
    let stranger = KeyPair::from_seed([9; 32]);
    assert_eq!(
        sign_artifact(&stranger, &cert(), CONTEXT, &digest()),
        Err(ArtifactError::KeyMismatch)
    );
}

#[test]
fn the_certificate_is_checked_at_the_verifiers_time_and_against_the_master() {
    let s = signed();
    let m = master().public();
    assert_eq!(
        verify_artifact(
            &s,
            &m,
            CONTEXT,
            &digest(),
            ISSUED_AT - 1,
            Revocation::NoListAvailable
        ),
        Err(ArtifactError::Cert(DeviceCertError::NotYetValid {
            now: ISSUED_AT - 1,
            issued_at: ISSUED_AT
        }))
    );
    assert_eq!(
        verify_artifact(
            &s,
            &m,
            CONTEXT,
            &digest(),
            NOT_AFTER,
            Revocation::NoListAvailable
        ),
        Err(ArtifactError::Cert(DeviceCertError::Expired {
            now: NOT_AFTER,
            not_after: NOT_AFTER
        }))
    );
    let other_master = KeyPair::from_seed([11; 32]).public();
    assert_eq!(
        verify_artifact(
            &s,
            &other_master,
            CONTEXT,
            &digest(),
            NOW,
            Revocation::NoListAvailable
        ),
        Err(ArtifactError::Cert(DeviceCertError::IssuerMismatch))
    );
}

#[test]
fn a_revoked_certificate_is_refused() {
    let s = signed();
    let m = master();
    let mut revocations = CertRevocations::new();
    revocations
        .accept(
            RevocationList::issue(&m, 1, ISSUED_AT, &[CERT_ID]),
            &m.public(),
        )
        .unwrap();
    assert_eq!(
        verify_artifact(
            &s,
            &m.public(),
            CONTEXT,
            &digest(),
            NOW,
            Revocation::Checked(&revocations)
        ),
        Err(ArtifactError::Revoked)
    );
    let mut others = CertRevocations::new();
    others
        .accept(
            RevocationList::issue(&m, 1, ISSUED_AT, &[[0x5a; 16]]),
            &m.public(),
        )
        .unwrap();
    assert_eq!(
        verify_artifact(
            &s,
            &m.public(),
            CONTEXT,
            &digest(),
            NOW,
            Revocation::Checked(&others)
        ),
        Ok(())
    );
}

#[test]
fn contexts_must_be_1_to_64_printable_ascii_bytes_without_outer_spaces() {
    let bad: [&[u8]; 6] = [
        b"",
        &[b'a'; 65],
        b"caf\xc3\xa9/v1",
        b" lead/v1",
        b"trail/v1 ",
        b"tab\t/v1",
    ];
    for context in bad {
        assert_eq!(
            sign_artifact(&device(), &cert(), context, &digest()),
            Err(ArtifactError::InvalidContext),
            "{context:?}"
        );
        assert_eq!(
            verify_artifact(
                &signed(),
                &master().public(),
                context,
                &digest(),
                NOW,
                Revocation::NoListAvailable
            ),
            Err(ArtifactError::InvalidContext),
            "{context:?}"
        );
    }
    let longest = [b'a'; 64];
    let s = sign_artifact(&device(), &cert(), &longest, &digest()).unwrap();
    assert_eq!(
        verify_artifact(
            &s,
            &master().public(),
            &longest,
            &digest(),
            NOW,
            Revocation::NoListAvailable
        ),
        Ok(())
    );
    assert!(sign_artifact(&device(), &cert(), b"inner space/v1", &digest()).is_ok());
}

#[test]
fn decoding_is_strict() {
    let bytes = signed().to_bytes();
    for n in 0..bytes.len() {
        assert!(
            ArtifactSignature::from_bytes(&bytes[..n]).is_err(),
            "a {n}-byte prefix decoded"
        );
    }
    let mut longer = bytes.clone();
    longer.extend_from_slice(&[0]);
    assert!(matches!(
        ArtifactSignature::from_bytes(&longer),
        Err(ArtifactError::Malformed(_))
    ));
    let mut v2 = bytes.clone();
    v2[0] = 2;
    assert_eq!(
        ArtifactSignature::from_bytes(&v2),
        Err(ArtifactError::UnsupportedVersion(2))
    );
    let mut alg = bytes.clone();
    alg[2 + CONTEXT.len()] = 2;
    assert_eq!(
        ArtifactSignature::from_bytes(&alg),
        Err(ArtifactError::UnsupportedDigest(2))
    );
    let mut ctx = bytes.clone();
    ctx[2] = 0x80;
    assert_eq!(
        ArtifactSignature::from_bytes(&ctx),
        Err(ArtifactError::InvalidContext)
    );
    let mut bad_cert = bytes;
    let cert_at = 2 + CONTEXT.len() + 1 + 32 + 2;
    bad_cert[cert_at] = 9; // the certificate's own version byte
    assert!(matches!(
        ArtifactSignature::from_bytes(&bad_cert),
        Err(ArtifactError::Cert(DeviceCertError::UnsupportedVersion(9)))
    ));
}

#[test]
fn a_non_canonical_signature_scalar_is_refused() {
    // S + L (the group order) is the same scalar modulo L; only the reduced one is accepted
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let mut bytes = signed().to_bytes();
    let s_at = bytes.len() - 32;
    let mut carry = 0u16;
    for i in 0..32 {
        let v = u16::from(bytes[s_at + i]) + u16::from(L[i]) + carry;
        bytes[s_at + i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    assert_eq!(carry, 0, "S + L fits in 32 bytes");
    let tweaked = ArtifactSignature::from_bytes(&bytes).unwrap();
    assert_eq!(verify(&tweaked), Err(ArtifactError::BadSignature));
}

#[test]
fn a_weak_device_key_is_refused_even_when_the_lax_equation_holds() {
    // device key = the identity point (small order): R = B with s = 1 satisfies the lax check for
    // any message; only strict verification rejects it
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut b = [0x66u8; 32];
    b[0] = 0x58;
    let mut s = [0u8; 32];
    s[0] = 1;
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&b);
    sig[32..].copy_from_slice(&s);
    let weak_cert = cert_with(identity, CERT_ID);
    let bytes = expected_bytes(CONTEXT, digest().bytes(), &weak_cert, &sig);
    let forged = ArtifactSignature::from_bytes(&bytes).unwrap();
    let weak = PublicKey(identity);
    // the oracle's premise, measured: the lax check accepts, the strict one refuses
    assert!(weak.verify(&forged.signed_message(), &Signature(sig)));
    assert!(!weak.verify_strict(&forged.signed_message(), &Signature(sig)));
    assert_eq!(verify(&forged), Err(ArtifactError::BadSignature));
}

#[test]
fn a_certificate_too_long_for_the_length_field_is_refused() {
    // the certificate's length is a u16; a subject near the u16 limit makes a longer certificate
    let id = "a".repeat(65_500);
    let subject = Did::parse(&format!("did:alice:{id}")).unwrap();
    let long = DeviceCert::issue(
        &master(),
        &subject,
        device().public().0,
        ISSUED_AT,
        NOT_AFTER,
        CERT_ID,
    )
    .unwrap();
    assert!(long.to_bytes().len() > usize::from(u16::MAX));
    assert_eq!(
        sign_artifact(&device(), &long, CONTEXT, &digest()),
        Err(ArtifactError::Malformed(
            "certificate longer than 65535 bytes"
        ))
    );
}

#[test]
fn a_signature_does_not_move_to_another_issuers_certificate_for_the_same_key_and_id() {
    // another master issues its own certificate for the victim's device key, with the same
    // certificate id and its own subject, and swaps it in: the signature must not follow
    let s = signed();
    let other_master = KeyPair::from_seed([12; 32]);
    let other_subject = Did::parse("did:alice:someone-else").unwrap();
    let foreign = DeviceCert::issue(
        &other_master,
        &other_subject,
        device().public().0,
        ISSUED_AT,
        NOT_AFTER,
        CERT_ID,
    )
    .unwrap();
    assert_eq!(foreign.cert_id(), cert().cert_id());
    let swapped_bytes = expected_bytes(CONTEXT, digest().bytes(), &foreign, s.signature());
    let swapped = ArtifactSignature::from_bytes(&swapped_bytes).unwrap();
    assert_eq!(
        verify_artifact(
            &swapped,
            &other_master.public(),
            CONTEXT,
            &digest(),
            NOW,
            Revocation::NoListAvailable
        ),
        Err(ArtifactError::BadSignature)
    );
}

#[test]
fn revocation_is_checked_only_when_a_list_is_given_and_skipping_it_is_explicit() {
    let s = signed();
    let m = master();
    let mut revoking = CertRevocations::new();
    revoking
        .accept(
            RevocationList::issue(&m, 1, ISSUED_AT, &[CERT_ID]),
            &m.public(),
        )
        .unwrap();
    // with the list: refused; stating that no list exists: accepted (the caller's statement)
    assert_eq!(
        verify_artifact(
            &s,
            &m.public(),
            CONTEXT,
            &digest(),
            NOW,
            Revocation::Checked(&revoking)
        ),
        Err(ArtifactError::Revoked)
    );
    assert_eq!(
        verify_artifact(
            &s,
            &m.public(),
            CONTEXT,
            &digest(),
            NOW,
            Revocation::NoListAvailable
        ),
        Ok(())
    );
    // an empty list is a checked list: nothing revoked
    let empty = CertRevocations::new();
    assert_eq!(
        verify_artifact(
            &s,
            &m.public(),
            CONTEXT,
            &digest(),
            NOW,
            Revocation::Checked(&empty)
        ),
        Ok(())
    );
}
