//! Oracle for `DeviceId`: the device identifier a certificate carries is derived from the subject and the
//! device key, never chosen by the issuer.
//!
//! The expected ids are computed outside this crate (Python's `hashlib.sha256` over the documented input:
//! `b"alice-identity/device-id/v1" || u16 BE subject length || subject || device_public`, first 16 bytes),
//! so none of them comes from the code under test.

use alice_identity::cert_revocation::{CertRevocations, RevocationList};
use alice_identity::device_cert::{
    DeviceCert, DeviceCertError, DeviceId, DEVICE_CERT_CONTEXT, DEVICE_CERT_VERSION,
    DEVICE_ID_CONTEXT,
};
use alice_identity::did::Did;
use alice_sign::KeyPair;

const ISSUED_AT: u64 = 1_800_000_000;
const NOT_AFTER: u64 = 1_800_086_400;
const NOISE: [u8; 32] = [0x4e; 32];

fn did(s: &str) -> Did {
    Did::parse(s).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn master() -> KeyPair {
    KeyPair::from_seed([7; 32])
}

fn cert(subject: &str, device: [u8; 32], issued_at: u64, not_after: u64) -> DeviceCert {
    DeviceCert::issue(
        &master(),
        &did(subject),
        device,
        NOISE,
        issued_at,
        not_after,
    )
    .unwrap()
}

/// The offset of the id field in the encoding of a certificate whose subject is `len` bytes
fn id_at(len: usize) -> usize {
    1 + 2 + len + 32 + 32 + 8 + 8
}

#[test]
fn the_id_is_the_documented_hash_of_subject_and_device_key() {
    assert_eq!(DEVICE_ID_CONTEXT, b"alice-identity/device-id/v1");
    // hashlib vectors
    let cases: [(&str, [u8; 32], &str); 3] = [
        (
            "did:alice:person-1",
            [9; 32],
            "8a1fa0de5820c1098a07322ab4b766d4",
        ),
        (
            "did:alice:person-1",
            [0x11; 32],
            "5651b50179de3122f91f5ca01e98bd05",
        ),
        (
            "did:alice:person-2",
            [9; 32],
            "433fed7f056f1d65e381d01c1b4eb44a",
        ),
    ];
    for (subject, device, want) in cases {
        let id = DeviceId::derive(&did(subject), &device).unwrap();
        assert_eq!(hex(id.as_bytes()), want, "{subject}");
        assert_eq!(id.to_string(), want, "Display is the lower-case hex");
    }
    let counting: [u8; 32] = std::array::from_fn(|i| u8::try_from(i).unwrap());
    assert_eq!(
        hex(DeviceId::derive(&did("did:a:b"), &counting)
            .unwrap()
            .as_bytes()),
        "d5f65c6ec03964a31b62dcf8d1767e62"
    );
}

#[test]
fn an_issued_certificate_carries_the_derived_id_in_its_field() {
    let c = cert("did:alice:person-1", [9; 32], ISSUED_AT, NOT_AFTER);
    assert_eq!(DEVICE_CERT_VERSION, 3);
    assert_eq!(
        hex(c.device_id().as_bytes()),
        "8a1fa0de5820c1098a07322ab4b766d4"
    );
    let bytes = c.to_bytes();
    let at = id_at("did:alice:person-1".len());
    assert_eq!(hex(&bytes[at..at + 16]), "8a1fa0de5820c1098a07322ab4b766d4");
    assert_eq!(DeviceCert::from_bytes(&bytes).unwrap(), c);
}

#[test]
fn a_renewal_of_the_same_key_and_subject_has_the_same_id() {
    let first = cert("did:alice:person-1", [9; 32], ISSUED_AT, NOT_AFTER);
    let renewed = cert("did:alice:person-1", [9; 32], NOT_AFTER, NOT_AFTER + 86_400);
    assert_ne!(first.to_bytes(), renewed.to_bytes());
    assert_eq!(first.device_id(), renewed.device_id());
}

#[test]
fn another_subject_or_another_key_has_another_id() {
    let base = cert("did:alice:person-1", [9; 32], ISSUED_AT, NOT_AFTER);
    let alias = cert("did:alice:person-1-alias", [9; 32], ISSUED_AT, NOT_AFTER);
    let other_key = cert("did:alice:person-1", [10; 32], ISSUED_AT, NOT_AFTER);
    assert_ne!(base.device_id(), alias.device_id());
    assert_ne!(base.device_id(), other_key.device_id());
}

/// A certificate whose id field is `id`, validly signed by `m` (the bytes `issue` can no longer make)
fn signed_with_id(m: &KeyPair, version: u8, id: [u8; 16]) -> Vec<u8> {
    let subject = b"did:alice:person-1";
    let mut body = vec![version];
    body.extend_from_slice(&u16::try_from(subject.len()).unwrap().to_be_bytes());
    body.extend_from_slice(subject);
    body.extend_from_slice(&[9; 32]);
    body.extend_from_slice(&NOISE);
    body.extend_from_slice(&ISSUED_AT.to_be_bytes());
    body.extend_from_slice(&NOT_AFTER.to_be_bytes());
    body.extend_from_slice(&id);
    body.extend_from_slice(&m.public().0);
    let mut signed = DEVICE_CERT_CONTEXT.to_vec();
    signed.extend_from_slice(&body);
    let sig = m.sign(&signed).0;
    body.extend_from_slice(&sig);
    body
}

#[test]
fn a_validly_signed_certificate_with_an_issuer_chosen_id_is_refused() {
    let m = master();
    let derived: [u8; 16] = DeviceId::derive(&did("did:alice:person-1"), &[9; 32])
        .unwrap()
        .as_bytes()
        .to_owned();
    // the same bytes with the derived id decode: the refusal below is the id, not the layout
    assert!(DeviceCert::from_bytes(&signed_with_id(&m, 3, derived)).is_ok());
    let mut chosen = derived;
    chosen[15] ^= 1;
    assert_eq!(
        DeviceCert::from_bytes(&signed_with_id(&m, 3, chosen)),
        Err(DeviceCertError::DeviceIdMismatch)
    );
    // one flipped bit anywhere in the stored field is refused as well
    let good = cert("did:alice:person-1", [9; 32], ISSUED_AT, NOT_AFTER).to_bytes();
    let at = id_at("did:alice:person-1".len());
    for i in 0..16 {
        let mut b = good.clone();
        b[at + i] ^= 0x80;
        assert_eq!(
            DeviceCert::from_bytes(&b),
            Err(DeviceCertError::DeviceIdMismatch)
        );
    }
}

#[test]
fn a_version_2_certificate_is_refused_with_its_version() {
    let m = master();
    let derived = *DeviceId::derive(&did("did:alice:person-1"), &[9; 32])
        .unwrap()
        .as_bytes();
    // version 2 had the same layout with an issuer-chosen id: neither an arbitrary nor a derived id decodes
    assert_eq!(
        DeviceCert::from_bytes(&signed_with_id(&m, 2, [0xa5; 16])),
        Err(DeviceCertError::UnsupportedVersion(2))
    );
    assert_eq!(
        DeviceCert::from_bytes(&signed_with_id(&m, 2, derived)),
        Err(DeviceCertError::UnsupportedVersion(2))
    );
}

#[test]
fn revoking_a_device_id_revokes_every_certificate_of_that_key() {
    let m = master();
    let first = cert("did:alice:person-1", [9; 32], ISSUED_AT, NOT_AFTER);
    let renewed = cert("did:alice:person-1", [9; 32], NOT_AFTER, NOT_AFTER + 86_400);
    let other = cert("did:alice:person-1", [10; 32], ISSUED_AT, NOT_AFTER);
    let mut revocations = CertRevocations::new();
    revocations
        .accept(
            RevocationList::issue(&m, 1, ISSUED_AT, &[first.device_id()]),
            &m.public(),
        )
        .unwrap();
    assert!(revocations.revokes(&first));
    assert!(revocations.revokes(&renewed));
    assert!(!revocations.revokes(&other));
    assert!(revocations.is_revoked(&m.public(), &renewed.device_id()));
}

#[test]
fn an_id_reads_back_from_its_bytes() {
    let id = DeviceId::derive(&did("did:alice:person-1"), &[9; 32]).unwrap();
    assert_eq!(DeviceId::from_raw(*id.as_bytes()), id);
    assert_eq!(DeviceId::from(*id.as_bytes()), id);
    assert_eq!(AsRef::<[u8]>::as_ref(&id), id.as_bytes());
}

#[test]
fn a_subject_too_long_for_a_certificate_has_no_id() {
    let long = format!("did:alice:{}", "x".repeat(300));
    assert!(matches!(
        DeviceId::derive(&did(&long), &[9; 32]),
        Err(DeviceCertError::SubjectTooLong(_))
    ));
}
