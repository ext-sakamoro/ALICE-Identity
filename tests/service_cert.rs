//! Oracle for `service_cert`: a service's key statement is a version 3 device certificate whose subject
//! is `did:alice-service:<service>`.
//!
//! The golden encoding was computed outside this crate (Python: hashlib for the device id and the
//! digest, PyNaCl for the Ed25519 signature over the documented context and body), so it does not come
//! from the code under test.

use alice_identity::artifact::Revocation;
use alice_identity::cert_revocation::{CertRevocations, RevocationList};
use alice_identity::device_cert::{DeviceCert, DeviceCertError, DeviceId, DEVICE_CERT_CONTEXT};
use alice_identity::did::Did;
use alice_identity::service_cert::{
    issue_service_cert, service_subject, verify_service_cert, ServiceCertError,
    MAX_SERVICE_NAME_LEN, SERVICE_CERT_MAX_LIFETIME_SECS, SERVICE_DID_METHOD,
};
use alice_sign::{hash_data, KeyPair};

const SERVICE: &str = "relay";
const ISSUED_AT: u64 = 1_800_000_000;
const NOT_AFTER: u64 = ISSUED_AT + 30 * 86_400;
const NOISE: [u8; 32] = [0x4e; 32];

/// A test fixture, never a production key: the operator's master key of these tests
fn master() -> KeyPair {
    KeyPair::from_seed([0x5a; 32])
}

/// A test fixture: the service's signing key
fn signing() -> [u8; 32] {
    KeyPair::from_seed([0x11; 32]).public().0
}

fn issued() -> DeviceCert {
    issue_service_cert(&master(), SERVICE, signing(), NOISE, ISSUED_AT, NOT_AFTER).unwrap()
}

fn verify_at(cert: &DeviceCert, now: u64) -> Result<[u8; 32], ServiceCertError> {
    verify_service_cert(
        cert,
        &master().public(),
        SERVICE,
        now,
        Revocation::NoListAvailable,
    )
}

/// The encoding of `issued()`, computed outside this crate (see the module documentation)
const GOLDEN_HEX: &str = "0300176469643a616c6963652d736572766963653a72656c6179d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787374e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e000000006b49d200000000006b715f002cc6cdf9011839b93c29b491383786f10d7550754e0800a5d237eef5826035766b9b3e5a15868a940ab289958788e3b076cb83f514f51e6d9771e083edb773f3ad5bbba05d953757b687acc1a1a55a0248fb903d7bd4d46f8a195422244fa423032ff1fd425759c38e05976b0eec6402";
/// SHA-256 of the golden encoding (hashlib)
const GOLDEN_SHA256: &str = "7413768a2378268f2f420a8a0febe622921c3d12352c52ab8531a25a58e7ef10";
/// The device id of the signing key under `did:alice-service:relay` (hashlib)
const GOLDEN_DEVICE_ID: &str = "2cc6cdf9011839b93c29b491383786f1";

/// A certificate for `subject` laid out by hand (the documented version 3 layout) and signed by `m`
///
/// `DeviceCert::issue` refuses the reserved method and `issue_service_cert` refuses a lifetime over
/// the bound, so a correctly signed service certificate that breaks the bound is made here, as an
/// operator signing by hand could make it.
fn hand_signed(m: &KeyPair, subject: &Did, issued_at: u64, not_after: u64) -> DeviceCert {
    let text = subject.to_string();
    let mut body = vec![3u8];
    body.extend_from_slice(&u16::try_from(text.len()).unwrap().to_be_bytes());
    body.extend_from_slice(text.as_bytes());
    body.extend_from_slice(&signing());
    body.extend_from_slice(&NOISE);
    body.extend_from_slice(&issued_at.to_be_bytes());
    body.extend_from_slice(&not_after.to_be_bytes());
    body.extend_from_slice(DeviceId::derive(subject, &signing()).unwrap().as_bytes());
    body.extend_from_slice(&m.public().0);
    let mut signed = DEVICE_CERT_CONTEXT.to_vec();
    signed.extend_from_slice(&body);
    body.extend_from_slice(&m.sign(&signed).0);
    DeviceCert::from_bytes(&body).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// --- the subject and the name rule ---

#[test]
fn the_subject_is_the_reserved_service_did() {
    assert_eq!(SERVICE_DID_METHOD, "alice-service");
    let s = service_subject(SERVICE).unwrap();
    assert_eq!(s.to_string(), "did:alice-service:relay");
    // the generic DID parser accepts the method, and the text reads back as the same DID
    assert_eq!(Did::parse("did:alice-service:relay").unwrap(), s);
}

#[test]
fn good_service_names_are_accepted() {
    let longest = "a".repeat(MAX_SERVICE_NAME_LEN);
    let names = [
        "relay",
        "r",
        "0",
        "relay-2",
        "a-b-c",
        "push9",
        longest.as_str(),
    ];
    let mut compared = 0;
    for name in names {
        assert_eq!(
            service_subject(name).unwrap().to_string(),
            format!("did:alice-service:{name}")
        );
        compared += 1;
    }
    assert_eq!(compared, names.len());
    assert!(compared > 0);
}

#[test]
fn bad_service_names_are_refused_at_subject_issue_and_verify() {
    let too_long = "a".repeat(MAX_SERVICE_NAME_LEN + 1);
    let names = [
        "",
        "Relay",
        "RELAY",
        "re lay",
        "re_lay",
        "re.lay",
        "re:lay",
        "re/lay",
        "-relay",
        "relay-",
        "-",
        "rélay",
        "relay\n",
        too_long.as_str(),
    ];
    let cert = issued();
    let mut compared = 0;
    for name in names {
        assert_eq!(
            service_subject(name),
            Err(ServiceCertError::BadServiceName),
            "{name:?}"
        );
        assert_eq!(
            issue_service_cert(&master(), name, signing(), NOISE, ISSUED_AT, NOT_AFTER),
            Err(ServiceCertError::BadServiceName),
            "{name:?}"
        );
        assert_eq!(
            verify_service_cert(
                &cert,
                &master().public(),
                name,
                ISSUED_AT,
                Revocation::NoListAvailable
            ),
            Err(ServiceCertError::BadServiceName),
            "{name:?}"
        );
        compared += 1;
    }
    assert_eq!(compared, names.len());
    assert!(compared > 0);
}

// --- accepts ---

#[test]
fn a_fixture_signed_certificate_returns_its_noise_static_key() {
    let c = issued();
    assert_eq!(verify_at(&c, ISSUED_AT), Ok(NOISE));
    assert_eq!(verify_at(&c, NOT_AFTER - 1), Ok(NOISE));
    // the device-certificate start leeway applies
    assert_eq!(verify_at(&c, ISSUED_AT - 600), Ok(NOISE));
    // decoded from its bytes, it verifies the same way
    let back = DeviceCert::from_bytes(&c.to_bytes()).unwrap();
    assert_eq!(verify_at(&back, ISSUED_AT), Ok(NOISE));
}

#[test]
fn a_renewal_with_the_same_keys_keeps_the_device_id() {
    let first = issued();
    let renewal = issue_service_cert(
        &master(),
        SERVICE,
        signing(),
        NOISE,
        NOT_AFTER - 86_400,
        NOT_AFTER - 86_400 + SERVICE_CERT_MAX_LIFETIME_SECS,
    )
    .unwrap();
    assert_eq!(first.device_id(), renewal.device_id());
    assert_eq!(verify_at(&renewal, NOT_AFTER), Ok(NOISE));
}

// --- the golden encoding ---

#[test]
fn the_encoding_of_a_fixed_service_certificate_is_the_recorded_bytes() {
    let c = issued();
    let bytes = c.to_bytes();
    assert_eq!(hex(&bytes), GOLDEN_HEX);
    assert_eq!(hex(&hash_data(&bytes).0), GOLDEN_SHA256);
    assert_eq!(hex(c.device_id().as_bytes()), GOLDEN_DEVICE_ID);
    assert_eq!(bytes.len(), 218);
    // the hand layout of the tests below is the recorded one
    let subject = service_subject(SERVICE).unwrap();
    assert_eq!(
        hex(&hand_signed(&master(), &subject, ISSUED_AT, NOT_AFTER).to_bytes()),
        GOLDEN_HEX
    );
    // the checker is not vacuous: one other byte gives another digest
    let mut other = bytes;
    other[0] ^= 1;
    assert_ne!(hex(&hash_data(&other).0), GOLDEN_SHA256);
}

#[test]
fn the_recorded_bytes_verify_as_the_service_certificate() {
    let c = DeviceCert::from_bytes(&unhex(GOLDEN_HEX)).unwrap();
    assert_eq!(verify_at(&c, ISSUED_AT), Ok(NOISE));
}

// --- rejects ---

#[test]
fn another_master_is_an_issuer_mismatch() {
    let other = KeyPair::from_seed([0x5b; 32]);
    assert_eq!(
        verify_service_cert(
            &issued(),
            &other.public(),
            SERVICE,
            ISSUED_AT,
            Revocation::NoListAvailable
        ),
        Err(ServiceCertError::Cert(DeviceCertError::IssuerMismatch))
    );
}

#[test]
fn now_at_not_after_is_expired() {
    assert_eq!(
        verify_at(&issued(), NOT_AFTER),
        Err(ServiceCertError::Cert(DeviceCertError::Expired {
            now: NOT_AFTER,
            not_after: NOT_AFTER
        }))
    );
}

#[test]
fn issued_at_beyond_the_skew_is_not_yet_valid() {
    let now = ISSUED_AT - 601;
    assert_eq!(
        verify_at(&issued(), now),
        Err(ServiceCertError::Cert(DeviceCertError::NotYetValid {
            now,
            issued_at: ISSUED_AT
        }))
    );
}

#[test]
fn another_service_is_wrong_service() {
    let push =
        issue_service_cert(&master(), "push", signing(), NOISE, ISSUED_AT, NOT_AFTER).unwrap();
    assert_eq!(
        verify_at(&push, ISSUED_AT),
        Err(ServiceCertError::WrongService)
    );
    // and the other way round
    assert_eq!(
        verify_service_cert(
            &issued(),
            &master().public(),
            "push",
            ISSUED_AT,
            Revocation::NoListAvailable
        ),
        Err(ServiceCertError::WrongService)
    );
    // a prefix or extension of the name is another service
    for name in ["rela", "relay2", "relay-x"] {
        let c =
            issue_service_cert(&master(), name, signing(), NOISE, ISSUED_AT, NOT_AFTER).unwrap();
        assert_eq!(
            verify_at(&c, ISSUED_AT),
            Err(ServiceCertError::WrongService)
        );
    }
}

#[test]
fn a_user_did_certificate_is_not_a_service() {
    let subjects = [
        Did::parse("did:alice:relay").unwrap(),
        Did::parse("did:key:relay").unwrap(),
        // the service name as the id under another method
        Did::new("alice-services", SERVICE),
        Did::key_ed25519(&master().public()),
    ];
    let mut compared = 0;
    for subject in &subjects {
        let c =
            DeviceCert::issue(&master(), subject, signing(), NOISE, ISSUED_AT, NOT_AFTER).unwrap();
        assert_eq!(
            verify_at(&c, ISSUED_AT),
            Err(ServiceCertError::NotAService),
            "{subject}"
        );
        compared += 1;
    }
    assert_eq!(compared, subjects.len());
}

#[test]
fn a_lifetime_over_thirty_days_is_refused_at_issue() {
    assert_eq!(SERVICE_CERT_MAX_LIFETIME_SECS, 2_592_000);
    let over = ISSUED_AT + SERVICE_CERT_MAX_LIFETIME_SECS + 1;
    assert_eq!(
        issue_service_cert(&master(), SERVICE, signing(), NOISE, ISSUED_AT, over),
        Err(ServiceCertError::LifetimeTooLong(
            SERVICE_CERT_MAX_LIFETIME_SECS + 1
        ))
    );
    // exactly 30 days is accepted (`issued()` uses it)
    assert_eq!(NOT_AFTER - ISSUED_AT, SERVICE_CERT_MAX_LIFETIME_SECS);
    assert_eq!(verify_at(&issued(), ISSUED_AT), Ok(NOISE));
}

#[test]
fn a_lifetime_over_thirty_days_is_refused_at_verify() {
    let over = ISSUED_AT + SERVICE_CERT_MAX_LIFETIME_SECS + 1;
    let subject = service_subject(SERVICE).unwrap();
    // signed correctly by the master, by hand (no issuing function makes it)
    let c = hand_signed(&master(), &subject, ISSUED_AT, over);
    assert_eq!(
        verify_at(&c, ISSUED_AT),
        Err(ServiceCertError::LifetimeTooLong(
            SERVICE_CERT_MAX_LIFETIME_SECS + 1
        ))
    );
}

#[test]
fn not_after_not_after_issued_at_is_invalid_validity() {
    assert_eq!(
        issue_service_cert(&master(), SERVICE, signing(), NOISE, ISSUED_AT, ISSUED_AT),
        Err(ServiceCertError::Cert(DeviceCertError::InvalidValidity))
    );
}

/// Byte offsets in the encoding of `issued()`: subject at 3..26, signing key, noise static key at
/// 58..90, issued_at 90..98, not_after 98..106, device id, issuer, signature 154..218
#[test]
fn one_flipped_byte_in_a_signed_field_or_the_signature_is_refused() {
    let good = issued().to_bytes();
    let subject_at = 3 + "did:alice-service:".len(); // the 'r' of "relay": 'r' ^ 1 = 's'
    let cases: [(&str, usize, Result<(), DeviceCertError>); 5] = [
        ("noise_static", 58, Err(DeviceCertError::BadSignature)),
        // the device id is derived from the subject, so the decoder already refuses it
        (
            "subject",
            subject_at,
            Err(DeviceCertError::DeviceIdMismatch),
        ),
        ("issued_at", 97, Err(DeviceCertError::BadSignature)),
        ("not_after", 105, Err(DeviceCertError::BadSignature)),
        ("signature", 200, Err(DeviceCertError::BadSignature)),
    ];
    let mut compared = 0;
    for (field, at, want) in cases {
        let mut b = good.clone();
        b[at] ^= 1;
        let got = match DeviceCert::from_bytes(&b) {
            Err(e) => Err(ServiceCertError::Cert(e)),
            Ok(c) => verify_at(&c, ISSUED_AT).map(|_| ()),
        };
        assert_eq!(got, want.map_err(ServiceCertError::Cert), "{field}");
        compared += 1;
    }
    assert_eq!(compared, 5);
}

#[test]
fn a_revoked_device_id_is_revoked() {
    let c = issued();
    let m = master();
    let mut revs = CertRevocations::new();
    // a list that revokes another id does not touch this certificate
    revs.accept(
        RevocationList::issue(&m, 1, ISSUED_AT, &[DeviceId::from_raw([1; 16])]),
        &m.public(),
    )
    .unwrap();
    assert_eq!(
        verify_service_cert(
            &c,
            &m.public(),
            SERVICE,
            ISSUED_AT,
            Revocation::Checked(&revs)
        ),
        Ok(NOISE)
    );
    revs.accept(
        RevocationList::issue(
            &m,
            2,
            ISSUED_AT,
            &[DeviceId::from_raw([1; 16]), c.device_id()],
        ),
        &m.public(),
    )
    .unwrap();
    assert_eq!(
        verify_service_cert(
            &c,
            &m.public(),
            SERVICE,
            ISSUED_AT,
            Revocation::Checked(&revs)
        ),
        Err(ServiceCertError::Revoked)
    );
    // the revocation covers the renewal with the same keys
    let renewal =
        issue_service_cert(&m, SERVICE, signing(), NOISE, NOT_AFTER, NOT_AFTER + 86_400).unwrap();
    assert_eq!(
        verify_service_cert(
            &renewal,
            &m.public(),
            SERVICE,
            NOT_AFTER,
            Revocation::Checked(&revs)
        ),
        Err(ServiceCertError::Revoked)
    );
}

#[test]
fn the_checks_run_in_the_documented_order() {
    let m = master();
    // an expired certificate of a non-service subject: the certificate check comes first
    let user = DeviceCert::issue(
        &m,
        &Did::parse("did:alice:person-1").unwrap(),
        signing(),
        NOISE,
        ISSUED_AT,
        NOT_AFTER,
    )
    .unwrap();
    assert!(matches!(
        verify_at(&user, NOT_AFTER),
        Err(ServiceCertError::Cert(DeviceCertError::Expired { .. }))
    ));
    // another service with a lifetime over the bound: the subject check comes before the lifetime
    let subject = service_subject("push").unwrap();
    let long = hand_signed(
        &m,
        &subject,
        ISSUED_AT,
        ISSUED_AT + SERVICE_CERT_MAX_LIFETIME_SECS + 1,
    );
    assert_eq!(
        verify_at(&long, ISSUED_AT),
        Err(ServiceCertError::WrongService)
    );
    // a revoked certificate with a lifetime over the bound: the lifetime comes before revocation
    let own = service_subject(SERVICE).unwrap();
    let long_own = hand_signed(
        &m,
        &own,
        ISSUED_AT,
        ISSUED_AT + SERVICE_CERT_MAX_LIFETIME_SECS + 1,
    );
    let mut revs = CertRevocations::new();
    revs.accept(
        RevocationList::issue(&m, 1, ISSUED_AT, &[long_own.device_id()]),
        &m.public(),
    )
    .unwrap();
    assert!(matches!(
        verify_service_cert(
            &long_own,
            &m.public(),
            SERVICE,
            ISSUED_AT,
            Revocation::Checked(&revs)
        ),
        Err(ServiceCertError::LifetimeTooLong(_))
    ));
    // a bad name with an otherwise failing certificate: the name comes first
    assert_eq!(
        verify_service_cert(
            &user,
            &m.public(),
            "Relay",
            NOT_AFTER,
            Revocation::NoListAvailable
        ),
        Err(ServiceCertError::BadServiceName)
    );
}

#[test]
fn errors_display_and_chain_the_certificate_error() {
    use std::error::Error;
    let e = ServiceCertError::Cert(DeviceCertError::IssuerMismatch);
    assert!(e.source().is_some());
    assert!(e.to_string().contains("issuer"));
    assert!(ServiceCertError::WrongService.source().is_none());
    assert!(ServiceCertError::LifetimeTooLong(5)
        .to_string()
        .contains('5'));
}
