//! Oracle for `verify_service_artifact`: an artifact signature made by a service's signing key under a
//! service certificate, accepted only for the service the verifier names.
//!
//! The certificate is held to every rule of `verify_service_cert` (name, reserved method, the exact
//! service, the 30-day bound, revocation) and the signature to every rule of `verify_artifact`
//! (context, digest, strict signature under the certificate's key). A device certificate of a person
//! is never accepted here, as a service certificate is never accepted by `verify_artifact`.

use alice_identity::artifact::{
    sha256_payload, sign_artifact, verify_artifact, verify_service_artifact, ArtifactError,
    ArtifactSignature, Revocation,
};
use alice_identity::cert_revocation::{CertRevocations, RevocationList};
use alice_identity::device_cert::{DeviceCert, DeviceCertError, DeviceId, DEVICE_CERT_CONTEXT};
use alice_identity::did::Did;
use alice_identity::service_cert::{
    issue_service_cert, service_subject, ServiceCertError, SERVICE_CERT_MAX_LIFETIME_SECS,
};
use alice_sign::KeyPair;

const SERVICE: &str = "relay";
const ISSUED_AT: u64 = 1_800_000_000;
const NOT_AFTER: u64 = ISSUED_AT + SERVICE_CERT_MAX_LIFETIME_SECS;
const NOW: u64 = ISSUED_AT + 60;
const NOISE: [u8; 32] = [0x4e; 32];
const CONTEXT: &[u8] = b"alice-test/handshake/v1";

/// A test fixture, never a production key: the operator's master key
fn master() -> KeyPair {
    KeyPair::from_seed([0x5a; 32])
}

/// A test fixture: the service's signing key
fn service_key() -> KeyPair {
    KeyPair::from_seed([0x11; 32])
}

fn service_cert_of(service: &str) -> DeviceCert {
    issue_service_cert(
        &master(),
        service,
        service_key().public().0,
        NOISE,
        ISSUED_AT,
        NOT_AFTER,
    )
    .unwrap()
}

/// A certificate for `subject` with `service_key()` laid out by hand (the documented version 3
/// layout) and signed by `m`: the way to make a correctly signed certificate no issuing function makes
fn hand_signed(m: &KeyPair, subject: &Did, issued_at: u64, not_after: u64) -> DeviceCert {
    let key = service_key().public().0;
    let text = subject.to_string();
    let mut body = vec![3u8];
    body.extend_from_slice(&u16::try_from(text.len()).unwrap().to_be_bytes());
    body.extend_from_slice(text.as_bytes());
    body.extend_from_slice(&key);
    body.extend_from_slice(&NOISE);
    body.extend_from_slice(&issued_at.to_be_bytes());
    body.extend_from_slice(&not_after.to_be_bytes());
    body.extend_from_slice(DeviceId::derive(subject, &key).unwrap().as_bytes());
    body.extend_from_slice(&m.public().0);
    let mut signed = DEVICE_CERT_CONTEXT.to_vec();
    signed.extend_from_slice(&body);
    body.extend_from_slice(&m.sign(&signed).0);
    DeviceCert::from_bytes(&body).unwrap()
}

fn signed_by(cert: &DeviceCert) -> ArtifactSignature {
    sign_artifact(&service_key(), cert, CONTEXT, &sha256_payload(b"payload")).unwrap()
}

fn check(sig: &ArtifactSignature, service: &str, now: u64) -> Result<(), ArtifactError> {
    verify_service_artifact(
        sig,
        &master().public(),
        service,
        CONTEXT,
        &sha256_payload(b"payload"),
        now,
        Revocation::NoListAvailable,
    )
}

#[test]
fn a_service_signature_under_its_service_certificate_is_accepted() {
    let sig = signed_by(&service_cert_of(SERVICE));
    assert_eq!(check(&sig, SERVICE, NOW), Ok(()));
    // decoded from its bytes, as a receiver holds it
    let back = ArtifactSignature::from_bytes(&sig.to_bytes()).unwrap();
    assert_eq!(check(&back, SERVICE, NOW), Ok(()));
    // and verify_artifact, the path for a person's devices, refuses the same signature
    assert_eq!(
        verify_artifact(
            &sig,
            &master().public(),
            CONTEXT,
            &sha256_payload(b"payload"),
            NOW,
            Revocation::NoListAvailable
        ),
        Err(ArtifactError::Cert(DeviceCertError::ReservedSubject))
    );
}

#[test]
fn a_person_certificate_is_not_a_service() {
    let m = master();
    let subjects = [
        Did::key_ed25519(&m.public()),
        Did::parse("did:alice:relay").unwrap(),
        Did::new("alice-services", SERVICE),
    ];
    let mut compared = 0;
    for subject in &subjects {
        let cert = DeviceCert::issue(
            &m,
            subject,
            service_key().public().0,
            NOISE,
            ISSUED_AT,
            NOT_AFTER,
        )
        .unwrap();
        assert_eq!(
            check(&signed_by(&cert), SERVICE, NOW),
            Err(ArtifactError::Service(ServiceCertError::NotAService)),
            "{subject}"
        );
        compared += 1;
    }
    assert_eq!(compared, subjects.len());
}

#[test]
fn another_service_is_wrong_service_and_a_bad_name_is_refused() {
    let sig = signed_by(&service_cert_of("push"));
    assert_eq!(
        check(&sig, SERVICE, NOW),
        Err(ArtifactError::Service(ServiceCertError::WrongService))
    );
    assert_eq!(
        check(&sig, "Push", NOW),
        Err(ArtifactError::Service(ServiceCertError::BadServiceName))
    );
}

#[test]
fn a_lifetime_over_thirty_days_is_refused() {
    let subject = service_subject(SERVICE).unwrap();
    let long = hand_signed(&master(), &subject, ISSUED_AT, NOT_AFTER + 1);
    assert_eq!(
        check(&signed_by(&long), SERVICE, NOW),
        Err(ArtifactError::Service(ServiceCertError::LifetimeTooLong(
            SERVICE_CERT_MAX_LIFETIME_SECS + 1
        )))
    );
}

#[test]
fn the_certificate_window_and_issuer_are_checked() {
    let sig = signed_by(&service_cert_of(SERVICE));
    assert!(matches!(
        check(&sig, SERVICE, NOT_AFTER),
        Err(ArtifactError::Cert(DeviceCertError::Expired { .. }))
    ));
    let other = KeyPair::from_seed([0x77; 32]);
    assert_eq!(
        verify_service_artifact(
            &sig,
            &other.public(),
            SERVICE,
            CONTEXT,
            &sha256_payload(b"payload"),
            NOW,
            Revocation::NoListAvailable
        ),
        Err(ArtifactError::Cert(DeviceCertError::IssuerMismatch))
    );
}

#[test]
fn a_revoked_service_certificate_is_revoked() {
    let m = master();
    let cert = service_cert_of(SERVICE);
    let mut revs = CertRevocations::new();
    revs.accept(
        RevocationList::issue(&m, 1, ISSUED_AT, &[cert.device_id()]),
        &m.public(),
    )
    .unwrap();
    let r = verify_service_artifact(
        &signed_by(&cert),
        &m.public(),
        SERVICE,
        CONTEXT,
        &sha256_payload(b"payload"),
        NOW,
        Revocation::Checked(&revs),
    );
    assert_eq!(r, Err(ArtifactError::Revoked));
    // an empty list does not revoke it
    let empty = CertRevocations::new();
    assert_eq!(
        verify_service_artifact(
            &signed_by(&cert),
            &m.public(),
            SERVICE,
            CONTEXT,
            &sha256_payload(b"payload"),
            NOW,
            Revocation::Checked(&empty),
        ),
        Ok(())
    );
}

#[test]
fn a_changed_signature_is_refused() {
    let bytes = signed_by(&service_cert_of(SERVICE)).to_bytes();
    let mut compared = 0;
    // each byte of the 64-byte signature at the end
    for at in bytes.len() - 64..bytes.len() {
        let mut changed = bytes.clone();
        changed[at] ^= 1;
        let sig = ArtifactSignature::from_bytes(&changed).unwrap();
        assert_eq!(
            check(&sig, SERVICE, NOW),
            Err(ArtifactError::BadSignature),
            "{at}"
        );
        compared += 1;
    }
    assert_eq!(compared, 64);
}

#[test]
fn context_and_digest_are_checked_first() {
    let sig = signed_by(&service_cert_of(SERVICE));
    let verify = |context: &[u8], payload: &[u8], service: &str| {
        verify_service_artifact(
            &sig,
            &master().public(),
            service,
            context,
            &sha256_payload(payload),
            NOW,
            Revocation::NoListAvailable,
        )
    };
    assert_eq!(
        verify(b"", b"payload", SERVICE),
        Err(ArtifactError::InvalidContext)
    );
    assert_eq!(
        verify(b"alice-test/other/v1", b"payload", SERVICE),
        Err(ArtifactError::ContextMismatch)
    );
    // the digest before the certificate (another service is not read yet)
    assert_eq!(
        verify(CONTEXT, b"other", "push"),
        Err(ArtifactError::DigestMismatch)
    );
}

#[test]
fn the_certificate_is_checked_before_the_signature() {
    // a person certificate with a changed signature: the certificate refusal answers
    let m = master();
    let person = DeviceCert::issue(
        &m,
        &Did::key_ed25519(&m.public()),
        service_key().public().0,
        NOISE,
        ISSUED_AT,
        NOT_AFTER,
    )
    .unwrap();
    let mut bytes = signed_by(&person).to_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let sig = ArtifactSignature::from_bytes(&bytes).unwrap();
    assert_eq!(
        check(&sig, SERVICE, NOW),
        Err(ArtifactError::Service(ServiceCertError::NotAService))
    );
}

#[test]
fn the_service_error_displays_and_chains() {
    use std::error::Error;
    let e = ArtifactError::Service(ServiceCertError::WrongService);
    assert!(e.to_string().contains("another service"), "{e}");
    assert!(e.source().is_some());
    assert!(ArtifactError::BadSignature.source().is_none());
}
