//! Oracle for the separation of service certificates from the device certificates of a person.
//!
//! A service certificate is a [`DeviceCert`] whose subject has the reserved method
//! [`SERVICE_DID_METHOD`] (`did:alice-service:<service>`). An operator may sign service certificates
//! with the same master key that signs the devices of a person, so the subject method is the only
//! thing that keeps the two apart:
//!
//! - only [`issue_service_cert`] issues a certificate with the reserved method ([`DeviceCert::issue`]
//!   refuses it as [`DeviceCertError::ReservedSubject`]);
//! - only [`verify_service_cert`] accepts one: [`DeviceCert::verify`] and every path that accepts a
//!   device of a person through it (artifact signatures, signed artifacts, contact cards) refuse it.
//!
//! The method is compared exactly: a method that only starts with, contains or differs in case from
//! the reserved one is an ordinary method, issued and accepted as a person's, and is never a service.

use alice_identity::artifact::{
    sha256_payload, sign_artifact, verify_artifact, ArtifactError, Revocation, SignedArtifact,
};
use alice_identity::cert_revocation::CertRevocations;
use alice_identity::contact_card::{
    ContactCard, ContactCardError, CONTACT_CARD_CONTEXT, CONTACT_CARD_VERSION,
};
use alice_identity::device_cert::{DeviceCert, DeviceCertError};
use alice_identity::did::Did;
use alice_identity::service_cert::{
    issue_service_cert, verify_service_cert, ServiceCertError, SERVICE_DID_METHOD,
};
use alice_sign::KeyPair;

const SERVICE: &str = "relay";
const ISSUED_AT: u64 = 1_800_000_000;
const NOT_AFTER: u64 = ISSUED_AT + 30 * 86_400;
const NOW: u64 = ISSUED_AT + 60;
const NOISE: [u8; 32] = [0x4e; 32];
const CONTEXT: &[u8] = b"alice-test/artifact/v1";

/// A test fixture, never a production key: one master that signs both a person's devices and a
/// service (the reuse the separation must survive)
fn master() -> KeyPair {
    KeyPair::from_seed([0x5a; 32])
}

/// A test fixture: the service's signing key
fn service_key() -> KeyPair {
    KeyPair::from_seed([0x11; 32])
}

/// A test fixture: a device key of the person
fn device_key() -> KeyPair {
    KeyPair::from_seed([0x22; 32])
}

fn service_cert() -> DeviceCert {
    issue_service_cert(
        &master(),
        SERVICE,
        service_key().public().0,
        NOISE,
        ISSUED_AT,
        NOT_AFTER,
    )
    .unwrap()
}

fn person_cert() -> DeviceCert {
    let m = master();
    DeviceCert::issue(
        &m,
        &Did::key_ed25519(&m.public()),
        device_key().public().0,
        NOISE,
        ISSUED_AT,
        NOT_AFTER,
    )
    .unwrap()
}

fn reserved<T: std::fmt::Debug>(r: Result<T, DeviceCertError>) -> bool {
    matches!(r, Err(DeviceCertError::ReservedSubject))
}

// --- issuance ---

#[test]
fn device_cert_issue_refuses_the_reserved_method_whatever_the_id() {
    // a valid service name, and ids no service name takes: none can be minted as a person's
    let ids = ["relay", "x", "Relay", "-relay", "a:b", "push-1"];
    let mut compared = 0;
    for id in ids {
        let subject = Did::new(SERVICE_DID_METHOD, id);
        let r = DeviceCert::issue(
            &master(),
            &subject,
            service_key().public().0,
            NOISE,
            ISSUED_AT,
            NOT_AFTER,
        );
        assert!(reserved(r), "{subject}");
        compared += 1;
    }
    assert_eq!(compared, ids.len());
}

#[test]
fn issue_service_cert_still_issues_and_verify_service_cert_still_accepts() {
    let c = service_cert();
    assert_eq!(c.subject().method, SERVICE_DID_METHOD);
    assert_eq!(
        verify_service_cert(
            &c,
            &master().public(),
            SERVICE,
            NOW,
            Revocation::NoListAvailable
        ),
        Ok(NOISE)
    );
}

// --- acceptance as a device of a person ---

#[test]
fn device_cert_verify_refuses_a_service_certificate() {
    let c = service_cert();
    assert!(reserved(c.verify(&master().public(), NOW)));
    // decoded from bytes, as a receiver holds it
    let decoded = DeviceCert::from_bytes(&c.to_bytes()).unwrap();
    assert!(reserved(decoded.verify(&master().public(), NOW)));
}

#[test]
fn the_reserved_subject_is_checked_after_the_signature() {
    // another master: the issuer check answers first, so an unsigned claim of the subject is not read
    let other = KeyPair::from_seed([0x77; 32]);
    assert_eq!(
        service_cert().verify(&other.public(), NOW),
        Err(DeviceCertError::IssuerMismatch)
    );
    // an expired service certificate: the subject is refused before the window is read
    assert!(reserved(
        service_cert().verify(&master().public(), NOT_AFTER)
    ));
}

#[test]
fn an_artifact_signed_with_a_service_certificate_is_refused() {
    let digest = sha256_payload(b"payload");
    let sig = sign_artifact(&service_key(), &service_cert(), CONTEXT, &digest).unwrap();
    let empty = CertRevocations::new();
    let lists = [Revocation::NoListAvailable, Revocation::Checked(&empty)];
    let mut compared = 0;
    for revocation in lists {
        assert_eq!(
            verify_artifact(&sig, &master().public(), CONTEXT, &digest, NOW, revocation),
            Err(ArtifactError::Cert(DeviceCertError::ReservedSubject))
        );
        compared += 1;
    }
    assert_eq!(compared, 2);
}

#[test]
fn a_signed_artifact_under_a_service_certificate_is_refused_at_open() {
    let unit =
        SignedArtifact::sign(&service_key(), &service_cert(), CONTEXT, b"law", b"payload").unwrap();
    assert_eq!(
        SignedArtifact::open(
            &unit.to_bytes(),
            &master().public(),
            CONTEXT,
            NOW,
            Revocation::NoListAvailable
        ),
        Err(ArtifactError::Cert(DeviceCertError::ReservedSubject))
    );
}

#[test]
fn a_contact_card_with_a_service_certificate_is_not_issued() {
    let mut compared = 0;
    for (certs, at) in [
        (vec![service_cert()], 0),
        (vec![person_cert(), service_cert()], 1),
    ] {
        assert_eq!(
            ContactCard::issue(&master(), &certs, None, ISSUED_AT),
            Err(ContactCardError::CertIssuerMismatch(at))
        );
        compared += 1;
    }
    assert_eq!(compared, 2);
}

/// A card body laid out by hand (the documented layout), signed by `m`, carrying `certs`
fn hand_card(m: &KeyPair, certs: &[DeviceCert]) -> Vec<u8> {
    let subject = Did::key_ed25519(&m.public()).to_string();
    let mut body = vec![CONTACT_CARD_VERSION];
    body.extend_from_slice(&u16::try_from(subject.len()).unwrap().to_be_bytes());
    body.extend_from_slice(subject.as_bytes());
    body.extend_from_slice(&m.public().0);
    body.extend_from_slice(&ISSUED_AT.to_be_bytes());
    body.push(u8::try_from(certs.len()).unwrap());
    for c in certs {
        let b = c.to_bytes();
        body.extend_from_slice(&u16::try_from(b.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&b);
    }
    body.extend_from_slice(&0u32.to_be_bytes());
    let mut signed = CONTACT_CARD_CONTEXT.to_vec();
    signed.extend_from_slice(&body);
    body.extend_from_slice(&m.sign(&signed).0);
    body
}

#[test]
fn a_contact_card_signed_by_the_master_with_a_service_certificate_is_refused() {
    let m = master();
    // the hand layout is the card's own: a card of the person's certificate decodes and verifies
    let good = ContactCard::from_bytes(&hand_card(&m, &[person_cert()])).unwrap();
    assert_eq!(good.verify(NOW), Ok(()));
    let mut compared = 0;
    for (certs, at) in [
        (vec![service_cert()], 0),
        (vec![person_cert(), service_cert()], 1),
    ] {
        assert_eq!(
            ContactCard::from_bytes(&hand_card(&m, &certs)),
            Err(ContactCardError::CertIssuerMismatch(at))
        );
        compared += 1;
    }
    assert_eq!(compared, 2);
}

// --- the method is compared exactly ---

#[test]
fn methods_near_the_reserved_one_are_person_methods_and_never_services() {
    let methods = [
        "alice-services",
        "alice-service-x",
        "xalice-service",
        "alice-servic",
        "ALICE-SERVICE",
        "Alice-Service",
    ];
    let mut compared = 0;
    for method in methods {
        assert_ne!(method, SERVICE_DID_METHOD);
        let subject = Did::new(method, SERVICE);
        let c = DeviceCert::issue(
            &master(),
            &subject,
            service_key().public().0,
            NOISE,
            ISSUED_AT,
            NOT_AFTER,
        )
        .unwrap_or_else(|e| panic!("{subject}: {e}"));
        assert_eq!(c.verify(&master().public(), NOW), Ok(()), "{subject}");
        assert_eq!(
            verify_service_cert(
                &c,
                &master().public(),
                SERVICE,
                NOW,
                Revocation::NoListAvailable
            ),
            Err(ServiceCertError::NotAService),
            "{subject}"
        );
        compared += 1;
    }
    assert_eq!(compared, methods.len());
}

// --- a person's certificates are unaffected ---

#[test]
fn a_person_certificate_under_the_same_master_is_accepted_as_before() {
    let c = person_cert();
    assert_eq!(c.verify(&master().public(), NOW), Ok(()));
    let digest = sha256_payload(b"payload");
    let sig = sign_artifact(&device_key(), &c, CONTEXT, &digest).unwrap();
    assert_eq!(
        verify_artifact(
            &sig,
            &master().public(),
            CONTEXT,
            &digest,
            NOW,
            Revocation::NoListAvailable
        ),
        Ok(())
    );
    let card = ContactCard::issue(&master(), &[c], None, ISSUED_AT).unwrap();
    assert_eq!(card.verify(NOW), Ok(()));
}

#[test]
fn reserved_subject_has_its_own_message() {
    let text = DeviceCertError::ReservedSubject.to_string();
    assert!(text.contains(SERVICE_DID_METHOD), "{text}");
}
