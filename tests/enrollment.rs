//! Oracle for device enrollment: `EnrollmentTicket`, `EnrollmentRequest` and `EnrollmentDesk`.
//!
//! The expected bytes, text, short code and grant come from `scripts/gen_enrollment_vectors.py`, an
//! independent implementation written from the layout in the module documentation (Python's hashlib and
//! base64, pynacl for Ed25519), stored in `tests/data/enrollment_*`. Tickets and requests that break one
//! rule are assembled here from the same layout and signed with alice-sign.

use alice_identity::device_cert::{DeviceCert, DeviceCertError, MAX_CLOCK_SKEW_SECS};
use alice_identity::did::Did;
use alice_identity::enrollment::{
    EnrollmentDesk, EnrollmentError, EnrollmentRequest, EnrollmentTicket,
    ENROLLMENT_REQUEST_CONTEXT, ENROLLMENT_TICKET_MAX_LIFETIME_SECS,
};
use alice_identity::invite::Invite;
use alice_sign::KeyPair;

const TICKET_HEX: &str = include_str!("data/enrollment_ticket.hex");
const TICKET_TEXT: &str = include_str!("data/enrollment_ticket.txt");
const REQUEST_HEX: &str = include_str!("data/enrollment_request.hex");
const REQUEST_TEXT: &str = include_str!("data/enrollment_request.txt");
const GRANT_HEX: &str = include_str!("data/enrollment_grant.hex");
/// `short_code` of tests/data/enrollment_vectors.json
const SHORT_CODE: &str = "TWX01-FQXJ8";

const SUBJECT: &str = "did:alice:enroll-oracle";
const TICKET_ID: [u8; 16] = [
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
];
const NOISE: [u8; 32] = [0x44; 32];
const ISSUED_AT: u64 = 1_800_000_000;
const NOT_AFTER: u64 = 1_800_000_600;
const REQUESTED_AT: u64 = 1_800_000_060;
const GRANT_AT: u64 = 1_800_000_120;
const GRANT_NOT_AFTER: u64 = GRANT_AT + 86_400 * 365;

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn master() -> KeyPair {
    KeyPair::from_seed([7; 32])
}

fn device() -> KeyPair {
    KeyPair::from_seed([9; 32])
}

fn subject() -> Did {
    Did::parse(SUBJECT).unwrap()
}

fn ticket() -> EnrollmentTicket {
    EnrollmentTicket::issue(&master(), &subject(), TICKET_ID, ISSUED_AT, NOT_AFTER).unwrap()
}

fn request() -> EnrollmentRequest {
    EnrollmentRequest::new(&device(), &ticket(), NOISE, REQUESTED_AT)
}

fn desk() -> EnrollmentDesk {
    EnrollmentDesk::new(master().public())
}

/// A request body laid out as the module documentation states it, signed by `signer`
fn signed_request(signer: &KeyPair, subject: &str, device_public: &[u8; 32]) -> Vec<u8> {
    let s = subject.as_bytes();
    let mut body = vec![1];
    body.extend_from_slice(&u16::try_from(s.len()).unwrap().to_be_bytes());
    body.extend_from_slice(s);
    body.extend_from_slice(&master().public().0);
    body.extend_from_slice(&TICKET_ID);
    body.extend_from_slice(device_public);
    body.extend_from_slice(&NOISE);
    body.extend_from_slice(&REQUESTED_AT.to_be_bytes());
    let mut signed = ENROLLMENT_REQUEST_CONTEXT.to_vec();
    signed.extend_from_slice(&body);
    body.extend_from_slice(&signer.sign(&signed).0);
    body
}

#[test]
fn the_ticket_is_the_reference_ticket() {
    let t = ticket();
    assert_eq!(t.to_bytes(), unhex(TICKET_HEX));
    assert_eq!(t.to_text(), TICKET_TEXT.trim());
    assert_eq!(EnrollmentTicket::from_bytes(&unhex(TICKET_HEX)).unwrap(), t);
    assert_eq!(EnrollmentTicket::from_text(TICKET_TEXT.trim()).unwrap(), t);
    assert_eq!(t.subject(), &subject());
    assert_eq!(t.master_public(), &master().public().0);
    assert_eq!(t.ticket_id(), &TICKET_ID);
}

#[test]
fn the_request_is_the_reference_request_with_its_short_code() {
    let r = request();
    assert_eq!(r.to_bytes(), unhex(REQUEST_HEX));
    assert_eq!(r.to_text(), REQUEST_TEXT.trim());
    assert_eq!(r.short_code(), SHORT_CODE);
    let back = EnrollmentRequest::from_bytes(&unhex(REQUEST_HEX)).unwrap();
    assert_eq!(back, r);
    assert_eq!(back.short_code(), SHORT_CODE);
    assert_eq!(
        EnrollmentRequest::from_text(REQUEST_TEXT.trim()).unwrap(),
        r
    );
    assert_eq!(r.device_public(), &device().public().0);
    assert_eq!(r.noise_static(), &NOISE);
}

#[test]
fn the_desk_grants_the_reference_certificate_and_the_device_accepts_it() {
    let mut d = desk();
    let cert = d
        .approve(&master(), &ticket(), &request(), GRANT_AT, GRANT_NOT_AFTER)
        .unwrap();
    assert_eq!(cert.to_bytes(), unhex(GRANT_HEX));
    assert_eq!(d.len(), 1);
    request().accept_grant(&cert, GRANT_AT).unwrap();
    // the grant is an ordinary device certificate of the master
    cert.verify(&master().public(), GRANT_AT).unwrap();
}

#[test]
fn a_ticket_is_used_once() {
    let mut d = desk();
    d.approve(&master(), &ticket(), &request(), GRANT_AT, GRANT_NOT_AFTER)
        .unwrap();
    let other = EnrollmentRequest::new(
        &KeyPair::from_seed([10; 32]),
        &ticket(),
        NOISE,
        REQUESTED_AT,
    );
    assert_eq!(
        d.approve(&master(), &ticket(), &other, GRANT_AT, GRANT_NOT_AFTER),
        Err(EnrollmentError::AlreadyUsed)
    );
    assert_eq!(
        d.approve(&master(), &ticket(), &request(), GRANT_AT, GRANT_NOT_AFTER),
        Err(EnrollmentError::AlreadyUsed)
    );
    assert_eq!(d.len(), 1);
}

#[test]
fn a_request_not_signed_by_its_device_key_is_refused() {
    // the device key of `device()`, signed by another key: no proof of possession
    let forged = signed_request(&KeyPair::from_seed([10; 32]), SUBJECT, &device().public().0);
    assert_eq!(
        EnrollmentRequest::from_bytes(&forged),
        Err(EnrollmentError::BadSignature)
    );
    // the layout itself is the reference one: signed by the device it reads back
    let honest = signed_request(&device(), SUBJECT, &device().public().0);
    assert_eq!(honest, unhex(REQUEST_HEX));
    let mut flipped = unhex(REQUEST_HEX);
    let at = flipped.len() - 70;
    flipped[at] ^= 1;
    assert_eq!(
        EnrollmentRequest::from_bytes(&flipped),
        Err(EnrollmentError::BadSignature)
    );
}

#[test]
fn a_contact_invite_is_not_an_enrollment_ticket() {
    // an invite has the same field order (version, issuer, key, 16-byte id, window, signature) but is signed
    // under the invite context: it must not read as a ticket
    let invite = Invite::issue(&master(), TICKET_ID, ISSUED_AT, NOT_AFTER).unwrap();
    assert_eq!(
        EnrollmentTicket::from_bytes(&invite.to_bytes()),
        Err(EnrollmentError::BadSignature)
    );
    assert_eq!(
        EnrollmentTicket::from_text(&invite.to_text()),
        Err(EnrollmentError::BadText)
    );
}

#[test]
fn the_ticket_window_is_enforced_at_approval() {
    let mut d = desk();
    assert_eq!(
        d.approve(&master(), &ticket(), &request(), NOT_AFTER, GRANT_NOT_AFTER),
        Err(EnrollmentError::Expired {
            now: NOT_AFTER,
            not_after: NOT_AFTER
        })
    );
    let early = ISSUED_AT - MAX_CLOCK_SKEW_SECS - 1;
    assert_eq!(
        d.approve(&master(), &ticket(), &request(), early, GRANT_NOT_AFTER),
        Err(EnrollmentError::NotYetValid {
            now: early,
            issued_at: ISSUED_AT
        })
    );
    // refused approvals record nothing: the ticket still works in its window
    assert!(d.is_empty());
    d.approve(
        &master(),
        &ticket(),
        &request(),
        NOT_AFTER - 1,
        GRANT_NOT_AFTER,
    )
    .unwrap();
}

#[test]
fn a_request_made_outside_the_ticket_window_is_refused() {
    let mut d = desk();
    let late = EnrollmentRequest::new(&device(), &ticket(), NOISE, NOT_AFTER);
    assert_eq!(
        d.approve(&master(), &ticket(), &late, GRANT_AT, GRANT_NOT_AFTER),
        Err(EnrollmentError::RequestOutsideTicket)
    );
    assert!(d.is_empty());
}

#[test]
fn a_request_for_another_ticket_or_subject_is_refused() {
    let mut d = desk();
    let mut other_id = TICKET_ID;
    other_id[0] ^= 1;
    let other_ticket =
        EnrollmentTicket::issue(&master(), &subject(), other_id, ISSUED_AT, NOT_AFTER).unwrap();
    let for_other = EnrollmentRequest::new(&device(), &other_ticket, NOISE, REQUESTED_AT);
    assert_eq!(
        d.approve(&master(), &ticket(), &for_other, GRANT_AT, GRANT_NOT_AFTER),
        Err(EnrollmentError::WrongTicket)
    );
    // same id, another subject: the request names the subject it asks to join
    let jane = Did::parse("did:alice:jane").unwrap();
    let jane_ticket =
        EnrollmentTicket::issue(&master(), &jane, TICKET_ID, ISSUED_AT, NOT_AFTER).unwrap();
    let for_jane = EnrollmentRequest::new(&device(), &jane_ticket, NOISE, REQUESTED_AT);
    assert_eq!(
        d.approve(&master(), &ticket(), &for_jane, GRANT_AT, GRANT_NOT_AFTER),
        Err(EnrollmentError::SubjectMismatch)
    );
    assert!(d.is_empty());
}

#[test]
fn another_master_cannot_approve_at_this_desk() {
    let mut d = desk();
    let stranger = KeyPair::from_seed([11; 32]);
    assert_eq!(
        d.approve(&stranger, &ticket(), &request(), GRANT_AT, GRANT_NOT_AFTER),
        Err(EnrollmentError::WrongMaster)
    );
    let strangers_ticket =
        EnrollmentTicket::issue(&stranger, &subject(), TICKET_ID, ISSUED_AT, NOT_AFTER).unwrap();
    let r = EnrollmentRequest::new(&device(), &strangers_ticket, NOISE, REQUESTED_AT);
    assert_eq!(
        d.approve(&master(), &strangers_ticket, &r, GRANT_AT, GRANT_NOT_AFTER),
        Err(EnrollmentError::WrongMaster)
    );
    assert!(d.is_empty());
}

#[test]
fn the_device_refuses_a_grant_that_is_not_for_its_request() {
    let r = request();
    // another device's certificate from the right master
    let other = KeyPair::from_seed([10; 32]);
    let wrong_device = DeviceCert::issue(
        &master(),
        &subject(),
        other.public().0,
        NOISE,
        GRANT_AT,
        GRANT_NOT_AFTER,
    )
    .unwrap();
    assert_eq!(
        r.accept_grant(&wrong_device, GRANT_AT),
        Err(EnrollmentError::GrantMismatch("device key"))
    );
    let wrong_noise = DeviceCert::issue(
        &master(),
        &subject(),
        device().public().0,
        [0x45; 32],
        GRANT_AT,
        GRANT_NOT_AFTER,
    )
    .unwrap();
    assert_eq!(
        r.accept_grant(&wrong_noise, GRANT_AT),
        Err(EnrollmentError::GrantMismatch("noise key"))
    );
    let jane = Did::parse("did:alice:jane").unwrap();
    let wrong_subject = DeviceCert::issue(
        &master(),
        &jane,
        device().public().0,
        NOISE,
        GRANT_AT,
        GRANT_NOT_AFTER,
    )
    .unwrap();
    assert_eq!(
        r.accept_grant(&wrong_subject, GRANT_AT),
        Err(EnrollmentError::GrantMismatch("subject"))
    );
    // the right device, issued by another key
    let stranger = KeyPair::from_seed([11; 32]);
    let wrong_master = DeviceCert::issue(
        &stranger,
        &subject(),
        device().public().0,
        NOISE,
        GRANT_AT,
        GRANT_NOT_AFTER,
    )
    .unwrap();
    assert_eq!(
        r.accept_grant(&wrong_master, GRANT_AT),
        Err(EnrollmentError::Cert(DeviceCertError::IssuerMismatch))
    );
}

#[test]
fn ticket_issue_refuses_bad_windows_and_service_subjects() {
    assert_eq!(
        EnrollmentTicket::issue(&master(), &subject(), TICKET_ID, ISSUED_AT, ISSUED_AT),
        Err(EnrollmentError::InvalidValidity)
    );
    assert_eq!(
        EnrollmentTicket::issue(
            &master(),
            &subject(),
            TICKET_ID,
            ISSUED_AT,
            ISSUED_AT + ENROLLMENT_TICKET_MAX_LIFETIME_SECS + 1
        ),
        Err(EnrollmentError::LifetimeTooLong)
    );
    EnrollmentTicket::issue(
        &master(),
        &subject(),
        TICKET_ID,
        ISSUED_AT,
        ISSUED_AT + ENROLLMENT_TICKET_MAX_LIFETIME_SECS,
    )
    .unwrap();
    let service = Did::parse("did:alice-service:relay").unwrap();
    assert_eq!(
        EnrollmentTicket::issue(&master(), &service, TICKET_ID, ISSUED_AT, NOT_AFTER),
        Err(EnrollmentError::ReservedSubject)
    );
}

#[test]
fn cancelled_tickets_stay_refused_and_prune_drops_only_expired_uses() {
    let mut d = desk();
    d.cancel(TICKET_ID);
    assert_eq!(
        d.approve(&master(), &ticket(), &request(), GRANT_AT, GRANT_NOT_AFTER),
        Err(EnrollmentError::Cancelled)
    );
    let mut d = desk();
    d.approve(&master(), &ticket(), &request(), GRANT_AT, GRANT_NOT_AFTER)
        .unwrap();
    d.prune(NOT_AFTER - 1);
    assert_eq!(d.len(), 1);
    d.prune(NOT_AFTER);
    assert!(d.is_empty());
    let mut d = desk();
    d.cancel(TICKET_ID);
    d.prune(u64::MAX);
    assert_eq!(d.len(), 1);
}

#[test]
fn degenerate_bytes_and_text_are_refused_without_panic() {
    let ticket = unhex(TICKET_HEX);
    let request = unhex(REQUEST_HEX);
    assert_eq!(
        EnrollmentTicket::from_bytes(&[]),
        Err(EnrollmentError::Malformed("version"))
    );
    assert_eq!(
        EnrollmentRequest::from_bytes(&[]),
        Err(EnrollmentError::Malformed("version"))
    );
    assert_eq!(
        EnrollmentTicket::from_bytes(&[2]),
        Err(EnrollmentError::UnsupportedVersion(2))
    );
    for cut in 1..ticket.len() {
        assert!(
            EnrollmentTicket::from_bytes(&ticket[..cut]).is_err(),
            "cut {cut}"
        );
    }
    for cut in 1..request.len() {
        assert!(
            EnrollmentRequest::from_bytes(&request[..cut]).is_err(),
            "cut {cut}"
        );
    }
    let mut long = ticket.clone();
    long.push(0);
    assert!(matches!(
        EnrollmentTicket::from_bytes(&long),
        Err(EnrollmentError::Malformed(_))
    ));
    let mut long = request;
    long.push(0);
    assert!(matches!(
        EnrollmentRequest::from_bytes(&long),
        Err(EnrollmentError::Malformed(_))
    ));
    for bad in [
        "",
        "ALICE-ENROLL:1:",
        "ALICE-ENROLL:1:aaaa",
        "ALICE-ENROLL-REQ:1:AE",
    ] {
        assert!(EnrollmentTicket::from_text(bad).is_err(), "{bad}");
    }
    assert_eq!(
        EnrollmentRequest::from_text("ALICE-ENROLL-REQ:1:"),
        Err(EnrollmentError::BadText)
    );
    // a ticket's text is not a request's and the other way round
    assert_eq!(
        EnrollmentRequest::from_text(TICKET_TEXT.trim()),
        Err(EnrollmentError::BadText)
    );
    assert_eq!(
        EnrollmentTicket::from_text(REQUEST_TEXT.trim()),
        Err(EnrollmentError::BadText)
    );
}
