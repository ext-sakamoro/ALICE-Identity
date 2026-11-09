//! Oracle for `ContactCard`.
//!
//! The expected bytes, text and short code come from `scripts/gen_contact_vectors.py`, an independent
//! implementation written byte by byte from the layout in the module documentation (Python's hashlib and
//! base64, pynacl for Ed25519), stored in `tests/data/`. Cards that break one rule are assembled here from
//! the same layout and signed with alice-sign, so no expected value comes from the code under test.

use alice_identity::cert_revocation::RevocationList;
use alice_identity::contact_card::{
    ContactCard, ContactCardError, CONTACT_CARD_CONTEXT, CONTACT_CARD_TEXT_PREFIX, MAX_CARD_CERTS,
};
use alice_identity::device_cert::{DeviceCert, DeviceCertError, DEVICE_CERT_CONTEXT};
use alice_identity::did::Did;
use alice_sign::KeyPair;

const CARD_HEX: &str = include_str!("data/contact_card.hex");
const CERTS_HEX: &str = include_str!("data/contact_card_certs.hex");
const CARD_TEXT: &str = include_str!("data/contact_card.txt");
const SHORT_CODE: &str = "0F0R-GAYY";
const SUBJECT: &str = "did:key:z6MkvDqGT54cXesYGvABpF1UapVNwjCqRcafi4Px6Thv5T3Z";
const ISSUED_AT: u64 = 1_800_000_100;
const CERT_ISSUED_AT: u64 = 1_800_000_000;
const CERT_NOT_AFTER: u64 = 1_800_086_400;
const NOW: u64 = 1_800_000_200;

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn master() -> KeyPair {
    KeyPair::from_seed([7; 32])
}

fn subject_of(k: &KeyPair) -> Did {
    Did::key_ed25519(&k.public())
}

fn cert(master: &KeyPair, device: u8, noise: u8) -> DeviceCert {
    DeviceCert::issue(
        master,
        &subject_of(master),
        [device; 32],
        [noise; 32],
        CERT_ISSUED_AT,
        CERT_NOT_AFTER,
    )
    .unwrap()
}

fn certs() -> Vec<DeviceCert> {
    vec![cert(&master(), 9, 0x4e), cert(&master(), 10, 0x4f)]
}

/// A body laid out as the module documentation states it, signed with `context` by `signer`
fn signed_card(
    signer: &KeyPair,
    context: &[u8],
    subject: &str,
    master_public: &[u8; 32],
    certs: &[Vec<u8>],
    revocation: &[u8],
) -> Vec<u8> {
    let mut b = vec![1u8];
    b.extend_from_slice(&u16::try_from(subject.len()).unwrap().to_be_bytes());
    b.extend_from_slice(subject.as_bytes());
    b.extend_from_slice(master_public);
    b.extend_from_slice(&ISSUED_AT.to_be_bytes());
    b.push(u8::try_from(certs.len()).unwrap());
    for c in certs {
        b.extend_from_slice(&u16::try_from(c.len()).unwrap().to_be_bytes());
        b.extend_from_slice(c);
    }
    b.extend_from_slice(&u32::try_from(revocation.len()).unwrap().to_be_bytes());
    b.extend_from_slice(revocation);
    let mut signed = context.to_vec();
    signed.extend_from_slice(&b);
    b.extend_from_slice(&signer.sign(&signed).0);
    b
}

fn cert_bytes() -> Vec<Vec<u8>> {
    certs().iter().map(DeviceCert::to_bytes).collect()
}

#[test]
fn the_device_certificates_of_the_reference_are_this_crates_certificates() {
    let reference: Vec<Vec<u8>> = CERTS_HEX.lines().map(unhex).collect();
    assert_eq!(cert_bytes(), reference);
}

#[test]
fn an_issued_card_is_the_reference_bytes_text_and_short_code() {
    let card = ContactCard::issue(&master(), &certs(), None, ISSUED_AT).unwrap();
    assert_eq!(card.to_bytes(), unhex(CARD_HEX));
    assert_eq!(card.to_text(), CARD_TEXT.trim());
    assert!(card.to_text().starts_with(CONTACT_CARD_TEXT_PREFIX));
    assert_eq!(card.short_code(), SHORT_CODE);
    assert_eq!(card.subject().to_string(), SUBJECT);
    assert_eq!(card.master_public(), &master().public().0);
    assert_eq!(card.issued_at(), ISSUED_AT);
    assert_eq!(card.device_certs(), certs().as_slice());
    assert!(card.revocations().is_none());
}

#[test]
fn the_reference_bytes_and_text_decode_and_verify() {
    let from_bytes = ContactCard::from_bytes(&unhex(CARD_HEX)).unwrap();
    let from_text = ContactCard::from_text(CARD_TEXT.trim()).unwrap();
    assert_eq!(from_bytes, from_text);
    assert_eq!(from_bytes.to_bytes(), unhex(CARD_HEX));
    from_bytes.verify(NOW).unwrap();
    assert_eq!(from_bytes.short_code(), SHORT_CODE);
}

/// The card carries no field a person fills in: the only text is the subject, which must be the did:key
/// of the master key, so a name put in its place is refused even when the master signed it
#[test]
fn a_subject_that_is_not_the_did_key_of_the_master_is_refused() {
    let m = master();
    let other = KeyPair::from_seed([8; 32]);
    let named = signed_card(&m, CONTACT_CARD_CONTEXT, "did:alice:jane", &m.public().0, &cert_bytes(), b"");
    assert_eq!(ContactCard::from_bytes(&named), Err(ContactCardError::SubjectNotDidKey));
    let foreign = signed_card(
        &m,
        CONTACT_CARD_CONTEXT,
        &subject_of(&other).to_string(),
        &m.public().0,
        &cert_bytes(),
        b"",
    );
    assert_eq!(ContactCard::from_bytes(&foreign), Err(ContactCardError::SubjectKeyMismatch));
}

#[test]
fn a_signature_under_another_context_is_refused() {
    let m = master();
    let card = signed_card(&m, DEVICE_CERT_CONTEXT, SUBJECT, &m.public().0, &cert_bytes(), b"");
    assert_eq!(ContactCard::from_bytes(&card), Err(ContactCardError::BadSignature));
}

#[test]
fn every_one_byte_change_is_refused() {
    let bytes = unhex(CARD_HEX);
    let mut compared = 0;
    for i in 0..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        let ok = ContactCard::from_bytes(&b).and_then(|c| c.verify(NOW));
        assert!(ok.is_err(), "byte {i} changed and the card still verified");
        compared += 1;
    }
    assert_eq!(compared, bytes.len());
    assert!(compared > 600);
}

#[test]
fn a_certificate_of_another_master_is_refused() {
    let m = master();
    let other = KeyPair::from_seed([8; 32]);
    let mixed = vec![cert(&m, 9, 0x4e), cert(&other, 10, 0x4f)];
    assert_eq!(
        ContactCard::issue(&m, &mixed, None, ISSUED_AT),
        Err(ContactCardError::CertIssuerMismatch(1))
    );
    let bytes: Vec<Vec<u8>> = mixed.iter().map(DeviceCert::to_bytes).collect();
    let card = signed_card(&m, CONTACT_CARD_CONTEXT, SUBJECT, &m.public().0, &bytes, b"");
    assert_eq!(ContactCard::from_bytes(&card), Err(ContactCardError::CertIssuerMismatch(1)));
}

#[test]
fn a_revoked_device_is_not_carried() {
    let m = master();
    let cs = certs();
    let list = RevocationList::issue(&m, 1, ISSUED_AT, &[cs[0].device_id()]);
    assert_eq!(
        ContactCard::issue(&m, &cs, Some(&list), ISSUED_AT),
        Err(ContactCardError::RevokedCert(0))
    );
    let card = signed_card(&m, CONTACT_CARD_CONTEXT, SUBJECT, &m.public().0, &cert_bytes(), &list.to_bytes());
    assert_eq!(ContactCard::from_bytes(&card), Err(ContactCardError::RevokedCert(0)));
    // the same list without the carried devices is accepted and travels with the card
    let other = RevocationList::issue(&m, 2, ISSUED_AT, &[]);
    let card = ContactCard::issue(&m, &cs, Some(&other), ISSUED_AT).unwrap();
    let back = ContactCard::from_bytes(&card.to_bytes()).unwrap();
    assert_eq!(back.revocations(), Some(&other));
    back.verify(NOW).unwrap();
}

#[test]
fn a_revocation_list_of_another_master_is_refused() {
    let m = master();
    let other = KeyPair::from_seed([8; 32]);
    let list = RevocationList::issue(&other, 1, ISSUED_AT, &[]);
    assert_eq!(
        ContactCard::issue(&m, &certs(), Some(&list), ISSUED_AT),
        Err(ContactCardError::RevocationIssuerMismatch)
    );
}

#[test]
fn verify_checks_every_certificate_at_now() {
    let card = ContactCard::from_bytes(&unhex(CARD_HEX)).unwrap();
    assert_eq!(
        card.verify(CERT_NOT_AFTER),
        Err(ContactCardError::Cert(
            0,
            DeviceCertError::Expired { now: CERT_NOT_AFTER, not_after: CERT_NOT_AFTER }
        ))
    );
    card.verify(CERT_NOT_AFTER - 1).unwrap();
}

#[test]
fn the_number_of_certificates_is_bounded() {
    let m = master();
    assert_eq!(ContactCard::issue(&m, &[], None, ISSUED_AT), Err(ContactCardError::NoCerts));
    let many: Vec<DeviceCert> = (0..=MAX_CARD_CERTS).map(|i| cert(&m, 100 + i as u8, 1)).collect();
    assert_eq!(
        ContactCard::issue(&m, &many, None, ISSUED_AT),
        Err(ContactCardError::TooManyCerts(MAX_CARD_CERTS + 1))
    );
    ContactCard::issue(&m, &many[..MAX_CARD_CERTS], None, ISSUED_AT).unwrap();
    let none = signed_card(&m, CONTACT_CARD_CONTEXT, SUBJECT, &m.public().0, &[], b"");
    assert_eq!(ContactCard::from_bytes(&none), Err(ContactCardError::NoCerts));
}

#[test]
fn truncated_and_trailing_bytes_are_refused() {
    let bytes = unhex(CARD_HEX);
    assert!(matches!(ContactCard::from_bytes(&[]), Err(ContactCardError::Malformed(_))));
    for len in [1, 3, 40, bytes.len() - 65, bytes.len() - 1] {
        assert!(ContactCard::from_bytes(&bytes[..len]).is_err(), "length {len}");
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(ContactCard::from_bytes(&longer).is_err());
    let mut v2 = bytes;
    v2[0] = 2;
    assert_eq!(ContactCard::from_bytes(&v2), Err(ContactCardError::UnsupportedVersion(2)));
}

#[test]
fn the_text_form_takes_only_its_prefix_and_upper_case_base32() {
    let text = CARD_TEXT.trim();
    let body = &text[CONTACT_CARD_TEXT_PREFIX.len()..];
    assert_eq!(ContactCard::from_text(&format!("alice-card:1:{body}")), Err(ContactCardError::BadText));
    assert_eq!(ContactCard::from_text(&text.to_lowercase()), Err(ContactCardError::BadText));
    assert_eq!(ContactCard::from_text(&format!("{text}=")), Err(ContactCardError::BadText));
    assert_eq!(ContactCard::from_text(&format!("{text} ")), Err(ContactCardError::BadText));
    assert_eq!(ContactCard::from_text(CONTACT_CARD_TEXT_PREFIX), Err(ContactCardError::BadText));
}
