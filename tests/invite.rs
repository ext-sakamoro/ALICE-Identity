//! Oracle for `Invite` and `InviteRedemptions`.
//!
//! The expected bytes and text come from `scripts/gen_contact_vectors.py` (an independent implementation
//! of the layout in the module documentation, stored in `tests/data/`); invites that break one rule are
//! assembled here from the same layout and signed with alice-sign.

use alice_identity::device_cert::MAX_CLOCK_SKEW_SECS;
use alice_identity::did::Did;
use alice_identity::invite::{
    Invite, InviteError, InviteRedemptions, INVITE_CONTEXT, INVITE_TEXT_PREFIX,
};
use alice_sign::KeyPair;

const INVITE_HEX: &str = include_str!("data/invite.hex");
const INVITE_TEXT: &str = include_str!("data/invite.txt");
const ID: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const ISSUED_AT: u64 = 1_800_000_000;
const NOT_AFTER: u64 = 1_800_003_600;

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn master() -> KeyPair {
    KeyPair::from_seed([7; 32])
}

fn invite() -> Invite {
    Invite::issue(&master(), ID, ISSUED_AT, NOT_AFTER).unwrap()
}

/// A body laid out as the module documentation states it, signed with `context` by `signer`
fn signed_invite(signer: &KeyPair, context: &[u8], issuer: &str, issuer_public: &[u8; 32]) -> Vec<u8> {
    let mut b = vec![1u8];
    b.extend_from_slice(&u16::try_from(issuer.len()).unwrap().to_be_bytes());
    b.extend_from_slice(issuer.as_bytes());
    b.extend_from_slice(issuer_public);
    b.extend_from_slice(&ID);
    b.extend_from_slice(&ISSUED_AT.to_be_bytes());
    b.extend_from_slice(&NOT_AFTER.to_be_bytes());
    let mut signed = context.to_vec();
    signed.extend_from_slice(&b);
    b.extend_from_slice(&signer.sign(&signed).0);
    b
}

#[test]
fn an_issued_invite_is_the_reference_bytes_and_text() {
    let inv = invite();
    assert_eq!(inv.to_bytes(), unhex(INVITE_HEX));
    assert_eq!(inv.to_text(), INVITE_TEXT.trim());
    assert!(inv.to_text().starts_with(INVITE_TEXT_PREFIX));
    assert_eq!(inv.issuer(), &Did::key_ed25519(&master().public()));
    assert_eq!(inv.issuer_public(), &master().public().0);
    assert_eq!(inv.invite_id(), &ID);
    assert_eq!((inv.issued_at(), inv.not_after()), (ISSUED_AT, NOT_AFTER));
    assert_eq!(Invite::from_bytes(&unhex(INVITE_HEX)).unwrap(), inv);
    assert_eq!(Invite::from_text(INVITE_TEXT.trim()).unwrap(), inv);
}

#[test]
fn the_validity_window_has_leeway_at_the_start_only() {
    let inv = invite();
    inv.verify(ISSUED_AT - MAX_CLOCK_SKEW_SECS).unwrap();
    assert_eq!(
        inv.verify(ISSUED_AT - MAX_CLOCK_SKEW_SECS - 1),
        Err(InviteError::NotYetValid { now: ISSUED_AT - MAX_CLOCK_SKEW_SECS - 1, issued_at: ISSUED_AT })
    );
    inv.verify(NOT_AFTER - 1).unwrap();
    assert_eq!(inv.verify(NOT_AFTER), Err(InviteError::Expired { now: NOT_AFTER, not_after: NOT_AFTER }));
    assert_eq!(
        Invite::issue(&master(), ID, NOT_AFTER, NOT_AFTER),
        Err(InviteError::InvalidValidity)
    );
}

#[test]
fn an_invite_is_redeemed_once() {
    let m = master();
    let mut r = InviteRedemptions::new(m.public());
    let inv = invite();
    r.redeem(&inv, ISSUED_AT + 10).unwrap();
    assert_eq!(r.redeem(&inv, ISSUED_AT + 20), Err(InviteError::AlreadyRedeemed));
    // another invite of the same issuer is its own
    let second = Invite::issue(&m, [0xaa; 16], ISSUED_AT, NOT_AFTER).unwrap();
    r.redeem(&second, ISSUED_AT + 30).unwrap();
}

#[test]
fn the_redemptions_take_only_their_issuers_invites() {
    let other = KeyPair::from_seed([8; 32]);
    let mut r = InviteRedemptions::new(master().public());
    let foreign = Invite::issue(&other, ID, ISSUED_AT, NOT_AFTER).unwrap();
    assert_eq!(r.redeem(&foreign, ISSUED_AT + 1), Err(InviteError::WrongIssuer));
    // the refused invite was not recorded: the issuer's own invite with the same id still redeems
    r.redeem(&invite(), ISSUED_AT + 1).unwrap();
}

#[test]
fn an_expired_or_early_invite_is_not_recorded() {
    let mut r = InviteRedemptions::new(master().public());
    let inv = invite();
    assert!(matches!(r.redeem(&inv, NOT_AFTER), Err(InviteError::Expired { .. })));
    assert!(matches!(r.redeem(&inv, 0), Err(InviteError::NotYetValid { .. })));
    r.redeem(&inv, ISSUED_AT).unwrap();
}

#[test]
fn a_cancelled_invite_is_refused() {
    let mut r = InviteRedemptions::new(master().public());
    r.cancel(ID);
    assert_eq!(r.redeem(&invite(), ISSUED_AT + 1), Err(InviteError::Cancelled));
    // cancelling a redeemed invite keeps it refused as redeemed
    let mut r = InviteRedemptions::new(master().public());
    r.redeem(&invite(), ISSUED_AT + 1).unwrap();
    r.cancel(ID);
    assert_eq!(r.redeem(&invite(), ISSUED_AT + 2), Err(InviteError::AlreadyRedeemed));
}

#[test]
fn pruning_drops_only_records_whose_invites_have_expired() {
    let m = master();
    let mut r = InviteRedemptions::new(m.public());
    let short = invite();
    let long = Invite::issue(&m, [0xbb; 16], ISSUED_AT, NOT_AFTER + 86_400).unwrap();
    r.redeem(&short, ISSUED_AT + 1).unwrap();
    r.redeem(&long, ISSUED_AT + 1).unwrap();
    r.cancel([0xcc; 16]);
    assert_eq!(r.len(), 3);
    r.prune(NOT_AFTER);
    assert_eq!(r.len(), 2, "the expired redemption goes, the live one and the cancellation stay");
    // the pruned invite is still refused, by its expiry
    assert!(matches!(r.redeem(&short, NOT_AFTER), Err(InviteError::Expired { .. })));
    assert_eq!(r.redeem(&long, NOT_AFTER), Err(InviteError::AlreadyRedeemed));
}

#[test]
fn a_subject_that_is_not_the_did_key_of_the_issuer_is_refused() {
    let m = master();
    let other = KeyPair::from_seed([8; 32]);
    let named = signed_invite(&m, INVITE_CONTEXT, "did:alice:jane", &m.public().0);
    assert_eq!(Invite::from_bytes(&named), Err(InviteError::SubjectNotDidKey));
    let foreign = signed_invite(&m, INVITE_CONTEXT, &Did::key_ed25519(&other.public()).to_string(), &m.public().0);
    assert_eq!(Invite::from_bytes(&foreign), Err(InviteError::SubjectKeyMismatch));
}

#[test]
fn a_signature_under_another_context_is_refused() {
    let m = master();
    let card_context = alice_identity::contact_card::CONTACT_CARD_CONTEXT;
    let issuer = Did::key_ed25519(&m.public()).to_string();
    let inv = signed_invite(&m, card_context, &issuer, &m.public().0);
    assert_eq!(Invite::from_bytes(&inv), Err(InviteError::BadSignature));
    assert_eq!(Invite::from_bytes(&signed_invite(&m, INVITE_CONTEXT, &issuer, &m.public().0)).unwrap(), invite());
}

#[test]
fn every_one_byte_change_is_refused() {
    let bytes = unhex(INVITE_HEX);
    let mut compared = 0;
    for i in 0..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        assert!(Invite::from_bytes(&b).is_err(), "byte {i} changed and the invite still decoded");
        compared += 1;
    }
    assert_eq!(compared, bytes.len());
    assert!(compared > 150);
}

#[test]
fn truncated_trailing_and_text_errors_are_refused() {
    let bytes = unhex(INVITE_HEX);
    assert!(matches!(Invite::from_bytes(&[]), Err(InviteError::Malformed(_))));
    assert!(Invite::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(Invite::from_bytes(&longer).is_err());
    let text = INVITE_TEXT.trim();
    assert_eq!(Invite::from_text(&text.to_lowercase()), Err(InviteError::BadText));
    assert_eq!(Invite::from_text(&format!("{text}=")), Err(InviteError::BadText));
    assert_eq!(Invite::from_text(INVITE_TEXT_PREFIX), Err(InviteError::BadText));
}
