//! Oracle for `RevocationList` and `CertRevocations`. The expected bytes are assembled here from
//! the layout in the module documentation and signed with alice-sign over the context.

use alice_identity::cert_revocation::{
    Accepted, CertRevocations, RevocationList, RevocationListError, REVOCATION_LIST_CONTEXT,
    REVOCATION_LIST_VERSION,
};
use alice_identity::device_cert::DeviceCert;
use alice_identity::did::Did;
use alice_sign::{KeyPair, PublicKey, Signature};

const AT: u64 = 1_800_000_000;

fn master() -> KeyPair {
    KeyPair::from_seed([7; 32])
}

fn id(n: u8) -> [u8; 16] {
    [n; 16]
}

fn expected_body(master: &KeyPair, sequence: u64, ids: &[[u8; 16]]) -> Vec<u8> {
    let mut b = vec![1u8];
    b.extend_from_slice(&master.public().0);
    b.extend_from_slice(&sequence.to_be_bytes());
    b.extend_from_slice(&AT.to_be_bytes());
    b.extend_from_slice(&u32::try_from(ids.len()).unwrap().to_be_bytes());
    for i in ids {
        b.extend_from_slice(i);
    }
    b
}

fn signed_bytes(master: &KeyPair, body: &[u8]) -> Vec<u8> {
    let mut m = REVOCATION_LIST_CONTEXT.to_vec();
    m.extend_from_slice(body);
    let mut out = body.to_vec();
    out.extend_from_slice(&master.sign(&m).0);
    out
}

#[test]
fn the_encoding_is_the_documented_layout_with_ids_sorted_and_merged() {
    let m = master();
    let l = RevocationList::issue(&m, 3, AT, &[id(5), id(2), id(5), id(9)]);
    let body = expected_body(&m, 3, &[id(2), id(5), id(9)]);
    let mut signed = REVOCATION_LIST_CONTEXT.to_vec();
    signed.extend_from_slice(&body);
    assert_eq!(
        REVOCATION_LIST_CONTEXT,
        b"alice-identity revocation-list v1"
    );
    assert_eq!(REVOCATION_LIST_VERSION, 1);
    assert_eq!(l.signed_message(), signed);
    assert_eq!(l.to_bytes(), signed_bytes(&m, &body));
    assert_eq!(l.revoked(), [id(2), id(5), id(9)]);
    assert_eq!(
        (l.version(), l.issuer_public(), l.sequence(), l.issued_at()),
        (1, &m.public().0, 3, AT)
    );
    assert_eq!(RevocationList::from_bytes(&l.to_bytes()).unwrap(), l);
    assert!(l.contains(&id(5)) && l.contains(&id(9)) && !l.contains(&id(3)));
}

#[test]
fn an_empty_list_is_a_list() {
    let m = master();
    let l = RevocationList::issue(&m, 0, AT, &[]);
    assert_eq!(l.to_bytes(), signed_bytes(&m, &expected_body(&m, 0, &[])));
    assert_eq!(l.verify(&m.public()), Ok(()));
    assert!(!l.contains(&id(0)));
}

#[test]
fn verify_is_strict_and_checks_the_issuer_and_the_context() {
    let m = master();
    let l = RevocationList::issue(&m, 1, AT, &[id(1)]);
    assert_eq!(l.verify(&m.public()), Ok(()));
    assert_eq!(
        l.verify(&KeyPair::from_seed([8; 32]).public()),
        Err(RevocationListError::IssuerMismatch)
    );
    // every byte of the body after the issuer, and of the signature
    let bytes = l.to_bytes();
    let mut checked = 0;
    for i in 33..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        if let Ok(t) = RevocationList::from_bytes(&b) {
            assert_eq!(
                t.verify(&m.public()),
                Err(RevocationListError::BadSignature),
                "byte {i}"
            );
            checked += 1;
        }
    }
    assert!(checked >= 8 + 8 + 64, "{checked}");
    // the same body signed without the context
    let body = expected_body(&m, 1, &[id(1)]);
    let mut bare = body.clone();
    bare.extend_from_slice(&m.sign(&body).0);
    assert_eq!(
        RevocationList::from_bytes(&bare)
            .unwrap()
            .verify(&m.public()),
        Err(RevocationListError::BadSignature)
    );
}

#[test]
fn a_device_certificate_signature_is_not_a_list_signature() {
    // the master signs a device certificate; its signature over the certificate's message must
    // not verify as a list (different contexts)
    let m = master();
    let c = DeviceCert::issue(
        &m,
        &Did::parse("did:alice:p").unwrap(),
        [1; 32],
        [2; 32],
        AT,
        AT + 1,
        id(4),
    )
    .unwrap();
    let l = RevocationList::issue(&m, 1, AT, &[id(1)]);
    let mut forged = l.to_bytes();
    let n = forged.len();
    forged[n - 64..].copy_from_slice(c.signature());
    assert_eq!(
        RevocationList::from_bytes(&forged)
            .unwrap()
            .verify(&m.public()),
        Err(RevocationListError::BadSignature)
    );
}

#[test]
fn a_weak_master_key_is_refused() {
    // identity point as the key, R = B and s = 1: the lax equation holds for any message
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut body = vec![1u8];
    body.extend_from_slice(&identity);
    body.extend_from_slice(&1u64.to_be_bytes());
    body.extend_from_slice(&AT.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    let mut b = [0x66u8; 32];
    b[0] = 0x58;
    let mut s = [0u8; 32];
    s[0] = 1;
    body.extend_from_slice(&b);
    body.extend_from_slice(&s);
    let l = RevocationList::from_bytes(&body).unwrap();
    let weak = PublicKey(identity);
    let sig = Signature(l.signature().to_owned());
    assert!(
        weak.verify(&l.signed_message(), &sig),
        "the lax check accepts it"
    );
    assert_eq!(l.verify(&weak), Err(RevocationListError::BadSignature));
}

#[test]
fn decoding_is_strict() {
    let m = master();
    let bytes = RevocationList::issue(&m, 1, AT, &[id(1), id(2)]).to_bytes();
    for n in 0..bytes.len() {
        assert!(
            RevocationList::from_bytes(&bytes[..n]).is_err(),
            "prefix of {n}"
        );
    }
    let mut long = bytes.clone();
    long.push(0);
    assert!(matches!(
        RevocationList::from_bytes(&long),
        Err(RevocationListError::Malformed(_))
    ));
    let mut v2 = bytes.clone();
    v2[0] = 2;
    assert_eq!(
        RevocationList::from_bytes(&v2),
        Err(RevocationListError::UnsupportedVersion(2))
    );
    // ids out of order, and a repeated id: not canonical
    for ids in [[id(2), id(1)], [id(1), id(1)]] {
        let raw = signed_bytes(&m, &expected_body(&m, 1, &ids));
        assert!(
            matches!(
                RevocationList::from_bytes(&raw),
                Err(RevocationListError::Malformed(_))
            ),
            "{ids:?}"
        );
    }
    // a count past the end of the input
    let mut big = bytes.clone();
    big[1 + 32 + 8 + 8] = 0xff;
    assert!(matches!(
        RevocationList::from_bytes(&big),
        Err(RevocationListError::Malformed(_))
    ));
}

#[test]
fn the_newest_list_wins_whatever_the_arrival_order() {
    let m = master();
    let pk = m.public();
    let l1 = RevocationList::issue(&m, 1, AT, &[id(1)]);
    let l2 = RevocationList::issue(&m, 2, AT, &[id(1), id(2)]);
    let mut a = CertRevocations::new();
    let mut b = CertRevocations::new();
    assert_eq!(a.sequence(&pk), None);
    assert!(!a.is_revoked(&pk, &id(1)));
    assert_eq!(a.accept(l1.clone(), &pk), Ok(Accepted::Replaced));
    assert_eq!(a.accept(l2.clone(), &pk), Ok(Accepted::Replaced));
    assert_eq!(b.accept(l2.clone(), &pk), Ok(Accepted::Replaced));
    assert_eq!(b.accept(l1, &pk), Ok(Accepted::Older));
    assert_eq!(b.accept(l2, &pk), Ok(Accepted::Unchanged));
    for r in [&a, &b] {
        assert_eq!(r.sequence(&pk), Some(2));
        assert!(r.is_revoked(&pk, &id(1)) && r.is_revoked(&pk, &id(2)));
        assert!(!r.is_revoked(&pk, &id(3)));
    }
}

#[test]
fn a_different_list_with_the_same_sequence_is_a_conflict_and_the_kept_one_stays() {
    let m = master();
    let pk = m.public();
    let mut r = CertRevocations::new();
    r.accept(RevocationList::issue(&m, 4, AT, &[id(1)]), &pk)
        .unwrap();
    assert_eq!(
        r.accept(RevocationList::issue(&m, 4, AT, &[id(2)]), &pk),
        Err(RevocationListError::Conflict { sequence: 4 })
    );
    assert!(r.is_revoked(&pk, &id(1)) && !r.is_revoked(&pk, &id(2)));
}

#[test]
fn an_unverified_list_is_not_kept() {
    let m = master();
    let other = KeyPair::from_seed([8; 32]);
    let mut r = CertRevocations::new();
    // signed by another key, offered under this master
    assert_eq!(
        r.accept(RevocationList::issue(&other, 9, AT, &[id(1)]), &m.public()),
        Err(RevocationListError::IssuerMismatch)
    );
    assert_eq!(r.sequence(&m.public()), None);
    assert!(!r.is_revoked(&m.public(), &id(1)));
}

#[test]
fn lists_of_different_masters_are_kept_apart() {
    let a = master();
    let b = KeyPair::from_seed([8; 32]);
    let mut r = CertRevocations::new();
    r.accept(RevocationList::issue(&a, 1, AT, &[id(1)]), &a.public())
        .unwrap();
    r.accept(RevocationList::issue(&b, 1, AT, &[id(2)]), &b.public())
        .unwrap();
    assert!(r.is_revoked(&a.public(), &id(1)) && !r.is_revoked(&a.public(), &id(2)));
    assert!(r.is_revoked(&b.public(), &id(2)) && !r.is_revoked(&b.public(), &id(1)));
}

#[test]
fn a_certificate_is_revoked_by_its_issuers_list() {
    let m = master();
    let did = Did::parse("did:alice:p").unwrap();
    let c = DeviceCert::issue(&m, &did, [1; 32], [2; 32], AT, AT + 10, id(6)).unwrap();
    let mut r = CertRevocations::new();
    assert!(!r.revokes(&c));
    r.accept(RevocationList::issue(&m, 1, AT, &[id(6)]), &m.public())
        .unwrap();
    assert!(r.revokes(&c));
    // the same id under another master's list does not revoke it
    let other = KeyPair::from_seed([8; 32]);
    let mut r2 = CertRevocations::new();
    r2.accept(
        RevocationList::issue(&other, 1, AT, &[id(6)]),
        &other.public(),
    )
    .unwrap();
    assert!(!r2.revokes(&c));
}

#[test]
fn errors_say_what_failed() {
    for (e, word) in [
        (RevocationListError::UnsupportedVersion(2), "version"),
        (RevocationListError::Malformed("order"), "order"),
        (RevocationListError::IssuerMismatch, "issuer"),
        (RevocationListError::BadSignature, "signature"),
        (RevocationListError::Conflict { sequence: 4 }, "sequence 4"),
    ] {
        assert!(e.to_string().contains(word), "{e:?} -> {e}");
    }
}

/// The list bytes for master seed [7; 32], sequence 3, issued_at AT and ids 2, 5, 9, recorded from
/// the hand-assembled layout and alice-sign's deterministic Ed25519: a change to the layout, the
/// context or the signature scheme changes these bytes
const GOLDEN: &str = "01ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c0000000000000003000000006b49d200000000030202020202020202020202020202020205050505050505050505050505050505090909090909090909090909090909093fb62db000efd5ad01d270e1b2e3c6d88447922b37372ae24f9ac28ebef1609cf05bf4f7c9653d0328fbe6fac543c46a2580905529623c33a000754e41cba80c";

#[test]
fn the_fixed_inputs_give_the_recorded_bytes() {
    let l = RevocationList::issue(&master(), 3, AT, &[id(9), id(2), id(5)]);
    let hex: String = l.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex.len(), 2 * (1 + 32 + 8 + 8 + 4 + 3 * 16 + 64));
    assert_eq!(hex, GOLDEN);
}
