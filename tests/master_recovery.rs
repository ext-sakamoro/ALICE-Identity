//! Oracle for device-loss recovery of the master key (`master_recovery`) and for revocations staying in force
//! through it (`RevocationList::extend`, `CertRevocations::accept`).
//!
//! The reference for "the same identity" is outside the code under test: the DID is `Did::key_ed25519` of the
//! original key, and a recovered key is compared with the original by its public key and by a signature that
//! verifies under the original public key. A changed share is forged here with its byte-form check recomputed
//! (BLAKE3 of everything before it, the documented shard layout), so only the DID can refuse it. Every test
//! counts what it compared and fails on 0.

#![cfg(feature = "recovery")]

use alice_crypto::recovery_code::{RecoveryCode, RecoveryCodeError};
use alice_crypto::{Shard, SssError};
use alice_identity::cert_revocation::{
    Accepted, CertRevocations, RevocationList, RevocationListError,
};
use alice_identity::device_cert::DeviceId;
use alice_identity::did::Did;
use alice_identity::master_recovery::{
    recover_master, split_master, MasterRecoveryBlob, MasterRecoveryError,
};
use alice_sign::KeyPair;

const AT: u64 = 1_800_000_000;
const SEED: [u8; 32] = [0x42; 32];

fn original() -> (KeyPair, Did) {
    let k = KeyPair::from_seed(SEED);
    let did = Did::key_ed25519(&k.public());
    (k, did)
}

fn code(b: u8) -> RecoveryCode {
    RecoveryCode::from_entropy([b; 16])
}

fn id(n: u8) -> DeviceId {
    DeviceId::from_raw([n; 16])
}

/// The recovered key is the original: the same public key, and its signature verifies under the original's
fn assert_same_identity(recovered: &KeyPair, original: &KeyPair) -> usize {
    assert_eq!(recovered.public(), original.public());
    let sig = recovered.sign(b"after recovery");
    assert!(original.public().verify(b"after recovery", &sig));
    2
}

/// A share with y byte `at` changed and the byte-form check recomputed (layout: version, threshold, x,
/// split id 16, u32 length, y, then the first 16 bytes of BLAKE3 of all that)
fn forged(share: &Shard, at: usize) -> Shard {
    forged_by(share, at, 0x5a)
}

/// [`forged`] with the change `delta`
fn forged_by(share: &Shard, at: usize, delta: u8) -> Shard {
    let mut b = share.to_bytes().expect("bytes").to_vec();
    let y0 = 3 + 16 + 4;
    let end = b.len() - 16;
    b[y0 + at] ^= delta;
    let check = alice_crypto::hash(&b[..end]);
    b[end..].copy_from_slice(&check.as_bytes()[..16]);
    Shard::from_bytes(&b).expect("a well-formed share")
}

#[test]
fn a_recovery_code_brings_back_the_same_did_and_key() {
    let (k, did) = original();
    let blob = MasterRecoveryBlob::seal(&SEED, &code(1)).expect("seals");
    let back = MasterRecoveryBlob::from_bytes(&blob.to_bytes()).expect("reads");
    assert_eq!(back, blob);
    let key = back.open(&code(1), &did).expect("opens");
    let compared = assert_same_identity(&key, &k);
    assert_eq!(Did::key_ed25519(&key.public()), did);
    assert!(compared + 1 > 0);
}

#[test]
fn a_wrong_code_a_changed_blob_or_another_did_is_refused() {
    let (_, did) = original();
    let blob = MasterRecoveryBlob::seal(&SEED, &code(1)).expect("seals");
    let mut compared = 0;
    for b in [0u8, 2, 0xff] {
        assert_eq!(
            blob.open(&code(b), &did).map(|_| ()),
            Err(MasterRecoveryError::Code(RecoveryCodeError::Open))
        );
        compared += 1;
    }
    // every byte of the blob changed: a changed public key no longer is this DID's, a changed seal does not open
    let bytes = blob.to_bytes();
    for i in 0..bytes.len() {
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        let r = MasterRecoveryBlob::from_bytes(&b).and_then(|x| x.open(&code(1), &did));
        assert!(r.is_err(), "byte {i} changed and it opened");
        compared += 1;
    }
    // someone else's blob opened against this DID
    let other_seed = [0x43; 32];
    let other = MasterRecoveryBlob::seal(&other_seed, &code(1)).expect("seals");
    assert_eq!(
        other.open(&code(1), &did).map(|_| ()),
        Err(MasterRecoveryError::NotThisIdentity)
    );
    // a DID that is not did:key
    assert_eq!(
        blob.open(&code(1), &Did::new("web", "example")).map(|_| ()),
        Err(MasterRecoveryError::NotAKeyDid)
    );
    compared += 2;
    assert_eq!(compared, 3 + bytes.len() + 2);
}

/// A blob that names this DID's key in its header but seals another seed (bound to that header, under a code the
/// holder knows) opens and is still refused: the seed's own key is checked against the DID
#[test]
fn a_blob_that_claims_this_did_but_holds_another_seed_is_refused() {
    let (k, did) = original();
    let other_seed = [0x43u8; 32];
    let mut ad = alice_identity::master_recovery::MASTER_RECOVERY_CONTEXT.to_vec();
    ad.extend_from_slice(&k.public().0);
    let sealed =
        alice_crypto::recovery_code::seal_secret(&code(1), &other_seed, &ad).expect("seals");
    let mut bytes = k.public().0.to_vec();
    bytes.extend_from_slice(&sealed);
    let blob = MasterRecoveryBlob::from_bytes(&bytes).expect("reads");
    assert_eq!(
        blob.open(&code(1), &did).map(|_| ()),
        Err(MasterRecoveryError::NotThisIdentity)
    );
}

#[test]
fn three_of_five_shares_bring_the_key_back_and_two_do_not() {
    let (k, did) = original();
    let shares = split_master(&SEED, 5, 3).expect("splits");
    assert_eq!(shares.len(), 5);
    let mut compared = 0;
    // every 3 of the 5
    for a in 0..5 {
        for b in a + 1..5 {
            for c in b + 1..5 {
                let set = [shares[a].clone(), shares[b].clone(), shares[c].clone()];
                let r = recover_master(&set, &did).expect("3 shares");
                compared += assert_same_identity(&r.key, &k);
                assert!(r.inconsistent.is_empty());
            }
        }
    }
    // every 2 of the 5
    for a in 0..5 {
        for b in a + 1..5 {
            let set = [shares[a].clone(), shares[b].clone()];
            assert_eq!(
                recover_master(&set, &did).map(|_| ()),
                Err(MasterRecoveryError::Shares(SssError::NotEnoughShards))
            );
            compared += 1;
        }
    }
    assert_eq!(compared, 10 * 2 + 10);
}

#[test]
fn a_changed_share_is_refused_by_the_did_and_named_when_more_are_given() {
    let (k, did) = original();
    let shares = split_master(&SEED, 5, 3).expect("splits");
    let mut compared = 0;
    for at in [0usize, 13, 31] {
        let bad = forged(&shares[1], at);
        // exactly k with one forged: the DID refuses
        let three = [shares[0].clone(), bad.clone(), shares[2].clone()];
        assert_eq!(
            recover_master(&three, &did).map(|_| ()),
            Err(MasterRecoveryError::NotThisIdentity)
        );
        // k + 1 with one forged: the other three bring the key back and the forged x is named
        let four = [shares[0].clone(), bad, shares[2].clone(), shares[3].clone()];
        let r = recover_master(&four, &did).expect("3 good of 4");
        compared += assert_same_identity(&r.key, &k);
        assert_eq!(r.inconsistent, vec![shares[1].x()]);
        compared += 2;
    }
    // k + 1 with two forged in different bytes (their changes cannot cancel: each byte has one changed share), so
    // every set of 3 holds a changed byte and none gives the DID's key
    let four = [
        shares[0].clone(),
        forged(&shares[1], 0),
        forged(&shares[2], 13),
        shares[3].clone(),
    ];
    assert_eq!(
        recover_master(&four, &did).map(|_| ()),
        Err(MasterRecoveryError::NoConsistentSet)
    );
    compared += 1;
    assert_eq!(compared, 3 * 4 + 1);
}

/// With at least k genuine shares every changed share is named: 6 of 3 with two changed (in different bytes)
#[test]
fn with_k_genuine_shares_every_changed_share_is_named() {
    let (k, did) = original();
    let shares = split_master(&SEED, 6, 3).expect("splits");
    let mut given = shares.clone();
    given[1] = forged(&shares[1], 0);
    given[4] = forged(&shares[4], 7);
    let r = recover_master(&given, &did).expect("4 genuine of 6");
    let compared = assert_same_identity(&r.key, &k);
    assert_eq!(r.inconsistent, vec![shares[1].x(), shares[4].x()]);
    // every pair changed alike (the same change in the same byte, so some sets of 3 through both cancel out and
    // give the DID's key): the genuine 4 still win and exactly the pair is named
    let mut pairs = 0;
    for i in 0..6 {
        for j in i + 1..6 {
            let mut given = shares.clone();
            given[i] = forged(&shares[i], 0);
            given[j] = forged(&shares[j], 0);
            let r = recover_master(&given, &did).expect("4 genuine of 6");
            assert_same_identity(&r.key, &k);
            assert_eq!(
                r.inconsistent,
                vec![shares[i].x(), shares[j].x()],
                "pair {i} {j}"
            );
            pairs += 1;
        }
    }
    assert_eq!(pairs, 15);
    // and with every share genuine none is named
    let r = recover_master(&shares, &did).expect("6 genuine");
    assert!(r.inconsistent.is_empty());
    assert_eq!(compared + 2, 4);
}

/// Changed shares that cancel out (the same change in the same byte of two shares, every change tried) never bring
/// back any key but the DID's: each call either refuses or returns the original key
#[test]
fn changes_that_cancel_out_never_bring_back_another_key() {
    let (k, did) = original();
    let shares = split_master(&SEED, 5, 3).expect("splits");
    let (mut returned, mut refused) = (0, 0);
    for delta in 1..=255u8 {
        let given = [
            shares[0].clone(),
            forged_by(&shares[1], 0, delta),
            forged_by(&shares[2], 0, delta),
            shares[3].clone(),
        ];
        match recover_master(&given, &did) {
            Ok(r) => {
                assert_same_identity(&r.key, &k);
                returned += 1;
            }
            Err(e) => {
                assert_eq!(e, MasterRecoveryError::NoConsistentSet, "delta {delta}");
                refused += 1;
            }
        }
    }
    assert_eq!(returned + refused, 255);
}

/// Many shares: 20 genuine shares of 10 come back at once (all on one polynomial), while 20 with one changed would
/// need C(20, 10) = 184756 sets, more than `MAX_RECOVERY_SETS`, and are refused rather than searched without bound
#[test]
fn many_genuine_shares_recover_and_an_unbounded_search_is_refused() {
    let (k, did) = original();
    let shares = split_master(&SEED, 20, 10).expect("splits");
    let r = recover_master(&shares, &did).expect("20 genuine");
    assert_same_identity(&r.key, &k);
    assert!(r.inconsistent.is_empty());
    let mut given = shares.clone();
    given[15] = forged(&shares[15], 3);
    assert_eq!(
        recover_master(&given, &did).map(|_| ()),
        Err(MasterRecoveryError::TooManyShares)
    );
}

#[test]
fn a_device_revoked_before_the_loss_stays_revoked_after_recovery() {
    let (k, did) = original();
    let pk = k.public();
    // before the loss: device 1 revoked
    let before = RevocationList::issue(&k, 4, AT, &[id(1)]);
    let mut contact = CertRevocations::new();
    assert_eq!(contact.accept(before.clone(), &pk), Ok(Accepted::Replaced));
    // the master comes back from the code and revokes the lost device 2 on top of the latest list
    let blob = MasterRecoveryBlob::seal(&SEED, &code(9)).expect("seals");
    let recovered = blob.open(&code(9), &did).expect("opens");
    let next = before
        .extend(&recovered, AT + 60, &[id(2)])
        .expect("extends");
    assert_eq!(next.sequence(), 5);
    assert_eq!(next.revoked(), &[id(1), id(2)]);
    assert_eq!(next.verify(&pk), Ok(()));
    assert_eq!(contact.accept(next, &pk), Ok(Accepted::Replaced));
    let mut compared = 0;
    for (d, revoked) in [(1u8, true), (2, true), (3, false)] {
        assert_eq!(contact.is_revoked(&pk, &id(d)), revoked, "device {d}");
        compared += 1;
    }
    // a newer list that leaves device 1 out (a master that came back without the latest list) is refused and the
    // kept list stays
    let forgetful = RevocationList::issue(&recovered, 6, AT + 120, &[id(2)]);
    assert_eq!(
        contact.accept(forgetful, &pk),
        Err(RevocationListError::DropsRevoked { device_id: id(1) })
    );
    assert_eq!(contact.sequence(&pk), Some(5));
    assert!(contact.is_revoked(&pk, &id(1)));
    compared += 3;
    // extend by another master is refused
    let stranger = KeyPair::from_seed([0x44; 32]);
    assert_eq!(
        before.extend(&stranger, AT, &[id(2)]).map(|_| ()),
        Err(RevocationListError::IssuerMismatch)
    );
    compared += 1;
    assert_eq!(compared, 3 + 3 + 1);
}

#[test]
fn degenerate_inputs_give_their_stated_errors() {
    let (_, did) = original();
    assert_eq!(
        split_master(&SEED, 5, 1).map(|_| ()),
        Err(MasterRecoveryError::Shares(SssError::ThresholdTooLow))
    );
    assert_eq!(
        split_master(&SEED, 2, 3).map(|_| ()),
        Err(MasterRecoveryError::Shares(SssError::ThresholdTooHigh))
    );
    assert_eq!(
        recover_master(&[], &did).map(|_| ()),
        Err(MasterRecoveryError::Shares(SssError::NotEnoughShards))
    );
    for len in [0usize, 31, 32] {
        assert_eq!(
            MasterRecoveryBlob::from_bytes(&vec![0u8; len]).map(|_| ()),
            Err(MasterRecoveryError::Malformed),
            "length {len}"
        );
    }
    // the last sequence cannot be extended
    let k = KeyPair::from_seed(SEED);
    let last = RevocationList::issue(&k, u64::MAX, AT, &[id(1)]);
    assert!(matches!(
        last.extend(&k, AT, &[id(2)]),
        Err(RevocationListError::Malformed(_))
    ));
}
