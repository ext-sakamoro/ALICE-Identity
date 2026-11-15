//! Oracle for `delegated_revocation`: a relay's revocation list is signed by a delegate key that the
//! offline master certified for the service `relay-revocations`, and lists are ordered by (epoch, sequence)
//! where the epoch is the delegate certificate's `issued_at`.
//!
//! The expected outcomes come from the rules of the design (freshness interval, 7-day bound, zero Noise
//! key, epoch before sequence), written here as literals; no expected value is computed by the code under
//! test. The conflict digests are compared with SHA-256 of the encoded lists computed in the test.

use alice_identity::artifact::Revocation;
use alice_identity::cert_revocation::{Accepted, RevocationList};
use alice_identity::delegated_revocation::{
    issue_revocation_delegate, DelegatedRevocationError as E, DelegatedRevocations,
    DEFAULT_REVOCATION_FRESHNESS_WINDOW_SECS, REVOCATION_DELEGATE_MAX_LIFETIME_SECS,
    REVOCATION_DELEGATE_NOISE_STATIC, REVOCATION_DELEGATE_SERVICE,
};
use alice_identity::device_cert::{DeviceCert, DeviceId, MAX_CLOCK_SKEW_SECS};
use alice_identity::service_cert::{issue_service_cert, verify_service_cert, ServiceCertError};
use alice_sign::{KeyPair, PublicKey};

const T0: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
const WINDOW: u64 = DEFAULT_REVOCATION_FRESHNESS_WINDOW_SECS;

/// Test fixtures, never production keys
fn master() -> KeyPair {
    KeyPair::from_seed([0x5a; 32])
}
fn other_master() -> KeyPair {
    KeyPair::from_seed([0x5b; 32])
}
fn delegate_key(n: u8) -> KeyPair {
    KeyPair::from_seed([0x20 + n; 32])
}
fn mpub() -> PublicKey {
    master().public()
}

/// A delegate certificate for key `n`, epoch `epoch`, valid 7 days
fn delegate(n: u8, epoch: u64) -> DeviceCert {
    issue_revocation_delegate(
        &master(),
        delegate_key(n).public().0,
        epoch,
        epoch + REVOCATION_DELEGATE_MAX_LIFETIME_SECS,
    )
    .unwrap()
}

fn dev(n: u8) -> DeviceId {
    DeviceId::from_raw([n; 16])
}

fn list(n: u8, seq: u64, at: u64, revoked: &[DeviceId]) -> RevocationList {
    RevocationList::issue(&delegate_key(n), seq, at, revoked)
}

#[test]
fn constants_have_the_ruled_values() {
    assert_eq!(DEFAULT_REVOCATION_FRESHNESS_WINDOW_SECS, 86_400);
    assert_eq!(REVOCATION_DELEGATE_MAX_LIFETIME_SECS, 604_800);
    assert_eq!(REVOCATION_DELEGATE_SERVICE, "relay-revocations");
    assert_eq!(REVOCATION_DELEGATE_NOISE_STATIC, [0u8; 32]);
}

#[test]
fn accepts_a_fresh_list_from_a_valid_delegate() {
    let mut r = DelegatedRevocations::new();
    let d = delegate(1, T0);
    let got = r.accept(list(1, 1, T0 + 10, &[dev(9)]), &d, &mpub(), T0 + 20, WINDOW);
    assert_eq!(got, Ok(Accepted::Replaced));
    assert_eq!(r.epoch(), Some(T0));
    assert_eq!(r.sequence(), Some(1));
    assert!(r.require_fresh(T0 + 20, WINDOW).is_ok());
}

#[test]
fn refuses_a_delegate_signed_by_another_master() {
    let d = issue_service_cert(
        &other_master(),
        REVOCATION_DELEGATE_SERVICE,
        delegate_key(1).public().0,
        [0; 32],
        T0,
        T0 + DAY,
    )
    .unwrap();
    let got = DelegatedRevocations::new().accept(list(1, 1, T0, &[]), &d, &mpub(), T0, WINDOW);
    assert!(
        matches!(got, Err(E::DelegateCert(ServiceCertError::Cert(_)))),
        "{got:?}"
    );
}

#[test]
fn refuses_an_expired_delegate() {
    let d = delegate(1, T0);
    let now = T0 + REVOCATION_DELEGATE_MAX_LIFETIME_SECS; // now == not_after
    let got = DelegatedRevocations::new().accept(list(1, 1, now, &[]), &d, &mpub(), now, WINDOW);
    assert!(
        matches!(got, Err(E::DelegateCert(ServiceCertError::Cert(_)))),
        "{got:?}"
    );
}

#[test]
fn refuses_a_delegate_living_seven_days_and_one_second() {
    let long = 7 * DAY + 1;
    // the helper refuses to issue it
    assert_eq!(
        issue_revocation_delegate(&master(), delegate_key(1).public().0, T0, T0 + long),
        Err(E::LifetimeTooLong(long))
    );
    // a general service certificate (30-day bound) of that lifetime is refused at accept
    let d = issue_service_cert(
        &master(),
        REVOCATION_DELEGATE_SERVICE,
        delegate_key(1).public().0,
        [0; 32],
        T0,
        T0 + long,
    )
    .unwrap();
    let got = DelegatedRevocations::new().accept(list(1, 1, T0, &[]), &d, &mpub(), T0, WINDOW);
    assert_eq!(got, Err(E::LifetimeTooLong(long)));
    // exactly 7 days is accepted
    let ok = issue_service_cert(
        &master(),
        REVOCATION_DELEGATE_SERVICE,
        delegate_key(1).public().0,
        [0; 32],
        T0,
        T0 + 7 * DAY,
    )
    .unwrap();
    let got = DelegatedRevocations::new().accept(list(1, 1, T0, &[]), &ok, &mpub(), T0, WINDOW);
    assert_eq!(got, Ok(Accepted::Replaced));
}

#[test]
fn refuses_a_delegate_with_a_non_zero_noise_key() {
    let mut compared = 0;
    for byte in [1u8, 0x80] {
        for at in [0usize, 31] {
            let mut noise = [0u8; 32];
            noise[at] = byte;
            let d = issue_service_cert(
                &master(),
                REVOCATION_DELEGATE_SERVICE,
                delegate_key(1).public().0,
                noise,
                T0,
                T0 + DAY,
            )
            .unwrap();
            let got =
                DelegatedRevocations::new().accept(list(1, 1, T0, &[]), &d, &mpub(), T0, WINDOW);
            assert_eq!(got, Err(E::NotAZeroNoiseKey));
            compared += 1;
        }
    }
    assert!(compared > 0);
}

#[test]
fn refuses_a_delegate_for_another_service() {
    let d = issue_service_cert(
        &master(),
        "relay",
        delegate_key(1).public().0,
        [0; 32],
        T0,
        T0 + DAY,
    )
    .unwrap();
    let got = DelegatedRevocations::new().accept(list(1, 1, T0, &[]), &d, &mpub(), T0, WINDOW);
    assert_eq!(got, Err(E::DelegateCert(ServiceCertError::WrongService)));
}

#[test]
fn refuses_a_list_signed_by_another_key_than_the_delegate() {
    let d = delegate(1, T0);
    // signed by delegate 2 (a key the master did not certify here) and by the master itself
    for l in [
        list(2, 1, T0, &[]),
        RevocationList::issue(&master(), 1, T0, &[]),
    ] {
        let got = DelegatedRevocations::new().accept(l, &d, &mpub(), T0, WINDOW);
        assert_eq!(got, Err(E::WrongSigner));
    }
}

#[test]
fn refuses_a_tampered_list() {
    let d = delegate(1, T0);
    let good = list(1, 1, T0, &[dev(3), dev(7)]).to_bytes();
    let mut compared = 0;
    // flip one bit in every byte after the issuer key (sequence, time, count, ids, signature)
    for i in 33..good.len() {
        let mut b = good.clone();
        b[i] ^= 0x01;
        let Ok(l) = RevocationList::from_bytes(&b) else {
            continue; // a malformed list never reaches accept
        };
        let got = DelegatedRevocations::new().accept(l, &d, &mpub(), T0, 3 * WINDOW);
        assert!(got.is_err(), "byte {i} flipped was accepted");
        if got == Err(E::BadSignature) {
            compared += 1;
        }
    }
    assert!(
        compared > 50,
        "only {compared} flips reached the signature check"
    );
}

#[test]
fn refuses_a_stale_list_and_one_from_the_future() {
    let d = delegate(1, T0);
    let now = T0 + 2 * DAY;
    // issued_at == now - window: fresh (the bound is included)
    let edge =
        DelegatedRevocations::new().accept(list(1, 1, now - WINDOW, &[]), &d, &mpub(), now, WINDOW);
    assert_eq!(edge, Ok(Accepted::Replaced));
    let stale = DelegatedRevocations::new().accept(
        list(1, 1, now - WINDOW - 1, &[]),
        &d,
        &mpub(),
        now,
        WINDOW,
    );
    assert_eq!(
        stale,
        Err(E::Stale {
            issued_at: now - WINDOW - 1,
            now
        })
    );
    // issued_at == now + skew: fresh; one more second: from the future
    let skew_edge = DelegatedRevocations::new().accept(
        list(1, 1, now + MAX_CLOCK_SKEW_SECS, &[]),
        &d,
        &mpub(),
        now,
        WINDOW,
    );
    assert_eq!(skew_edge, Ok(Accepted::Replaced));
    let future = DelegatedRevocations::new().accept(
        list(1, 1, now + MAX_CLOCK_SKEW_SECS + 1, &[]),
        &d,
        &mpub(),
        now,
        WINDOW,
    );
    assert_eq!(
        future,
        Err(E::FromTheFuture {
            issued_at: now + MAX_CLOCK_SKEW_SECS + 1,
            now
        })
    );
}

#[test]
fn is_fresh_follows_the_interval_and_saturates() {
    let l = list(1, 1, 1000, &[]);
    let cases: [(u64, u64, bool); 8] = [
        (1000, 0, true),
        (1001, 0, false),
        (1001, 1, true),
        (1000 - MAX_CLOCK_SKEW_SECS, 0, true),
        (1000 - MAX_CLOCK_SKEW_SECS - 1, 0, false),
        (0, u64::MAX, false),  // 1000 > 0 + skew (600)
        (500, u64::MAX, true), // window larger than now: no underflow (1000 <= 500 + 600)
        (u64::MAX, u64::MAX, true),
    ];
    let mut compared = 0;
    for (now, window, want) in cases {
        assert_eq!(l.is_fresh(now, window), want, "now {now} window {window}");
        compared += 1;
    }
    assert!(compared > 0);
    // now near u64::MAX does not wrap the skew bound
    let late = list(1, 1, u64::MAX, &[]);
    assert!(late.is_fresh(u64::MAX, 0));
}

#[test]
fn ordering_within_an_epoch() {
    let d = delegate(1, T0);
    let mut r = DelegatedRevocations::new();
    let l1 = list(1, 1, T0, &[dev(1)]);
    let l2 = list(1, 2, T0 + 1, &[dev(1), dev(2)]);
    assert_eq!(
        r.accept(l1.clone(), &d, &mpub(), T0 + 5, WINDOW),
        Ok(Accepted::Replaced)
    );
    // the sequence rises
    assert_eq!(
        r.accept(l2.clone(), &d, &mpub(), T0 + 5, WINDOW),
        Ok(Accepted::Replaced)
    );
    assert_eq!(r.sequence(), Some(2));
    // a lower one is refused
    assert_eq!(
        r.accept(l1, &d, &mpub(), T0 + 5, WINDOW),
        Err(E::OlderSequence {
            epoch: T0,
            kept: 2,
            offered: 1
        })
    );
    // the same list again is idempotent
    assert_eq!(
        r.accept(l2.clone(), &d, &mpub(), T0 + 5, WINDOW),
        Ok(Accepted::Unchanged)
    );
    assert_eq!(r.list(), Some(&l2));
    // a newer list in the same epoch keeps every revoked device
    assert_eq!(
        r.accept(list(1, 3, T0 + 2, &[dev(2)]), &d, &mpub(), T0 + 5, WINDOW),
        Err(E::DropsRevoked { device_id: dev(1) })
    );
}

#[test]
fn a_conflict_names_both_digests_and_keeps_the_first() {
    let d = delegate(1, T0);
    let mut r = DelegatedRevocations::new();
    let kept = list(1, 4, T0, &[dev(1)]);
    let offered = list(1, 4, T0, &[dev(1), dev(2)]);
    r.accept(kept.clone(), &d, &mpub(), T0, WINDOW).unwrap();
    let before = r.to_bytes();
    let got = r.accept(offered.clone(), &d, &mpub(), T0, WINDOW);
    let Err(E::Conflict {
        epoch,
        sequence,
        kept_digest,
        offered_digest,
    }) = got.clone()
    else {
        panic!("not a conflict: {got:?}");
    };
    assert_eq!((epoch, sequence), (T0, 4));
    assert_ne!(kept_digest, offered_digest);
    // the digests are SHA-256 of the encoded lists (independent of the code under test: computed
    // here through alice-crypto's sha256 on the bytes this test holds)
    assert_eq!(kept_digest, alice_crypto::sha256::digest(&kept.to_bytes()));
    assert_eq!(
        offered_digest,
        alice_crypto::sha256::digest(&offered.to_bytes())
    );
    // the log line names both in hex
    let text = got.unwrap_err().to_string();
    let hex = |d: &[u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert!(text.contains(&hex(&kept_digest)), "{text}");
    assert!(text.contains(&hex(&offered_digest)), "{text}");
    // the kept state is unchanged
    assert_eq!(r.to_bytes(), before);
    assert_eq!(r.list(), Some(&kept));
}

#[test]
fn the_same_epoch_with_another_delegate_key_is_refused() {
    let mut r = DelegatedRevocations::new();
    r.accept(list(1, 1, T0, &[]), &delegate(1, T0), &mpub(), T0, WINDOW)
        .unwrap();
    let got = r.accept(list(2, 2, T0, &[]), &delegate(2, T0), &mpub(), T0, WINDOW);
    assert_eq!(got, Err(E::DelegateConflict { epoch: T0 }));
}

/// The leaked delegate of epoch E signs u64::MAX - 1; the master's next delegate (E' > E) supersedes it with
/// sequence 1, and from then on lists under E are refused
fn leaked_delegate_steps(r: &mut DelegatedRevocations) {
    let e = T0;
    let e2 = T0 + DAY;
    let now = e2 + 10;
    let d_e = delegate(1, e);
    let d_e2 = delegate(2, e2);
    // the new list names the leaked delegate's device id and leaves out the attacker's entries
    let fresh = list(2, 1, now, &[d_e.device_id()]);
    assert_eq!(
        r.accept(fresh, &d_e2, &mpub(), now, WINDOW),
        Ok(Accepted::Replaced)
    );
    assert_eq!((r.epoch(), r.sequence()), (Some(e2), Some(1)));
    // a later list under E, even with the highest sequence, is refused
    let late = list(1, u64::MAX, now, &[]);
    let got = r.accept(late, &d_e, &mpub(), now, WINDOW);
    assert!(
        matches!(
            got,
            Err(E::DelegateCert(ServiceCertError::Revoked)) | Err(E::OlderEpoch { .. })
        ),
        "{got:?}"
    );
}

#[test]
fn a_leaked_delegate_is_superseded_by_the_next_epoch() {
    let e = T0;
    let mut r = DelegatedRevocations::new();
    let attack = list(1, u64::MAX - 1, e + 5, &[dev(0x77)]);
    r.accept(attack, &delegate(1, e), &mpub(), e + 10, WINDOW)
        .unwrap();
    assert_eq!(r.sequence(), Some(u64::MAX - 1));
    leaked_delegate_steps(&mut r);
    assert!(!r.list().unwrap().contains(&dev(0x77)));
}

#[test]
fn an_older_epoch_is_refused_even_when_its_delegate_is_not_revoked() {
    let e = T0;
    let e2 = T0 + DAY;
    let now = e2 + 10;
    let mut r = DelegatedRevocations::new();
    r.accept(list(2, 1, now, &[]), &delegate(2, e2), &mpub(), now, WINDOW)
        .unwrap();
    let got = r.accept(
        list(1, u64::MAX, now, &[]),
        &delegate(1, e),
        &mpub(),
        now,
        WINDOW,
    );
    assert_eq!(
        got,
        Err(E::OlderEpoch {
            kept: e2,
            offered: e
        })
    );
}

#[test]
fn a_delegate_named_in_the_kept_list_is_refused() {
    let e = T0;
    let e2 = T0 + DAY;
    let now = e2 + 10;
    let d_e2 = delegate(2, e2);
    let mut r = DelegatedRevocations::new();
    // the kept list (epoch E) revokes the delegate key 2's id
    r.accept(
        list(1, 1, now, &[d_e2.device_id()]),
        &delegate(1, e),
        &mpub(),
        now,
        2 * DAY,
    )
    .unwrap();
    let got = r.accept(list(2, 1, now, &[]), &d_e2, &mpub(), now, WINDOW);
    assert_eq!(got, Err(E::DelegateCert(ServiceCertError::Revoked)));
    assert!(r.revokes(&d_e2));
    // the Revocation view refuses the same certificate through verify_service_cert
    let via_view = verify_service_cert(
        &d_e2,
        &mpub(),
        REVOCATION_DELEGATE_SERVICE,
        now,
        r.revocation(),
    );
    assert_eq!(via_view, Err(ServiceCertError::Revoked));
}

#[test]
fn revocation_view_is_none_when_nothing_is_kept() {
    let r = DelegatedRevocations::new();
    assert!(matches!(r.revocation(), Revocation::NoListAvailable));
    assert!(!r.revokes(&delegate(1, T0)));
}

#[test]
fn require_fresh_refuses_empty_and_stale() {
    let r = DelegatedRevocations::new();
    assert_eq!(r.require_fresh(T0, WINDOW), Err(E::NothingKept));
    let mut r = DelegatedRevocations::new();
    r.accept(list(1, 1, T0, &[]), &delegate(1, T0), &mpub(), T0, WINDOW)
        .unwrap();
    assert_eq!(r.require_fresh(T0 + WINDOW, WINDOW), Ok(()));
    assert_eq!(
        r.require_fresh(T0 + WINDOW + 1, WINDOW),
        Err(E::Stale {
            issued_at: T0,
            now: T0 + WINDOW + 1
        })
    );
    assert_eq!(
        r.require_fresh(T0 - MAX_CLOCK_SKEW_SECS - 1, WINDOW),
        Err(E::FromTheFuture {
            issued_at: T0,
            now: T0 - MAX_CLOCK_SKEW_SECS - 1
        })
    );
}

#[test]
fn other_master_is_refused_once_one_is_kept() {
    let mut r = DelegatedRevocations::new();
    r.accept(list(1, 1, T0, &[]), &delegate(1, T0), &mpub(), T0, WINDOW)
        .unwrap();
    let d = issue_service_cert(
        &other_master(),
        REVOCATION_DELEGATE_SERVICE,
        delegate_key(3).public().0,
        [0; 32],
        T0 + 1,
        T0 + DAY,
    )
    .unwrap();
    let got = r.accept(
        list(3, 1, T0, &[]),
        &d,
        &other_master().public(),
        T0 + 1,
        WINDOW,
    );
    assert_eq!(got, Err(E::OtherMaster));
}

fn kept_state() -> DelegatedRevocations {
    let mut r = DelegatedRevocations::new();
    r.accept(
        list(1, u64::MAX - 1, T0 + 5, &[dev(3)]),
        &delegate(1, T0),
        &mpub(),
        T0 + 10,
        WINDOW,
    )
    .unwrap();
    r
}

#[test]
fn round_trip_keeps_the_refusals() {
    let r = kept_state();
    let bytes = r.to_bytes();
    let mut back = DelegatedRevocations::restore(&bytes, &mpub()).unwrap();
    assert_eq!(back.to_bytes(), bytes);
    assert_eq!((back.epoch(), back.sequence()), (r.epoch(), r.sequence()));
    // ordering refusals hold after restore
    let d = delegate(1, T0);
    assert_eq!(
        back.accept(list(1, 1, T0 + 6, &[dev(3)]), &d, &mpub(), T0 + 10, WINDOW),
        Err(E::OlderSequence {
            epoch: T0,
            kept: u64::MAX - 1,
            offered: 1
        })
    );
    assert!(matches!(
        back.accept(
            list(1, u64::MAX - 1, T0 + 6, &[dev(3), dev(4)]),
            &d,
            &mpub(),
            T0 + 10,
            WINDOW
        ),
        Err(E::Conflict { .. })
    ));
    // and the leaked-delegate recovery works from the restored state
    leaked_delegate_steps(&mut back);
    // the empty state round-trips too
    let empty = DelegatedRevocations::new().to_bytes();
    let e = DelegatedRevocations::restore(&empty, &mpub()).unwrap();
    assert_eq!(e.require_fresh(T0, WINDOW), Err(E::NothingKept));
}

#[test]
fn restore_does_not_check_freshness_but_require_fresh_does() {
    let bytes = kept_state().to_bytes();
    let back = DelegatedRevocations::restore(&bytes, &mpub()).unwrap();
    let late = T0 + 30 * DAY; // the delegate has expired and the list is stale
    assert!(matches!(
        back.require_fresh(late, WINDOW),
        Err(E::Stale { .. })
    ));
}

#[test]
fn from_bytes_fails_on_any_corruption() {
    let bytes = kept_state().to_bytes();
    let mut compared = 0;
    for i in 0..bytes.len() {
        for bit in [0x01u8, 0x80] {
            let mut b = bytes.clone();
            b[i] ^= bit;
            assert!(
                DelegatedRevocations::from_bytes(&b).is_err(),
                "byte {i} bit {bit:#x} flipped was read"
            );
            compared += 1;
        }
    }
    // truncation and extension
    for n in 0..bytes.len() {
        assert!(DelegatedRevocations::from_bytes(&bytes[..n]).is_err());
        compared += 1;
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(DelegatedRevocations::from_bytes(&longer).is_err());
    assert!(compared > 1000, "{compared}");
}

/// Re-encode a state with a recomputed digest (the digest has no key, so anyone can do it)
fn forge(master_pub: [u8; 32], cert: &DeviceCert, l: &RevocationList) -> Vec<u8> {
    let mut b = vec![1u8, 1];
    let c = cert.to_bytes();
    let lb = l.to_bytes();
    b.extend_from_slice(&master_pub);
    b.extend_from_slice(&cert.issued_at().to_be_bytes());
    b.extend_from_slice(&l.sequence().to_be_bytes());
    b.extend_from_slice(&u16::try_from(c.len()).unwrap().to_be_bytes());
    b.extend_from_slice(&c);
    b.extend_from_slice(&u32::try_from(lb.len()).unwrap().to_be_bytes());
    b.extend_from_slice(&lb);
    let d = alice_crypto::sha256::digest(&b);
    b.extend_from_slice(&d);
    b
}

#[test]
fn restore_checks_every_signature_from_bytes_does_not() {
    // the forge layout equals to_bytes for an honest state (the oracle of the format)
    let honest = kept_state();
    assert_eq!(
        forge(mpub().0, honest.delegate().unwrap(), honest.list().unwrap()),
        honest.to_bytes()
    );
    // a delegate certified by another master, stored as if the master had certified it
    let rogue = issue_service_cert(
        &other_master(),
        REVOCATION_DELEGATE_SERVICE,
        delegate_key(1).public().0,
        [0; 32],
        T0,
        T0 + DAY,
    )
    .unwrap();
    let l = list(1, 1, T0, &[]);
    let forged = forge(other_master().public().0, &rogue, &l);
    assert!(DelegatedRevocations::from_bytes(&forged).is_ok());
    assert_eq!(
        DelegatedRevocations::restore(&forged, &mpub()).unwrap_err(),
        E::OtherMaster
    );
    // same master key recorded, but the certificate's signature is someone else's: rewrite the
    // issuer field of a rogue certificate to the master's key
    let mut cb = rogue.to_bytes();
    let n = cb.len();
    cb[n - 64 - 32..n - 64].copy_from_slice(&mpub().0);
    let relabelled = DeviceCert::from_bytes(&cb).unwrap();
    let forged = forge(mpub().0, &relabelled, &l);
    assert!(DelegatedRevocations::from_bytes(&forged).is_ok());
    assert!(matches!(
        DelegatedRevocations::restore(&forged, &mpub()),
        Err(E::DelegateCert(ServiceCertError::Cert(_)))
    ));
    // a valid delegate with a list signed by another key
    let forged = forge(mpub().0, &delegate(1, T0), &list(2, 1, T0, &[]));
    assert!(DelegatedRevocations::from_bytes(&forged).is_ok());
    assert_eq!(
        DelegatedRevocations::restore(&forged, &mpub()).unwrap_err(),
        E::WrongSigner
    );
    // a valid delegate with a list whose signature does not verify
    let mut lb = list(1, 1, T0, &[]).to_bytes();
    let last = lb.len() - 1;
    lb[last] ^= 1;
    let bad = RevocationList::from_bytes(&lb).unwrap();
    let forged = forge(mpub().0, &delegate(1, T0), &bad);
    assert!(DelegatedRevocations::from_bytes(&forged).is_ok());
    assert_eq!(
        DelegatedRevocations::restore(&forged, &mpub()).unwrap_err(),
        E::BadSignature
    );
    // a delegate with a non-zero Noise key, and one for another service, both signed by the master
    let noisy = issue_service_cert(
        &master(),
        REVOCATION_DELEGATE_SERVICE,
        delegate_key(1).public().0,
        [9; 32],
        T0,
        T0 + DAY,
    )
    .unwrap();
    let forged = forge(mpub().0, &noisy, &l);
    assert_eq!(
        DelegatedRevocations::restore(&forged, &mpub()).unwrap_err(),
        E::NotAZeroNoiseKey
    );
    let relay = issue_service_cert(
        &master(),
        "relay",
        delegate_key(1).public().0,
        [0; 32],
        T0,
        T0 + DAY,
    )
    .unwrap();
    let forged = forge(mpub().0, &relay, &l);
    assert_eq!(
        DelegatedRevocations::restore(&forged, &mpub()).unwrap_err(),
        E::DelegateCert(ServiceCertError::WrongService)
    );
    let long = issue_service_cert(
        &master(),
        REVOCATION_DELEGATE_SERVICE,
        delegate_key(1).public().0,
        [0; 32],
        T0,
        T0 + 7 * DAY + 1,
    )
    .unwrap();
    let forged = forge(mpub().0, &long, &l);
    assert_eq!(
        DelegatedRevocations::restore(&forged, &mpub()).unwrap_err(),
        E::LifetimeTooLong(7 * DAY + 1)
    );
}

#[test]
fn from_bytes_refuses_every_truncated_body_with_a_valid_digest() {
    // the digest has no key, so a truncated body with a recomputed digest reaches the reader: every
    // field read (master, epoch, sequence, both lengths, both bodies) must refuse the short read
    let bytes = kept_state().to_bytes();
    let body = &bytes[..bytes.len() - 32];
    let mut compared = 0;
    for n in 1..body.len() {
        let mut b = body[..n].to_vec();
        let d = alice_crypto::sha256::digest(&b);
        b.extend_from_slice(&d);
        assert!(
            matches!(
                DelegatedRevocations::from_bytes(&b),
                Err(E::Malformed(_) | E::DelegateCert(_))
            ),
            "a body cut to {n} bytes was read"
        );
        compared += 1;
    }
    assert!(compared > 100, "{compared}");
}
