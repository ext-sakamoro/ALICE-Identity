//! A verifier whose clock runs behind the issuer's still accepts a certificate issued "in its future" by up to
//! the clock-skew leeway; the end of the validity window has no leeway.
//!
//! oracle (the documented rule, values written here, not read from the crate): with a leeway of 600 seconds a
//! certificate is valid when `issued_at <= now + 600` and `now < not_after`. So at a verifier's `now`:
//! - `issued_at = now + 600` is accepted and `now + 601` is refused as not yet valid;
//! - `not_after = now` and `not_after = now - 1` are refused as expired (no leeway at the end), and
//!   `not_after = now + 1` is accepted.

use alice_identity::device_cert::{DeviceCert, DeviceCertError, MAX_CLOCK_SKEW_SECS};
use alice_identity::did::Did;
use alice_sign::KeyPair;

const NOW: u64 = 1_800_000_000;

fn master() -> KeyPair {
    KeyPair::from_seed([1; 32])
}

fn cert(issued_at: u64, not_after: u64) -> DeviceCert {
    DeviceCert::issue(
        &master(),
        &Did::parse("did:alice:skew").unwrap(),
        KeyPair::from_seed([2; 32]).public().0,
        [0x4e; 32],
        issued_at,
        not_after,
    )
    .unwrap()
}

#[test]
fn the_leeway_is_ten_minutes() {
    assert_eq!(MAX_CLOCK_SKEW_SECS, 600);
}

#[test]
fn a_certificate_issued_up_to_ten_minutes_ahead_of_the_verifier_is_accepted() {
    let m = master().public();
    assert_eq!(cert(NOW + 600, NOW + 86_400).verify(&m, NOW), Ok(()));
    assert_eq!(cert(NOW, NOW + 86_400).verify(&m, NOW), Ok(()));
    assert_eq!(
        cert(NOW + 601, NOW + 86_400).verify(&m, NOW),
        Err(DeviceCertError::NotYetValid {
            now: NOW,
            issued_at: NOW + 601
        })
    );
}

#[test]
fn the_end_of_the_window_has_no_leeway() {
    let m = master().public();
    assert_eq!(cert(NOW - 86_400, NOW + 1).verify(&m, NOW), Ok(()));
    for not_after in [NOW, NOW - 1] {
        assert_eq!(
            cert(NOW - 86_400, not_after).verify(&m, NOW),
            Err(DeviceCertError::Expired {
                now: NOW,
                not_after
            }),
            "not_after {not_after}"
        );
    }
}
