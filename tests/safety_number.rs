//! Oracle for the safety number of two identities.
//!
//! The expected digits and bytes come from `scripts/gen_contact_vectors.py`, an independent
//! implementation written from the layout in the module documentation (Python's hashlib, with pynacl
//! for the Ed25519 public keys of the fixed seeds), stored in `tests/data/contact_vectors.json`.

use alice_identity::safety_number::{safety_number, SafetyNumberError, SAFETY_NUMBER_DIGITS};
use alice_sign::{KeyPair, PublicKey};

/// `safety_number.digits` of tests/data/contact_vectors.json (seeds [1; 32] and [2; 32])
const DIGITS: &str = "798654443717649966226971265591943135607974901481652324658976";
/// `safety_number.bytes_hex` of tests/data/contact_vectors.json
const BYTES_HEX: &str = include_str!("data/safety_number_bytes.hex");

fn key(seed: u8) -> PublicKey {
    KeyPair::from_seed([seed; 32]).public()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_number_of_the_fixed_keys_is_the_reference_number() {
    let n = safety_number(&key(1), &key(2)).expect("two different keys");
    assert_eq!(n.digits(), DIGITS);
    assert_eq!(n.digits().len(), SAFETY_NUMBER_DIGITS);
    assert_eq!(hex(n.as_bytes()), BYTES_HEX.trim());
}

#[test]
fn both_sides_compute_the_same_number() {
    for (a, b) in [(1u8, 2u8), (3, 4), (200, 7)] {
        let ab = safety_number(&key(a), &key(b)).unwrap();
        let ba = safety_number(&key(b), &key(a)).unwrap();
        assert_eq!(ab, ba, "seeds {a} and {b}");
    }
}

#[test]
fn the_grouped_form_is_twelve_groups_of_five_digits() {
    let n = safety_number(&key(1), &key(2)).unwrap();
    let grouped = n.grouped();
    let groups: Vec<&str> = grouped.split(' ').collect();
    assert_eq!(groups.len(), 12);
    assert!(groups.iter().all(|g| g.len() == 5 && g.bytes().all(|c| c.is_ascii_digit())));
    assert_eq!(groups.concat(), DIGITS);
    assert_eq!(groups[0], "79865");
}

/// Every single-bit change of either key changes the number (2 parties x 256 bits)
#[test]
fn every_one_bit_change_of_either_key_changes_the_number() {
    let a = key(1);
    let b = key(2);
    let base = safety_number(&a, &b).unwrap();
    let mut compared = 0;
    for party in 0..2 {
        for bit in 0..256 {
            let mut bytes = if party == 0 { a.0 } else { b.0 };
            bytes[bit / 8] ^= 1 << (bit % 8);
            let flipped = PublicKey(bytes);
            let n = if party == 0 {
                safety_number(&flipped, &b)
            } else {
                safety_number(&a, &flipped)
            }
            .expect("a flipped key is still a different key");
            assert_ne!(n.digits(), base.digits(), "party {party} bit {bit}");
            assert_ne!(n.as_bytes(), base.as_bytes(), "party {party} bit {bit}");
            compared += 1;
        }
    }
    assert_eq!(compared, 512);
}

#[test]
fn the_same_key_twice_is_refused() {
    let a = key(1);
    assert_eq!(safety_number(&a, &a), Err(SafetyNumberError::SameParty));
}
