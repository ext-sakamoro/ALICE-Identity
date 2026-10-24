//! Oracle for `DeviceCert`. The expected bytes are assembled here from the layout in the
//! module documentation, and the expected signature is made with alice-sign over the context and
//! those bytes, so neither comes from the code under test.

use alice_identity::device_cert::{
    DeviceCert, DeviceCertError, DEVICE_CERT_CONTEXT, DEVICE_CERT_VERSION,
};
use alice_identity::did::Did;
use alice_sign::{KeyPair, PublicKey, Signature};

const ISSUED_AT: u64 = 1_800_000_000;
const NOT_AFTER: u64 = 1_800_086_400;
const DEVICE: [u8; 32] = [9; 32];
const CERT_ID: [u8; 16] = [0xa5; 16];

fn master() -> KeyPair {
    KeyPair::from_seed([7; 32])
}

fn subject() -> Did {
    Did::parse("did:alice:person-1").unwrap()
}

/// The body as the layout states it, built byte by byte
fn expected_body(master: &KeyPair) -> Vec<u8> {
    let did = b"did:alice:person-1";
    let mut b = vec![1u8];
    b.extend_from_slice(&u16::try_from(did.len()).unwrap().to_be_bytes());
    b.extend_from_slice(did);
    b.extend_from_slice(&DEVICE);
    b.extend_from_slice(&ISSUED_AT.to_be_bytes());
    b.extend_from_slice(&NOT_AFTER.to_be_bytes());
    b.extend_from_slice(&CERT_ID);
    b.extend_from_slice(&master.public().0);
    b
}

fn issued() -> DeviceCert {
    DeviceCert::issue(&master(), &subject(), DEVICE, ISSUED_AT, NOT_AFTER, CERT_ID).unwrap()
}

#[test]
fn the_encoding_is_the_documented_layout_signed_over_the_context() {
    let m = master();
    let body = expected_body(&m);
    let mut signed = DEVICE_CERT_CONTEXT.to_vec();
    signed.extend_from_slice(&body);
    let sig = m.sign(&signed).0;
    let mut want = body.clone();
    want.extend_from_slice(&sig);

    let c = issued();
    assert_eq!(DEVICE_CERT_CONTEXT, b"alice-identity device-cert v1");
    assert_eq!(DEVICE_CERT_VERSION, 1);
    assert_eq!(c.signed_message(), signed);
    assert_eq!(c.to_bytes(), want);
    assert_eq!(c.signature(), &sig);
    assert_eq!(
        (
            c.version(),
            c.subject(),
            c.device_public(),
            c.issued_at(),
            c.not_after(),
            c.cert_id(),
            c.issuer_public()
        ),
        (
            1,
            &subject(),
            &DEVICE,
            ISSUED_AT,
            NOT_AFTER,
            &CERT_ID,
            &m.public().0
        )
    );
}

#[test]
fn bytes_read_back_as_the_same_certificate() {
    let c = issued();
    assert_eq!(DeviceCert::from_bytes(&c.to_bytes()).unwrap(), c);
}

#[test]
fn it_is_valid_from_issued_at_until_just_before_not_after() {
    let c = issued();
    let m = master().public();
    assert_eq!(c.verify(&m, ISSUED_AT), Ok(()));
    assert_eq!(c.verify(&m, NOT_AFTER - 1), Ok(()));
    assert_eq!(
        c.verify(&m, ISSUED_AT - 1),
        Err(DeviceCertError::NotYetValid {
            now: ISSUED_AT - 1,
            issued_at: ISSUED_AT
        })
    );
    assert_eq!(
        c.verify(&m, NOT_AFTER),
        Err(DeviceCertError::Expired {
            now: NOT_AFTER,
            not_after: NOT_AFTER
        })
    );
}

#[test]
fn another_master_is_an_issuer_mismatch() {
    let other = KeyPair::from_seed([8; 32]).public();
    assert_eq!(
        issued().verify(&other, ISSUED_AT),
        Err(DeviceCertError::IssuerMismatch)
    );
}

#[test]
fn a_changed_byte_anywhere_in_the_body_or_signature_fails_the_signature() {
    let m = master().public();
    let bytes = issued().to_bytes();
    // every byte after the version and the subject length (changing those is a decode error or
    // another subject, both covered elsewhere); the issuer key is excluded: changing it is a
    // mismatch with the master
    let issuer_at = bytes.len() - 64 - 32;
    let mut checked = 0;
    for i in 3..bytes.len() {
        if (issuer_at..issuer_at + 32).contains(&i) {
            continue;
        }
        let mut b = bytes.clone();
        b[i] ^= 0x01;
        // a changed subject byte may stop it being a DID: then it is rejected before the signature
        if let Ok(c) = DeviceCert::from_bytes(&b) {
            assert_eq!(
                c.verify(&m, ISSUED_AT),
                Err(DeviceCertError::BadSignature),
                "byte {i}"
            );
            checked += 1;
        }
    }
    // at least every byte of the fixed fields after the subject (device key, times, id,
    // signature) reached the signature check
    assert!(
        checked >= 32 + 8 + 8 + 16 + 64,
        "{checked} changed certificates checked"
    );
}

#[test]
fn a_signature_without_the_context_is_rejected() {
    // the same master signs the bare body (as another kind of statement could): not a certificate
    let m = master();
    let body = expected_body(&m);
    let mut b = body.clone();
    b.extend_from_slice(&m.sign(&body).0);
    let c = DeviceCert::from_bytes(&b).unwrap();
    assert_eq!(
        c.verify(&m.public(), ISSUED_AT),
        Err(DeviceCertError::BadSignature)
    );
}

#[test]
fn a_non_canonical_signature_scalar_is_rejected() {
    // S + L (the group order) is the same scalar modulo L; a signature must carry the reduced
    // one (alice-sign's lax and strict checks both refuse it; the weak-key test below is the one
    // that tells strict from lax)
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let c = issued();
    let mut bytes = c.to_bytes();
    let s_at = bytes.len() - 32;
    let mut carry = 0u16;
    for i in 0..32 {
        let v = u16::from(bytes[s_at + i]) + u16::from(L[i]) + carry;
        bytes[s_at + i] = (v & 0xff) as u8;
        carry = v >> 8;
    }
    assert_eq!(carry, 0, "S + L fits in 32 bytes");
    let tweaked = DeviceCert::from_bytes(&bytes).unwrap();
    assert_eq!(
        tweaked.verify(&master().public(), ISSUED_AT),
        Err(DeviceCertError::BadSignature)
    );
    // the oracle's own check: alice-sign's strict verifier refuses it too
    let sig: [u8; 64] = bytes[bytes.len() - 64..].try_into().unwrap();
    assert!(!master()
        .public()
        .verify_strict(&tweaked.signed_message(), &Signature(sig)));
}

#[test]
fn issuing_needs_a_window_and_a_subject_that_reads_back() {
    let m = master();
    assert_eq!(
        DeviceCert::issue(&m, &subject(), DEVICE, ISSUED_AT, ISSUED_AT, CERT_ID),
        Err(DeviceCertError::InvalidValidity)
    );
    assert_eq!(
        DeviceCert::issue(&m, &subject(), DEVICE, ISSUED_AT, ISSUED_AT - 1, CERT_ID),
        Err(DeviceCertError::InvalidValidity)
    );
    // `did:a:b:c` parses as method `a`, id `b:c`: a method with a colon does not read back
    for bad in [
        Did::new("a:b", "c"),
        Did::new("", "c"),
        Did::new("alice", ""),
    ] {
        assert_eq!(
            DeviceCert::issue(&m, &bad, DEVICE, ISSUED_AT, NOT_AFTER, CERT_ID),
            Err(DeviceCertError::InvalidSubject),
            "{bad:?}"
        );
    }
}

#[test]
fn decoding_rejects_every_short_input_and_trailing_bytes() {
    let bytes = issued().to_bytes();
    for n in 0..bytes.len() {
        assert!(
            DeviceCert::from_bytes(&bytes[..n]).is_err(),
            "prefix of {n} bytes"
        );
    }
    let mut long = bytes.clone();
    long.push(0);
    assert!(matches!(
        DeviceCert::from_bytes(&long),
        Err(DeviceCertError::Malformed(_))
    ));
}

#[test]
fn decoding_rejects_another_version_and_a_subject_that_is_not_a_did() {
    let bytes = issued().to_bytes();
    let mut v2 = bytes.clone();
    v2[0] = 2;
    assert_eq!(
        DeviceCert::from_bytes(&v2),
        Err(DeviceCertError::UnsupportedVersion(2))
    );

    // same length, subject text no longer `did:...`
    let mut not_did = bytes.clone();
    not_did[3] = b'x';
    assert_eq!(
        DeviceCert::from_bytes(&not_did),
        Err(DeviceCertError::InvalidSubject)
    );

    // a subject that is not UTF-8
    let mut not_utf8 = bytes.clone();
    not_utf8[3 + 4] = 0xff;
    assert_eq!(
        DeviceCert::from_bytes(&not_utf8),
        Err(DeviceCertError::InvalidSubject)
    );

    // a subject length past the end of the input
    let mut too_long = bytes.clone();
    too_long[1] = 0xff;
    assert!(matches!(
        DeviceCert::from_bytes(&too_long),
        Err(DeviceCertError::Malformed(_))
    ));
}

#[test]
fn errors_say_what_failed() {
    for (e, word) in [
        (DeviceCertError::UnsupportedVersion(2), "version"),
        (DeviceCertError::Malformed("subject"), "subject"),
        (DeviceCertError::InvalidSubject, "subject"),
        (DeviceCertError::InvalidValidity, "not_after"),
        (DeviceCertError::IssuerMismatch, "issuer"),
        (DeviceCertError::BadSignature, "signature"),
        (
            DeviceCertError::NotYetValid {
                now: 1,
                issued_at: 2,
            },
            "not yet valid",
        ),
        (
            DeviceCertError::Expired {
                now: 3,
                not_after: 2,
            },
            "expired",
        ),
    ] {
        assert!(e.to_string().contains(word), "{e:?} -> {e}");
    }
}

#[test]
fn verify_takes_the_master_as_a_public_key() {
    // the resolver hands out a PublicKey; check the type lines up with alice-sign's
    let m: PublicKey = master().public();
    assert!(issued().verify(&m, ISSUED_AT).is_ok());
}

#[test]
fn a_weak_master_key_is_refused_even_when_the_lax_equation_holds() {
    // master public key = the identity point (small order): [s]B = R + k·A becomes R = [s]B, so
    // R = B with s = 1 satisfies the lax (cofactorless) check for any message; only strict
    // verification, which refuses small-order keys, rejects it
    let mut identity = [0u8; 32];
    identity[0] = 1;
    // compressed base point B
    let mut b = [0x66u8; 32];
    b[0] = 0x58;
    let mut s = [0u8; 32];
    s[0] = 1;
    let did = b"did:alice:person-1";
    let mut bytes = vec![1u8];
    bytes.extend_from_slice(&u16::try_from(did.len()).unwrap().to_be_bytes());
    bytes.extend_from_slice(did);
    bytes.extend_from_slice(&DEVICE);
    bytes.extend_from_slice(&ISSUED_AT.to_be_bytes());
    bytes.extend_from_slice(&NOT_AFTER.to_be_bytes());
    bytes.extend_from_slice(&CERT_ID);
    bytes.extend_from_slice(&identity);
    bytes.extend_from_slice(&b);
    bytes.extend_from_slice(&s);
    let weak = PublicKey(identity);
    let c = DeviceCert::from_bytes(&bytes).unwrap();
    let sig = Signature(c.signature().to_owned());
    // the oracle's premise, measured: the lax check accepts, the strict one refuses
    assert!(
        weak.verify(&c.signed_message(), &sig),
        "lax check accepts the forged signature"
    );
    assert!(!weak.verify_strict(&c.signed_message(), &sig));
    assert_eq!(
        c.verify(&weak, ISSUED_AT),
        Err(DeviceCertError::BadSignature)
    );
}

/// The certificate bytes for the fixed inputs above (master seed [7; 32]), recorded from the
/// hand-assembled layout and alice-sign's deterministic Ed25519: a change to the layout, the
/// context or the signature scheme changes these bytes
const GOLDEN: &str = "0100126469643a616c6963653a706572736f6e2d310909090909090909090909090909090909090909090909090909090909090909000000006b49d200000000006b4b2380a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c7e72fd8f53de829e2d21e671ba1f9a159dca879ed1884e0af75e0094cba8bfe9a2f2a159a9b9849599a2f2ffeeb8a17a1dcf7c90e2ae3a515f21e345c307d407";

#[test]
fn the_fixed_inputs_give_the_recorded_bytes() {
    let hex: String = issued()
        .to_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(hex.len(), 2 * (1 + 2 + 18 + 32 + 8 + 8 + 16 + 32 + 64));
    assert_eq!(hex, GOLDEN);
}
