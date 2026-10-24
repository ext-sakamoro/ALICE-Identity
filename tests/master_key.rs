//! Oracle for `MasterKeyResolver` and its `DidResolver` implementation: the master key is the one
//! `<did>#master` entry, controlled by the DID, 32 bytes long.

use alice_identity::did::Did;
use alice_identity::did_document::DidDocument;
use alice_identity::master_key::{MasterKeyResolver, ResolveError, MASTER_KEY_FRAGMENT};
use alice_identity::public_key::PublicKeyEntry;
use alice_identity::resolver::DidResolver;
use alice_sign::{KeyPair, PublicKey};

fn did() -> Did {
    Did::parse("did:alice:person-1").unwrap()
}

fn entry(id: &str, controller: &Did, bytes: Vec<u8>) -> PublicKeyEntry {
    PublicKeyEntry {
        id: id.to_owned(),
        key_type: "Ed25519".to_owned(),
        controller: controller.clone(),
        public_key_bytes: bytes,
    }
}

fn resolver_with(keys: Vec<PublicKeyEntry>) -> DidResolver {
    let mut doc = DidDocument::new(did(), 0);
    for k in keys {
        doc.add_public_key(k);
    }
    let mut r = DidResolver::new();
    r.register(doc).unwrap();
    r
}

#[test]
fn the_master_entry_resolves_to_its_key() {
    let master = KeyPair::from_seed([7; 32]).public();
    let other = KeyPair::from_seed([8; 32]).public();
    let r = resolver_with(vec![
        entry(&format!("{}#keys-1", did()), &did(), other.0.to_vec()),
        entry(
            &format!("{}{MASTER_KEY_FRAGMENT}", did()),
            &did(),
            master.0.to_vec(),
        ),
    ]);
    assert_eq!(MASTER_KEY_FRAGMENT, "#master");
    let got: PublicKey = r.master_key(&did()).unwrap();
    assert_eq!(got.0, master.0);
}

#[test]
fn missing_deactivated_absent_ambiguous_and_invalid_masters_are_errors() {
    let k = KeyPair::from_seed([7; 32]).public().0.to_vec();
    let m = format!("{}#master", did());
    assert_eq!(
        DidResolver::new().master_key(&did()),
        Err(ResolveError::NotFound)
    );

    let mut deact = resolver_with(vec![entry(&m, &did(), k.clone())]);
    deact.deactivate(&did()).unwrap();
    assert_eq!(deact.master_key(&did()), Err(ResolveError::Deactivated));

    let none = resolver_with(vec![entry(&format!("{}#keys-1", did()), &did(), k.clone())]);
    assert_eq!(none.master_key(&did()), Err(ResolveError::NoMasterKey));

    let two = resolver_with(vec![
        entry(&m, &did(), k.clone()),
        entry(&m, &did(), k.clone()),
    ]);
    assert_eq!(
        two.master_key(&did()),
        Err(ResolveError::AmbiguousMasterKey)
    );

    let foreign = resolver_with(vec![entry(
        &m,
        &Did::parse("did:alice:other").unwrap(),
        k.clone(),
    )]);
    assert_eq!(
        foreign.master_key(&did()),
        Err(ResolveError::InvalidMasterKey)
    );

    for len in [0, 31, 33] {
        let short = resolver_with(vec![entry(&m, &did(), vec![1; len])]);
        assert_eq!(
            short.master_key(&did()),
            Err(ResolveError::InvalidMasterKey),
            "{len} bytes"
        );
    }
}

#[test]
fn another_dids_master_entry_does_not_count() {
    // an entry named `<other did>#master` inside this document is not this DID's master key
    let k = KeyPair::from_seed([7; 32]).public().0.to_vec();
    let r = resolver_with(vec![entry("did:alice:other#master", &did(), k)]);
    assert_eq!(r.master_key(&did()), Err(ResolveError::NoMasterKey));
}

#[test]
fn errors_say_what_failed() {
    for (e, word) in [
        (ResolveError::NotFound, "not found"),
        (ResolveError::Deactivated, "deactivated"),
        (ResolveError::NoMasterKey, "no master key"),
        (ResolveError::AmbiguousMasterKey, "more than one"),
        (ResolveError::InvalidMasterKey, "invalid"),
    ] {
        assert!(e.to_string().contains(word), "{e:?} -> {e}");
    }
}
