# ALICE-Identity

Decentralized identity (DID) — self-sovereign identity as DAG trust graphs.

## Features

- **W3C DID**: Parse, validate, and resolve Decentralized Identifiers
- **did:key (Ed25519)**: `Did::key_ed25519` and `Did::ed25519_public_key` convert between an Ed25519 public key and its `did:key` identifier (base58btc, multicodec `0xed 0x01`)
- **DID Documents**: Public keys, service endpoints, lifecycle management
- **Verifiable Credentials**: Issue, verify, and present credentials signed with the Ed25519 key of the issuer's `did:key`, valid in `[issued_at, expires_at)`
- **Selective Disclosure**: Reveal only specified claims; the issuer's signature still covers each shown claim (salted Merkle commitment from alice-sign `cred::claims`)
- **Trust Graphs**: DAG-based transitive trust with path discovery
- **Revocation Registry**: Credential revocation tracking
- **Claim Schemas**: Define and validate credential claim structures
- **Device certificates**: a master key certifies a device key and the device's Noise static key (X25519) for a time window; signed revocation lists withdraw certificates
- **Artifact signatures**: a certified device key signs the digest of any artifact for one stated context (such as `alice-mls/artifact/v1`); the verifier names the context it expects, checks the certificate at its own time and against the revocation list (skipping that check has to be stated, `Revocation::NoListAvailable`), and verifies strictly. The signature covers the digest of the whole certificate, so it cannot be moved under another issuer's certificate for the same device key. Bind everything to protect into the one digest (for example `SHA-256(law_ref || payload_digest)`)
- **Signed artifacts**: a law reference and a payload kept or carried as one unit with the artifact signature over `SHA-256(law_ref || SHA-256(payload))` (`SignedArtifact`); its parts are read only through `SignedArtifact::open`, which checks the signature first, so a unit read back from storage is held to what a received one is and a rewritten one (a changed law reference or payload, or other ones under the old signature) is refused
- **Contact cards**: what one person hands another to reach their devices — the identity's `did:key`, its master key, its device certificates and its revocation list, signed by the master key, with no field a person fills in (no name, picture or address). Text form `ALICE-CARD:1:` + upper-case base32 (fits a QR code's alphanumeric mode) and an 8-character short code two people read to each other (`ContactCard`)
- **Invites**: a signed, single-use invite (`did:key`, a 16-byte id the caller draws, a validity window); the issuer's `InviteRedemptions` accepts each invite once, cancels one before use, and prunes expired records (`Invite`, `InviteRedemptions`)
- **Safety numbers**: 60 digits both people compute from their two master keys, identical on both sides and different when either key differs in any bit, plus a 64-byte form for comparing by QR code (`safety_number`)
- **No network, no clock**: creating identities, certificates, cards, invites and safety numbers calls no network and reads no clock (the caller passes `now`); `tests/no_network.rs` scans the sources

## Usage

```rust
use alice_identity::{Did, DidDocument, DidResolver, TrustGraph};

// Parse a DID
let did = Did::parse("did:alice:abc123").unwrap();

// Register a DID document
let mut resolver = DidResolver::new();
let doc = DidDocument::new(did.clone(), 1000);
resolver.register(doc).unwrap();

// Build a trust graph
let mut graph = TrustGraph::new();
graph.add_trust(&did_a, &did_b);
assert!(graph.is_trusted(&did_a, &did_b));
```

## Quality

- 100+ tests
- `clippy::pedantic` + `clippy::nursery` — 0 warnings
- Zero external dependencies

## License

`LicenseRef-Proprietary`. The text is [LICENSE-Proprietary](LICENSE-Proprietary).

Enquiries: https://extoria.co.jp/
