# ALICE-Identity

Decentralized identity (DID) — self-sovereign identity as DAG trust graphs.

## Features

- **W3C DID**: Parse, validate, and resolve Decentralized Identifiers
- **DID Documents**: Public keys, service endpoints, lifecycle management
- **Verifiable Credentials**: Issue, verify, and present credentials
- **Selective Disclosure**: Reveal only specified claims from a credential
- **Trust Graphs**: DAG-based transitive trust with path discovery
- **Revocation Registry**: Credential revocation tracking
- **Claim Schemas**: Define and validate credential claim structures
- **Device certificates**: a master key certifies a device key for a time window; signed revocation lists withdraw certificates
- **Artifact signatures**: a certified device key signs the digest of any artifact for one stated context (such as `alice-mls/artifact/v1`); the verifier names the context it expects, checks the certificate at its own time and against the revocation list (skipping that check has to be stated, `Revocation::NoListAvailable`), and verifies strictly. The signature covers the digest of the whole certificate, so it cannot be moved under another issuer's certificate for the same device key. Bind everything to protect into the one digest (for example `SHA-256(law_ref || payload_digest)`)

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

License: LicenseRef-Proprietary

`LicenseRef-Proprietary`: using, copying, modifying or distributing the source needs a written agreement with the copyright holder, Moroya Sakamoto. The text is [LICENSE-Proprietary](LICENSE-Proprietary).

Enquiries: https://extoria.co.jp/
