//! Integration tests.

#![allow(
    clippy::wildcard_imports,
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::indexing_slicing
)]

use crate::claim_schema::*;
use crate::credential::*;
use crate::did::*;
use crate::did_document::*;
use crate::errors::*;
use crate::presentation::*;
use crate::public_key::*;
use crate::resolver::*;
use crate::revocation::*;
use crate::selective_disclosure::*;
use crate::service_endpoint::*;
use crate::trust_graph::*;
use crate::verifier::*;
use std::collections::{BTreeMap, BTreeSet};

// -- helpers --

fn did_alice() -> Did {
    Did::new("alice", "alice001")
}

fn did_bob() -> Did {
    Did::new("alice", "bob002")
}

fn did_carol() -> Did {
    Did::new("alice", "carol003")
}

fn sample_credential(issuer: &Did, subject: &Did) -> VerifiableCredential {
    let mut claims = BTreeMap::new();
    claims.insert("name".to_owned(), "Alice".to_owned());
    claims.insert("age".to_owned(), "30".to_owned());
    claims.insert("active".to_owned(), "true".to_owned());
    VerifiableCredential {
        context: "https://www.w3.org/2018/credentials/v1".to_owned(),
        credential_type: "IdentityCredential".to_owned(),
        issuer: issuer.clone(),
        subject: subject.clone(),
        issued_at: 1000,
        expires_at: Some(5000),
        claims,
        proof: vec![1, 2, 3, 4],
    }
}

// -----------------------------------------------------------------------
// Did
// -----------------------------------------------------------------------

#[test]
fn did_parse_valid() {
    let did = Did::parse("did:example:123").unwrap();
    assert_eq!(did.method, "example");
    assert_eq!(did.id, "123");
}

#[test]
fn did_parse_complex_id() {
    let did = Did::parse("did:web:example.com:path:sub").unwrap();
    assert_eq!(did.method, "web");
    assert_eq!(did.id, "example.com:path:sub");
}

#[test]
fn did_parse_missing_prefix() {
    assert!(Did::parse("example:123").is_err());
}

#[test]
fn did_parse_empty_method() {
    assert!(Did::parse("did::123").is_err());
}

#[test]
fn did_parse_empty_id() {
    assert!(Did::parse("did:example:").is_err());
}

#[test]
fn did_parse_no_colons() {
    assert!(Did::parse("didexample123").is_err());
}

#[test]
fn did_parse_one_colon() {
    assert!(Did::parse("did:example").is_err());
}

#[test]
fn did_to_string() {
    let did = Did::new("alice", "abc");
    assert_eq!(did.to_string(), "did:alice:abc");
}

#[test]
fn did_validate_ok() {
    assert!(did_alice().validate().is_ok());
}

#[test]
fn did_validate_empty_method() {
    let did = Did::new("", "id");
    assert!(did.validate().is_err());
}

#[test]
fn did_validate_empty_id() {
    let did = Did::new("method", "");
    assert!(did.validate().is_err());
}

#[test]
fn did_equality() {
    assert_eq!(Did::new("a", "b"), Did::new("a", "b"));
    assert_ne!(Did::new("a", "b"), Did::new("a", "c"));
}

#[test]
fn did_clone() {
    let d = did_alice();
    let d2 = d.clone();
    assert_eq!(d, d2);
}

#[test]
fn did_hash_consistent() {
    let mut set = BTreeSet::new();
    set.insert(did_alice());
    set.insert(did_alice());
    assert_eq!(set.len(), 1);
}

// -----------------------------------------------------------------------
// DidDocument
// -----------------------------------------------------------------------

#[test]
fn did_document_new() {
    let doc = DidDocument::new(did_alice(), 100);
    assert_eq!(doc.id, did_alice());
    assert_eq!(doc.created, 100);
    assert_eq!(doc.updated, 100);
    assert!(doc.public_keys.is_empty());
    assert!(doc.services.is_empty());
}

#[test]
fn did_document_add_key() {
    let mut doc = DidDocument::new(did_alice(), 100);
    let key = PublicKeyEntry {
        id: "key-1".to_owned(),
        key_type: "Ed25519".to_owned(),
        controller: did_alice(),
        public_key_bytes: vec![0xAB, 0xCD],
    };
    doc.add_public_key(key);
    assert_eq!(doc.public_keys.len(), 1);
    assert_eq!(doc.public_keys[0].id, "key-1");
}

#[test]
fn did_document_add_service() {
    let mut doc = DidDocument::new(did_alice(), 100);
    let svc = ServiceEndpoint {
        id: "svc-1".to_owned(),
        service_type: "Messaging".to_owned(),
        endpoint: "https://example.com/msg".to_owned(),
    };
    doc.add_service(svc);
    assert_eq!(doc.services.len(), 1);
    assert_eq!(doc.services[0].service_type, "Messaging");
}

#[test]
fn did_document_multiple_keys() {
    let mut doc = DidDocument::new(did_alice(), 0);
    for i in 0..5 {
        doc.add_public_key(PublicKeyEntry {
            id: format!("key-{i}"),
            key_type: "Ed25519".to_owned(),
            controller: did_alice(),
            public_key_bytes: vec![i],
        });
    }
    assert_eq!(doc.public_keys.len(), 5);
}

#[test]
fn did_document_multiple_services() {
    let mut doc = DidDocument::new(did_alice(), 0);
    for i in 0..3 {
        doc.add_service(ServiceEndpoint {
            id: format!("svc-{i}"),
            service_type: "Type".to_owned(),
            endpoint: format!("https://example.com/{i}"),
        });
    }
    assert_eq!(doc.services.len(), 3);
}

// -----------------------------------------------------------------------
// VerifiableCredential
// -----------------------------------------------------------------------

#[test]
fn credential_creation() {
    let vc = sample_credential(&did_alice(), &did_bob());
    assert_eq!(vc.issuer, did_alice());
    assert_eq!(vc.subject, did_bob());
    assert_eq!(vc.claims.len(), 3);
}

#[test]
fn credential_no_expiry() {
    let vc = VerifiableCredential {
        context: String::new(),
        credential_type: String::new(),
        issuer: did_alice(),
        subject: did_bob(),
        issued_at: 0,
        expires_at: None,
        claims: BTreeMap::new(),
        proof: vec![1],
    };
    assert!(vc.expires_at.is_none());
}

// -----------------------------------------------------------------------
// VerifiablePresentation
// -----------------------------------------------------------------------

#[test]
fn presentation_creation() {
    let vp = VerifiablePresentation {
        holder: did_alice(),
        credentials: vec![sample_credential(&did_bob(), &did_alice())],
        proof: vec![9, 8, 7],
    };
    assert_eq!(vp.holder, did_alice());
    assert_eq!(vp.credentials.len(), 1);
}

#[test]
fn presentation_multiple_credentials() {
    let vp = VerifiablePresentation {
        holder: did_alice(),
        credentials: vec![
            sample_credential(&did_bob(), &did_alice()),
            sample_credential(&did_carol(), &did_alice()),
        ],
        proof: vec![1],
    };
    assert_eq!(vp.credentials.len(), 2);
}

// -----------------------------------------------------------------------
// CredentialVerifier
// -----------------------------------------------------------------------

#[test]
fn verifier_valid() {
    let mut v = CredentialVerifier::new();
    v.add_trusted_issuer(did_alice());
    let vc = sample_credential(&did_alice(), &did_bob());
    assert!(v.verify(&vc, 2000).is_ok());
}

#[test]
fn verifier_empty_proof() {
    let mut v = CredentialVerifier::new();
    v.add_trusted_issuer(did_alice());
    let mut vc = sample_credential(&did_alice(), &did_bob());
    vc.proof.clear();
    assert_eq!(v.verify(&vc, 2000), Err(IdentityError::InvalidSignature));
}

#[test]
fn verifier_expired() {
    let mut v = CredentialVerifier::new();
    v.add_trusted_issuer(did_alice());
    let vc = sample_credential(&did_alice(), &did_bob());
    assert_eq!(v.verify(&vc, 9999), Err(IdentityError::CredentialExpired));
}

#[test]
fn verifier_untrusted_issuer() {
    let v = CredentialVerifier::new();
    let vc = sample_credential(&did_alice(), &did_bob());
    assert!(matches!(
        v.verify(&vc, 2000),
        Err(IdentityError::UntrustedIssuer(_))
    ));
}

#[test]
fn verifier_no_expiry_ok() {
    let mut v = CredentialVerifier::new();
    v.add_trusted_issuer(did_alice());
    let mut vc = sample_credential(&did_alice(), &did_bob());
    vc.expires_at = None;
    assert!(v.verify(&vc, 999_999).is_ok());
}

#[test]
fn verifier_exact_expiry_boundary() {
    let mut v = CredentialVerifier::new();
    v.add_trusted_issuer(did_alice());
    let vc = sample_credential(&did_alice(), &did_bob());
    // expires_at = 5000, current_time = 5000 => NOT expired (only > is expired)
    assert!(v.verify(&vc, 5000).is_ok());
}

#[test]
fn verifier_default() {
    let v = CredentialVerifier::default();
    let vc = sample_credential(&did_alice(), &did_bob());
    assert!(v.verify(&vc, 0).is_err());
}

// -----------------------------------------------------------------------
// TrustGraph
// -----------------------------------------------------------------------

#[test]
fn trust_graph_direct() {
    let mut g = TrustGraph::new();
    g.add_trust(&did_alice(), &did_bob());
    assert!(g.is_trusted(&did_alice(), &did_bob()));
}

#[test]
fn trust_graph_no_reverse() {
    let mut g = TrustGraph::new();
    g.add_trust(&did_alice(), &did_bob());
    assert!(!g.is_trusted(&did_bob(), &did_alice()));
}

#[test]
fn trust_graph_transitive() {
    let mut g = TrustGraph::new();
    g.add_trust(&did_alice(), &did_bob());
    g.add_trust(&did_bob(), &did_carol());
    assert!(g.is_trusted(&did_alice(), &did_carol()));
}

#[test]
fn trust_graph_no_path() {
    let g = TrustGraph::new();
    assert!(!g.is_trusted(&did_alice(), &did_bob()));
}

#[test]
fn trust_graph_self() {
    let g = TrustGraph::new();
    assert!(g.is_trusted(&did_alice(), &did_alice()));
}

#[test]
fn trust_path_direct() {
    let mut g = TrustGraph::new();
    g.add_trust(&did_alice(), &did_bob());
    let path = g.trust_path(&did_alice(), &did_bob()).unwrap();
    assert_eq!(path.len(), 2);
    assert_eq!(path[0], did_alice());
    assert_eq!(path[1], did_bob());
}

#[test]
fn trust_path_transitive() {
    let mut g = TrustGraph::new();
    g.add_trust(&did_alice(), &did_bob());
    g.add_trust(&did_bob(), &did_carol());
    let path = g.trust_path(&did_alice(), &did_carol()).unwrap();
    assert_eq!(path.len(), 3);
}

#[test]
fn trust_path_none() {
    let g = TrustGraph::new();
    assert!(g.trust_path(&did_alice(), &did_bob()).is_none());
}

#[test]
fn trust_graph_remove() {
    let mut g = TrustGraph::new();
    g.add_trust(&did_alice(), &did_bob());
    g.remove_trust(&did_alice(), &did_bob());
    assert!(!g.is_trusted(&did_alice(), &did_bob()));
}

#[test]
fn trust_graph_remove_nonexistent() {
    let mut g = TrustGraph::new();
    g.remove_trust(&did_alice(), &did_bob()); // no panic
}

#[test]
fn trust_graph_trustees_of() {
    let mut g = TrustGraph::new();
    g.add_trust(&did_alice(), &did_bob());
    g.add_trust(&did_alice(), &did_carol());
    let ts = g.trustees_of(&did_alice());
    assert_eq!(ts.len(), 2);
}

#[test]
fn trust_graph_trustees_of_empty() {
    let g = TrustGraph::new();
    assert!(g.trustees_of(&did_alice()).is_empty());
}

#[test]
fn trust_graph_default() {
    let g = TrustGraph::default();
    assert!(!g.is_trusted(&did_alice(), &did_bob()));
}

#[test]
fn trust_graph_cycle() {
    let mut g = TrustGraph::new();
    g.add_trust(&did_alice(), &did_bob());
    g.add_trust(&did_bob(), &did_carol());
    g.add_trust(&did_carol(), &did_alice());
    assert!(g.is_trusted(&did_alice(), &did_carol()));
    assert!(g.is_trusted(&did_carol(), &did_bob()));
}

#[test]
fn trust_graph_duplicate_edge() {
    let mut g = TrustGraph::new();
    g.add_trust(&did_alice(), &did_bob());
    g.add_trust(&did_alice(), &did_bob());
    assert_eq!(g.trustees_of(&did_alice()).len(), 1);
}

// -----------------------------------------------------------------------
// DidResolver
// -----------------------------------------------------------------------

#[test]
fn resolver_register_and_resolve() {
    let mut r = DidResolver::new();
    let doc = DidDocument::new(did_alice(), 100);
    r.register(doc).unwrap();
    let resolved = r.resolve(&did_alice()).unwrap();
    assert_eq!(resolved.id, did_alice());
}

#[test]
fn resolver_duplicate_register() {
    let mut r = DidResolver::new();
    r.register(DidDocument::new(did_alice(), 100)).unwrap();
    assert!(r.register(DidDocument::new(did_alice(), 200)).is_err());
}

#[test]
fn resolver_not_found() {
    let r = DidResolver::new();
    assert!(matches!(
        r.resolve(&did_alice()),
        Err(IdentityError::DocumentNotFound(_))
    ));
}

#[test]
fn resolver_update() {
    let mut r = DidResolver::new();
    r.register(DidDocument::new(did_alice(), 100)).unwrap();
    let mut updated = DidDocument::new(did_alice(), 100);
    updated.updated = 200;
    r.update(updated).unwrap();
    assert_eq!(r.resolve(&did_alice()).unwrap().updated, 200);
}

#[test]
fn resolver_update_not_found() {
    let mut r = DidResolver::new();
    assert!(r.update(DidDocument::new(did_alice(), 100)).is_err());
}

#[test]
fn resolver_deactivate() {
    let mut r = DidResolver::new();
    r.register(DidDocument::new(did_alice(), 100)).unwrap();
    r.deactivate(&did_alice()).unwrap();
    assert!(r.is_deactivated(&did_alice()));
    assert!(matches!(
        r.resolve(&did_alice()),
        Err(IdentityError::DocumentDeactivated(_))
    ));
}

#[test]
fn resolver_deactivate_not_found() {
    let mut r = DidResolver::new();
    assert!(r.deactivate(&did_alice()).is_err());
}

#[test]
fn resolver_update_deactivated() {
    let mut r = DidResolver::new();
    r.register(DidDocument::new(did_alice(), 100)).unwrap();
    r.deactivate(&did_alice()).unwrap();
    assert!(r.update(DidDocument::new(did_alice(), 200)).is_err());
}

#[test]
fn resolver_default() {
    let r = DidResolver::default();
    assert!(r.resolve(&did_alice()).is_err());
}

#[test]
fn resolver_multiple_documents() {
    let mut r = DidResolver::new();
    r.register(DidDocument::new(did_alice(), 100)).unwrap();
    r.register(DidDocument::new(did_bob(), 200)).unwrap();
    assert!(r.resolve(&did_alice()).is_ok());
    assert!(r.resolve(&did_bob()).is_ok());
}

// -----------------------------------------------------------------------
// RevocationRegistry
// -----------------------------------------------------------------------

#[test]
fn revocation_revoke_and_check() {
    let mut reg = RevocationRegistry::new();
    reg.revoke("cred-001");
    assert!(reg.is_revoked("cred-001"));
}

#[test]
fn revocation_not_revoked() {
    let reg = RevocationRegistry::new();
    assert!(!reg.is_revoked("cred-001"));
}

#[test]
fn revocation_restore() {
    let mut reg = RevocationRegistry::new();
    reg.revoke("cred-001");
    reg.restore("cred-001");
    assert!(!reg.is_revoked("cred-001"));
}

#[test]
fn revocation_count() {
    let mut reg = RevocationRegistry::new();
    reg.revoke("a");
    reg.revoke("b");
    reg.revoke("c");
    assert_eq!(reg.count(), 3);
}

#[test]
fn revocation_duplicate_revoke() {
    let mut reg = RevocationRegistry::new();
    reg.revoke("a");
    reg.revoke("a");
    assert_eq!(reg.count(), 1);
}

#[test]
fn revocation_default() {
    let reg = RevocationRegistry::default();
    assert_eq!(reg.count(), 0);
}

#[test]
fn revocation_restore_non_existent() {
    let mut reg = RevocationRegistry::new();
    reg.restore("nothing"); // no panic
    assert_eq!(reg.count(), 0);
}

// -----------------------------------------------------------------------
// ClaimSchema
// -----------------------------------------------------------------------

#[test]
fn schema_validate_ok() {
    let mut schema = ClaimSchema::new();
    schema.add_required_field("name", "string");
    schema.add_required_field("age", "integer");
    let mut claims = BTreeMap::new();
    claims.insert("name".to_owned(), "Alice".to_owned());
    claims.insert("age".to_owned(), "30".to_owned());
    assert!(schema.validate(&claims).is_ok());
}

#[test]
fn schema_missing_required() {
    let mut schema = ClaimSchema::new();
    schema.add_required_field("name", "string");
    let claims = BTreeMap::new();
    assert!(matches!(
        schema.validate(&claims),
        Err(IdentityError::ClaimNotFound(_))
    ));
}

#[test]
fn schema_invalid_integer() {
    let mut schema = ClaimSchema::new();
    schema.add_required_field("age", "integer");
    let mut claims = BTreeMap::new();
    claims.insert("age".to_owned(), "not_a_number".to_owned());
    assert!(matches!(
        schema.validate(&claims),
        Err(IdentityError::InvalidClaimType { .. })
    ));
}

#[test]
fn schema_boolean_valid() {
    let mut schema = ClaimSchema::new();
    schema.add_required_field("active", "boolean");
    let mut claims = BTreeMap::new();
    claims.insert("active".to_owned(), "true".to_owned());
    assert!(schema.validate(&claims).is_ok());
}

#[test]
fn schema_boolean_invalid() {
    let mut schema = ClaimSchema::new();
    schema.add_required_field("active", "boolean");
    let mut claims = BTreeMap::new();
    claims.insert("active".to_owned(), "yes".to_owned());
    assert!(schema.validate(&claims).is_err());
}

#[test]
fn schema_date_valid() {
    let mut schema = ClaimSchema::new();
    schema.add_required_field("dob", "date");
    let mut claims = BTreeMap::new();
    claims.insert("dob".to_owned(), "1990-01-15".to_owned());
    assert!(schema.validate(&claims).is_ok());
}

#[test]
fn schema_date_invalid() {
    let mut schema = ClaimSchema::new();
    schema.add_required_field("dob", "date");
    let mut claims = BTreeMap::new();
    claims.insert("dob".to_owned(), "January".to_owned());
    assert!(schema.validate(&claims).is_err());
}

#[test]
fn schema_optional_field_present() {
    let mut schema = ClaimSchema::new();
    schema.add_required_field("name", "string");
    schema.add_optional_field("nickname", "string");
    let mut claims = BTreeMap::new();
    claims.insert("name".to_owned(), "Alice".to_owned());
    claims.insert("nickname".to_owned(), "Ali".to_owned());
    assert!(schema.validate(&claims).is_ok());
}

#[test]
fn schema_optional_field_absent() {
    let mut schema = ClaimSchema::new();
    schema.add_required_field("name", "string");
    schema.add_optional_field("nickname", "string");
    let mut claims = BTreeMap::new();
    claims.insert("name".to_owned(), "Alice".to_owned());
    assert!(schema.validate(&claims).is_ok());
}

#[test]
fn schema_unknown_type_passes() {
    let mut schema = ClaimSchema::new();
    schema.add_required_field("data", "custom");
    let mut claims = BTreeMap::new();
    claims.insert("data".to_owned(), "anything".to_owned());
    assert!(schema.validate(&claims).is_ok());
}

#[test]
fn schema_extra_claims_ok() {
    let mut schema = ClaimSchema::new();
    schema.add_required_field("name", "string");
    let mut claims = BTreeMap::new();
    claims.insert("name".to_owned(), "Alice".to_owned());
    claims.insert("extra".to_owned(), "value".to_owned());
    assert!(schema.validate(&claims).is_ok());
}

#[test]
fn schema_default() {
    let schema = ClaimSchema::default();
    assert!(schema.required_fields.is_empty());
    assert!(schema.field_types.is_empty());
}

// -----------------------------------------------------------------------
// SelectiveDisclosure
// -----------------------------------------------------------------------

#[test]
fn disclosure_subset() {
    let vc = sample_credential(&did_alice(), &did_bob());
    let disclosed = SelectiveDisclosure::disclose(&vc, &["name"]).unwrap();
    assert_eq!(disclosed.claims.len(), 1);
    assert_eq!(disclosed.claims.get("name").unwrap(), "Alice");
}

#[test]
fn disclosure_all_fields() {
    let vc = sample_credential(&did_alice(), &did_bob());
    let disclosed = SelectiveDisclosure::disclose(&vc, &["name", "age", "active"]).unwrap();
    assert_eq!(disclosed.claims.len(), 3);
}

#[test]
fn disclosure_empty_fields() {
    let vc = sample_credential(&did_alice(), &did_bob());
    let disclosed = SelectiveDisclosure::disclose(&vc, &[]).unwrap();
    assert!(disclosed.claims.is_empty());
}

#[test]
fn disclosure_missing_field() {
    let vc = sample_credential(&did_alice(), &did_bob());
    assert!(matches!(
        SelectiveDisclosure::disclose(&vc, &["nonexistent"]),
        Err(IdentityError::ClaimNotFound(_))
    ));
}

#[test]
fn disclosure_preserves_metadata() {
    let vc = sample_credential(&did_alice(), &did_bob());
    let disclosed = SelectiveDisclosure::disclose(&vc, &["name"]).unwrap();
    assert_eq!(disclosed.issuer, vc.issuer);
    assert_eq!(disclosed.subject, vc.subject);
    assert_eq!(disclosed.issued_at, vc.issued_at);
    assert_eq!(disclosed.expires_at, vc.expires_at);
    assert_eq!(disclosed.proof, vc.proof);
}

// -----------------------------------------------------------------------
// IdentityError Display
// -----------------------------------------------------------------------

#[test]
fn error_display_invalid_did() {
    let e = IdentityError::InvalidDid("bad".to_owned());
    assert_eq!(e.to_string(), "invalid DID: bad");
}

#[test]
fn error_display_not_found() {
    let e = IdentityError::DocumentNotFound("did:x:y".to_owned());
    assert!(e.to_string().contains("not found"));
}

#[test]
fn error_display_already_exists() {
    let e = IdentityError::DocumentAlreadyExists("did:x:y".to_owned());
    assert!(e.to_string().contains("already exists"));
}

#[test]
fn error_display_deactivated() {
    let e = IdentityError::DocumentDeactivated("did:x:y".to_owned());
    assert!(e.to_string().contains("deactivated"));
}

#[test]
fn error_display_expired() {
    let e = IdentityError::CredentialExpired;
    assert!(e.to_string().contains("expired"));
}

#[test]
fn error_display_revoked() {
    let e = IdentityError::CredentialRevoked("c1".to_owned());
    assert!(e.to_string().contains("revoked"));
}

#[test]
fn error_display_invalid_signature() {
    let e = IdentityError::InvalidSignature;
    assert!(e.to_string().contains("signature"));
}

#[test]
fn error_display_untrusted() {
    let e = IdentityError::UntrustedIssuer("did:x:y".to_owned());
    assert!(e.to_string().contains("untrusted"));
}

#[test]
fn error_display_schema() {
    let e = IdentityError::SchemaValidation("bad".to_owned());
    assert!(e.to_string().contains("schema"));
}

#[test]
fn error_display_claim_not_found() {
    let e = IdentityError::ClaimNotFound("f".to_owned());
    assert!(e.to_string().contains("claim"));
}

#[test]
fn error_display_invalid_claim_type() {
    let e = IdentityError::InvalidClaimType {
        field: "age".to_owned(),
        expected: "integer".to_owned(),
    };
    assert!(e.to_string().contains("age"));
}

#[test]
fn error_clone_and_eq() {
    let e1 = IdentityError::CredentialExpired;
    let e2 = e1.clone();
    assert_eq!(e1, e2);
}

#[test]
fn error_debug() {
    let e = IdentityError::InvalidSignature;
    let dbg = format!("{e:?}");
    assert!(dbg.contains("InvalidSignature"));
}

// -----------------------------------------------------------------------
// Integration: full flow
// -----------------------------------------------------------------------

#[test]
fn integration_full_identity_flow() {
    // 1. Create DIDs
    let issuer = Did::parse("did:alice:issuer001").unwrap();
    let holder = Did::parse("did:alice:holder002").unwrap();

    // 2. Register DID documents
    let mut resolver = DidResolver::new();
    let mut issuer_doc = DidDocument::new(issuer.clone(), 1000);
    issuer_doc.add_public_key(PublicKeyEntry {
        id: "key-1".to_owned(),
        key_type: "Ed25519".to_owned(),
        controller: issuer.clone(),
        public_key_bytes: vec![0xDE, 0xAD],
    });
    resolver.register(issuer_doc).unwrap();
    resolver
        .register(DidDocument::new(holder.clone(), 1000))
        .unwrap();

    // 3. Build trust graph
    let mut trust = TrustGraph::new();
    trust.add_trust(&holder, &issuer);

    // 4. Issue credential
    let mut claims = BTreeMap::new();
    claims.insert("degree".to_owned(), "PhD".to_owned());
    claims.insert("field".to_owned(), "Computer Science".to_owned());
    let vc = VerifiableCredential {
        context: "https://www.w3.org/2018/credentials/v1".to_owned(),
        credential_type: "DegreeCredential".to_owned(),
        issuer: issuer.clone(),
        subject: holder.clone(),
        issued_at: 2000,
        expires_at: Some(10000),
        claims,
        proof: vec![1, 2, 3],
    };

    // 5. Verify
    let mut verifier = CredentialVerifier::new();
    verifier.add_trusted_issuer(issuer.clone());
    assert!(verifier.verify(&vc, 3000).is_ok());

    // 6. Selective disclosure
    let disclosed = SelectiveDisclosure::disclose(&vc, &["degree"]).unwrap();
    assert_eq!(disclosed.claims.len(), 1);
    assert!(!disclosed.claims.contains_key("field"));

    // 7. Trust path
    assert!(trust.is_trusted(&holder, &issuer));
}

#[test]
fn integration_revocation_flow() {
    let mut registry = RevocationRegistry::new();
    let cred_id = "vc-abc-123";

    assert!(!registry.is_revoked(cred_id));
    registry.revoke(cred_id);
    assert!(registry.is_revoked(cred_id));
    registry.restore(cred_id);
    assert!(!registry.is_revoked(cred_id));
}

#[test]
fn integration_schema_and_credential() {
    let mut schema = ClaimSchema::new();
    schema.add_required_field("name", "string");
    schema.add_required_field("age", "integer");
    schema.add_optional_field("email", "string");

    let vc = sample_credential(&did_alice(), &did_bob());
    assert!(schema.validate(&vc.claims).is_ok());
}

#[test]
fn integration_resolver_lifecycle() {
    let mut r = DidResolver::new();
    let did = did_alice();

    // Register
    r.register(DidDocument::new(did.clone(), 100)).unwrap();
    assert!(r.resolve(&did).is_ok());

    // Update
    let mut doc2 = DidDocument::new(did.clone(), 100);
    doc2.updated = 200;
    doc2.add_service(ServiceEndpoint {
        id: "svc".to_owned(),
        service_type: "Auth".to_owned(),
        endpoint: "https://auth.example.com".to_owned(),
    });
    r.update(doc2).unwrap();
    assert_eq!(r.resolve(&did).unwrap().services.len(), 1);

    // Deactivate
    r.deactivate(&did).unwrap();
    assert!(r.resolve(&did).is_err());
}

#[test]
fn did_parse_roundtrip() {
    let original = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    let did = Did::parse(original).unwrap();
    assert_eq!(did.to_string(), original);
}

#[test]
fn did_inequality_method() {
    assert_ne!(Did::new("web", "x"), Did::new("key", "x"));
}

#[test]
fn verifier_multiple_trusted_issuers() {
    let mut v = CredentialVerifier::new();
    v.add_trusted_issuer(did_alice());
    v.add_trusted_issuer(did_bob());
    let vc = sample_credential(&did_bob(), &did_carol());
    assert!(v.verify(&vc, 2000).is_ok());
}

#[test]
fn revocation_many_ids() {
    let mut reg = RevocationRegistry::new();
    for i in 0..50 {
        reg.revoke(&format!("cred-{i}"));
    }
    assert_eq!(reg.count(), 50);
    assert!(reg.is_revoked("cred-25"));
    assert!(!reg.is_revoked("cred-999"));
}

#[test]
fn schema_negative_integer_valid() {
    let mut schema = ClaimSchema::new();
    schema.add_required_field("score", "integer");
    let mut claims = BTreeMap::new();
    claims.insert("score".to_owned(), "-42".to_owned());
    assert!(schema.validate(&claims).is_ok());
}

#[test]
fn schema_boolean_false_valid() {
    let mut schema = ClaimSchema::new();
    schema.add_required_field("flag", "boolean");
    let mut claims = BTreeMap::new();
    claims.insert("flag".to_owned(), "false".to_owned());
    assert!(schema.validate(&claims).is_ok());
}

#[test]
fn integration_trust_graph_complex() {
    let d1 = Did::new("alice", "d1");
    let d2 = Did::new("alice", "d2");
    let d3 = Did::new("alice", "d3");
    let d4 = Did::new("alice", "d4");
    let d5 = Did::new("alice", "d5");

    let mut g = TrustGraph::new();
    g.add_trust(&d1, &d2);
    g.add_trust(&d2, &d3);
    g.add_trust(&d3, &d4);
    g.add_trust(&d4, &d5);

    // Transitive trust across 4 hops
    assert!(g.is_trusted(&d1, &d5));
    let path = g.trust_path(&d1, &d5).unwrap();
    assert_eq!(path.len(), 5);

    // No reverse
    assert!(!g.is_trusted(&d5, &d1));

    // Remove middle edge breaks chain
    g.remove_trust(&d2, &d3);
    assert!(!g.is_trusted(&d1, &d5));
}
