//! ALICE-Identity: DID + Verifiable Credentials.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(
    clippy::module_name_repetitions,
    clippy::doc_markdown,
    clippy::wildcard_imports,
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::similar_names,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless,
    clippy::return_self_not_must_use
)]

pub mod artifact;
pub mod base58;
pub mod cert_revocation;
pub mod claim_schema;
pub mod credential;
pub mod device_cert;
pub mod did;
pub mod did_document;
pub mod errors;
pub mod jws;
pub mod master_key;
pub mod prelude;
pub mod presentation;
pub mod public_key;
pub mod resolver;
pub mod revocation;
pub mod selective_disclosure;
pub mod semantics;
pub mod service_endpoint;
pub mod signed_did;
pub mod trust_graph;
pub mod verifier;

#[cfg(test)]
mod integration_tests;

pub use crate::claim_schema::*;
pub use crate::credential::*;
pub use crate::did::*;
pub use crate::did_document::*;
pub use crate::errors::*;
pub use crate::presentation::*;
pub use crate::public_key::*;
pub use crate::resolver::*;
pub use crate::revocation::*;
pub use crate::selective_disclosure::*;
pub use crate::service_endpoint::*;
pub use crate::trust_graph::*;
pub use crate::verifier::*;
