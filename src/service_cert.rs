//! Service certificates: an operator's master key vouches for the signing key and the Noise static key
//! of a network service (for example a relay) for a bounded time.
//!
//! A service certificate is a [`DeviceCert`] (the same version 3 layout, context and signature) whose
//! subject is a reserved DID of the method [`SERVICE_DID_METHOD`]:
//!
//! ```text
//! subject = did:alice-service:<service>
//! ```
//!
//! No new byte layout is introduced: a client that already reads device certificates reads service
//! certificates, and the subject is what tells the two apart. [`verify_service_cert`] refuses a
//! certificate whose subject is not the expected service, so a device certificate of a person
//! (`did:alice:...`, `did:key:...`) is never accepted as the key of a service, and the certificate of
//! one service is never accepted for another.
//!
//! # Service names
//!
//! `<service>` is 1 to [`MAX_SERVICE_NAME_LEN`] bytes of lowercase ASCII letters (`a`-`z`), digits
//! (`0`-`9`) and `-`, and neither starts nor ends with `-` (the rule of a DNS label, in lowercase only).
//! Any other name is refused as [`ServiceCertError::BadServiceName`], at issue and at verification.
//! Because the name has no upper case, no `:` and no other character, one service has exactly one
//! subject text, and so one [`crate::device_cert::DeviceId`] per key.
//!
//! # Lifetime and renewal
//!
//! A service certificate is valid for at most [`SERVICE_CERT_MAX_LIFETIME_SECS`] (30 days) from
//! `issued_at` to `not_after`. [`issue_service_cert`] refuses a longer one and [`verify_service_cert`]
//! refuses a certificate whose `not_after - issued_at` is over it, whoever signed it. The validity
//! window itself is the device certificate's: `issued_at <= now + MAX_CLOCK_SKEW_SECS` and
//! `now < not_after` ([`DeviceCert::verify`]).
//!
//! To renew, the operator issues a new certificate for the same service with the same signing key and
//! Noise static key and a later validity. Its [`crate::device_cert::DeviceId`] is derived from the
//! subject and the signing key only, so the renewal keeps the same id, and a revocation of that id
//! retires every certificate of that key for that service, renewals included.
//!
//! # The master key
//!
//! The `master` that signs service certificates is the operator's offline key. It is never deployed
//! with the service: the service holds only its signing key and its Noise static key, and receives
//! each renewed certificate from the operator.

use crate::artifact::Revocation;
use crate::device_cert::{DeviceCert, DeviceCertError};
use crate::did::Did;
use alice_sign::{KeyPair, PublicKey};
use std::fmt;

/// The DID method reserved for services: a service's subject is `did:alice-service:<service>`
pub const SERVICE_DID_METHOD: &str = "alice-service";

/// The longest service name, in bytes (the length of a DNS label)
pub const MAX_SERVICE_NAME_LEN: usize = 63;

/// The longest a service certificate is valid, `not_after - issued_at`, in seconds (30 days)
pub const SERVICE_CERT_MAX_LIFETIME_SECS: u64 = 30 * 86_400;

/// Why a service certificate was not issued or accepted
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceCertError {
    /// The certificate itself was not issued or does not verify (issuer, signature, validity window)
    Cert(DeviceCertError),
    /// The service name breaks the rule in the module documentation
    BadServiceName,
    /// The subject is a service DID of another service than the expected one
    WrongService,
    /// The subject is not a service DID (another method than [`SERVICE_DID_METHOD`])
    NotAService,
    /// `not_after - issued_at` is over [`SERVICE_CERT_MAX_LIFETIME_SECS`] (the lifetime is given)
    LifetimeTooLong(u64),
    /// The issuer's newest revocation list revokes the certificate's device id
    Revoked,
}

impl fmt::Display for ServiceCertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cert(e) => write!(f, "service certificate: {e}"),
            Self::BadServiceName => write!(
                f,
                "service name is not 1 to {MAX_SERVICE_NAME_LEN} bytes of a-z, 0-9 and '-' (not at either end)"
            ),
            Self::WrongService => write!(f, "service certificate is for another service"),
            Self::NotAService => write!(f, "certificate subject is not a service DID"),
            Self::LifetimeTooLong(secs) => write!(
                f,
                "service certificate lifetime {secs} s is over {SERVICE_CERT_MAX_LIFETIME_SECS} s"
            ),
            Self::Revoked => write!(f, "service certificate is revoked"),
        }
    }
}

impl std::error::Error for ServiceCertError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cert(e) => Some(e),
            _ => None,
        }
    }
}

impl From<DeviceCertError> for ServiceCertError {
    fn from(e: DeviceCertError) -> Self {
        Self::Cert(e)
    }
}

/// Whether `service` follows the service name rule (see the module documentation)
fn valid_service_name(service: &str) -> bool {
    let b = service.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_SERVICE_NAME_LEN
        && b.first() != Some(&b'-')
        && b.last() != Some(&b'-')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// The subject of `service`'s certificates: `did:alice-service:<service>`
///
/// # Errors
/// [`ServiceCertError::BadServiceName`] when `service` breaks the service name rule
pub fn service_subject(service: &str) -> Result<Did, ServiceCertError> {
    if !valid_service_name(service) {
        return Err(ServiceCertError::BadServiceName);
    }
    Ok(Did::new(SERVICE_DID_METHOD, service))
}

/// Sign a certificate for `service`'s signing key `signing_public` and Noise static key `noise_static`
/// with the operator's master key
///
/// `master` is the operator's offline key; it is never deployed with the service (see the module
/// documentation).
///
/// # Errors
/// In this order: [`ServiceCertError::BadServiceName`],
/// [`ServiceCertError::LifetimeTooLong`] when `not_after - issued_at` is over
/// [`SERVICE_CERT_MAX_LIFETIME_SECS`], [`ServiceCertError::Cert`] with
/// [`DeviceCertError::InvalidValidity`] when `not_after <= issued_at`
pub fn issue_service_cert(
    master: &KeyPair,
    service: &str,
    signing_public: [u8; 32],
    noise_static: [u8; 32],
    issued_at: u64,
    not_after: u64,
) -> Result<DeviceCert, ServiceCertError> {
    let subject = service_subject(service)?;
    let lifetime = not_after.saturating_sub(issued_at);
    if lifetime > SERVICE_CERT_MAX_LIFETIME_SECS {
        return Err(ServiceCertError::LifetimeTooLong(lifetime));
    }
    Ok(DeviceCert::issue(
        master,
        &subject,
        signing_public,
        noise_static,
        issued_at,
        not_after,
    )?)
}

/// Accept `cert` as `service`'s certificate from `master` at `now`, and return the service's Noise
/// static key
///
/// The checks run in this order and the first failing one is returned:
///
/// 1. `service` follows the service name rule ([`ServiceCertError::BadServiceName`]);
/// 2. the certificate verifies under `master` at `now` ([`DeviceCert::verify`]: version, issuer,
///    signature, validity window; [`ServiceCertError::Cert`]);
/// 3. its subject is a service DID ([`ServiceCertError::NotAService`]) and is exactly
///    the subject [`service_subject`] gives for `service` ([`ServiceCertError::WrongService`]);
/// 4. `not_after - issued_at` is at most [`SERVICE_CERT_MAX_LIFETIME_SECS`]
///    ([`ServiceCertError::LifetimeTooLong`]);
/// 5. `revocation` does not revoke it ([`ServiceCertError::Revoked`]).
///
/// The signature is checked before anything the certificate states is acted on, so the subject and
/// the times that steps 3 and 4 read are the ones `master` signed.
///
/// # Errors
/// See the order above
pub fn verify_service_cert(
    cert: &DeviceCert,
    master: &PublicKey,
    service: &str,
    now: u64,
    revocation: Revocation<'_>,
) -> Result<[u8; 32], ServiceCertError> {
    let expected = service_subject(service)?;
    cert.verify(master, now)?;
    if cert.subject().method != SERVICE_DID_METHOD {
        return Err(ServiceCertError::NotAService);
    }
    if *cert.subject() != expected {
        return Err(ServiceCertError::WrongService);
    }
    // `verify` holds `issued_at <= now + skew < not_after + skew`, but not `issued_at < not_after`
    // for a certificate decoded from bytes, hence the saturating difference
    let lifetime = cert.not_after().saturating_sub(cert.issued_at());
    if lifetime > SERVICE_CERT_MAX_LIFETIME_SECS {
        return Err(ServiceCertError::LifetimeTooLong(lifetime));
    }
    if let Revocation::Checked(list) = revocation {
        if list.revokes(cert) {
            return Err(ServiceCertError::Revoked);
        }
    }
    Ok(*cert.noise_static())
}
