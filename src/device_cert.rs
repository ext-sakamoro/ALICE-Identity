//! Device certificates: a master key vouches for one device key, and the device's Noise static
//! key, of the same identity for a bounded time.
//!
//! The certificate is fixed width apart from the subject DID, encoded as one canonical byte
//! layout and signed with a context prefix, so a signature over other data under the same
//! master key (a [`crate::signed_did::SignedClaim`], a revocation list) is never accepted as a
//! certificate:
//!
//! ```text
//! signed = DEVICE_CERT_CONTEXT || body
//! body   = version (1) || subject length (u16 BE) || subject (UTF-8, `did:method:id`)
//!          || device_public (32) || noise_static (32) || issued_at (u64 BE) || not_after (u64 BE)
//!          || cert_id (16) || issuer_public (32)
//! bytes  = body || signature (64)
//! ```
//!
//! The certificate is valid for `issued_at <= now < not_after`; the caller passes `now` (this
//! crate reads no clock) and supplies `cert_id` (this crate draws no random numbers).

use crate::did::Did;
use alice_sign::{KeyPair, PublicKey, Signature};
use std::fmt;

/// The only certificate layout this version reads and writes (version 1, without the Noise static
/// key, is refused as [`DeviceCertError::UnsupportedVersion`])
pub const DEVICE_CERT_VERSION: u8 = 2;

/// Prefixed to the body before signing (domain separation)
pub const DEVICE_CERT_CONTEXT: &[u8] = b"alice-identity device-cert v2";

/// A master key's statement that `device_public` (the signing key) and `noise_static` (the X25519
/// static key of the device's Noise handshakes) belong to `subject` for a bounded time
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCert {
    version: u8,
    subject: Did,
    device_public: [u8; 32],
    noise_static: [u8; 32],
    issued_at: u64,
    not_after: u64,
    cert_id: [u8; 16],
    issuer_public: [u8; 32],
    signature: [u8; 64],
}

/// Why a certificate was not issued, decoded or accepted
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceCertError {
    /// The layout version is not [`DEVICE_CERT_VERSION`]
    UnsupportedVersion(u8),
    /// The bytes do not hold one whole certificate (the reason names the field)
    Malformed(&'static str),
    /// The subject is not a DID whose `did:method:id` text reads back as the same DID
    InvalidSubject,
    /// `not_after` is not after `issued_at`
    InvalidValidity,
    /// The certificate names another issuer than the master key it is checked against
    IssuerMismatch,
    /// The signature does not verify (strictly) over the context and the body
    BadSignature,
    /// `now` is before `issued_at`
    NotYetValid { now: u64, issued_at: u64 },
    /// `now` is at or after `not_after`
    Expired { now: u64, not_after: u64 },
}

impl fmt::Display for DeviceCertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported device certificate version {v}"),
            Self::Malformed(what) => write!(f, "malformed device certificate: {what}"),
            Self::InvalidSubject => write!(f, "device certificate subject is not a canonical DID"),
            Self::InvalidValidity => {
                write!(f, "device certificate not_after is not after issued_at")
            }
            Self::IssuerMismatch => {
                write!(
                    f,
                    "device certificate issuer is not the expected master key"
                )
            }
            Self::BadSignature => write!(f, "device certificate signature does not verify"),
            Self::NotYetValid { now, issued_at } => {
                write!(
                    f,
                    "device certificate not yet valid at {now} (issued at {issued_at})"
                )
            }
            Self::Expired { now, not_after } => {
                write!(f, "device certificate expired at {not_after} (now {now})")
            }
        }
    }
}

impl std::error::Error for DeviceCertError {}

/// Bytes after the subject: device key, Noise static key, two times, id and issuer key
const TAIL: usize = 32 + 32 + 8 + 8 + 16 + 32;
const SIGNATURE: usize = 64;

/// The subject as stored: `did:method:id`, accepted only when it parses back to the same DID
fn canonical_subject(subject: &Did) -> Result<String, DeviceCertError> {
    let text = subject.to_string();
    match Did::parse(&text) {
        Ok(back) if back == *subject && u16::try_from(text.len()).is_ok() => Ok(text),
        _ => Err(DeviceCertError::InvalidSubject),
    }
}

impl DeviceCert {
    /// Sign a certificate for `device_public` and `noise_static` under `subject` with the master key
    ///
    /// # Errors
    /// [`DeviceCertError::InvalidValidity`] when `not_after <= issued_at`,
    /// [`DeviceCertError::InvalidSubject`] when the subject does not round-trip as text
    pub fn issue(
        master: &KeyPair,
        subject: &Did,
        device_public: [u8; 32],
        noise_static: [u8; 32],
        issued_at: u64,
        not_after: u64,
        cert_id: [u8; 16],
    ) -> Result<Self, DeviceCertError> {
        if not_after <= issued_at {
            return Err(DeviceCertError::InvalidValidity);
        }
        canonical_subject(subject)?;
        let mut cert = Self {
            version: DEVICE_CERT_VERSION,
            subject: subject.clone(),
            device_public,
            noise_static,
            issued_at,
            not_after,
            cert_id,
            issuer_public: master.public().0,
            signature: [0; SIGNATURE],
        };
        cert.signature = master.sign(&cert.signed_message()).0;
        Ok(cert)
    }

    /// The body: everything the signature covers after the context
    fn body(&self) -> Vec<u8> {
        let subject = self.subject.to_string();
        // a certificate is built only by `issue` and `from_bytes`, which both bound the subject
        let len = u16::try_from(subject.len()).expect("subject length checked on construction");
        let mut b = Vec::with_capacity(1 + 2 + subject.len() + TAIL);
        b.extend_from_slice(&[self.version]);
        b.extend_from_slice(&len.to_be_bytes());
        b.extend_from_slice(subject.as_bytes());
        b.extend_from_slice(&self.device_public);
        b.extend_from_slice(&self.noise_static);
        b.extend_from_slice(&self.issued_at.to_be_bytes());
        b.extend_from_slice(&self.not_after.to_be_bytes());
        b.extend_from_slice(&self.cert_id);
        b.extend_from_slice(&self.issuer_public);
        b
    }

    /// The bytes the signature covers: [`DEVICE_CERT_CONTEXT`] followed by the body
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        let mut m = DEVICE_CERT_CONTEXT.to_vec();
        m.extend_from_slice(&self.body());
        m
    }

    /// The canonical encoding: the body followed by the signature
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.signature);
        b
    }

    /// Decode a certificate (the signature is not checked here; see [`DeviceCert::verify`])
    ///
    /// # Errors
    /// [`DeviceCertError::Malformed`] for a short or long input or a bad subject length,
    /// [`DeviceCertError::UnsupportedVersion`], [`DeviceCertError::InvalidSubject`]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DeviceCertError> {
        let (&version, rest) = bytes
            .split_first()
            .ok_or(DeviceCertError::Malformed("version"))?;
        if version != DEVICE_CERT_VERSION {
            return Err(DeviceCertError::UnsupportedVersion(version));
        }
        let (len, rest) = rest
            .split_first_chunk::<2>()
            .ok_or(DeviceCertError::Malformed("subject length"))?;
        let len = usize::from(u16::from_be_bytes(*len));
        if rest.len() < len {
            return Err(DeviceCertError::Malformed("subject"));
        }
        let (subject, rest) = rest.split_at(len);
        if rest.len() != TAIL + SIGNATURE {
            return Err(DeviceCertError::Malformed("length after the subject"));
        }
        let text = std::str::from_utf8(subject).map_err(|_| DeviceCertError::InvalidSubject)?;
        // any text `Did::parse` accepts displays back as the same text (it splits on the first
        // two colons and `Display` joins them again), so the stored subject is canonical here;
        // the round trip that can fail is a `Did` built field by field, checked in `issue`
        let subject = Did::parse(text).map_err(|_| DeviceCertError::InvalidSubject)?;
        let field = |at: usize, n: usize| &rest[at..at + n];
        let u64_at = |at: usize| u64::from_be_bytes(field(at, 8).try_into().expect("8 bytes"));
        Ok(Self {
            version,
            subject,
            device_public: field(0, 32).try_into().expect("32 bytes"),
            noise_static: field(32, 32).try_into().expect("32 bytes"),
            issued_at: u64_at(64),
            not_after: u64_at(72),
            cert_id: field(80, 16).try_into().expect("16 bytes"),
            issuer_public: field(96, 32).try_into().expect("32 bytes"),
            signature: field(128, SIGNATURE).try_into().expect("64 bytes"),
        })
    }

    /// Accept the certificate only if it was issued by `master`, its signature verifies strictly
    /// over the context and body, and `issued_at <= now < not_after`
    ///
    /// # Errors
    /// The first failing check, in this order: version, issuer, signature, validity window
    pub fn verify(&self, master: &PublicKey, now: u64) -> Result<(), DeviceCertError> {
        if self.version != DEVICE_CERT_VERSION {
            return Err(DeviceCertError::UnsupportedVersion(self.version));
        }
        if self.issuer_public != master.0 {
            return Err(DeviceCertError::IssuerMismatch);
        }
        if !master.verify_strict(&self.signed_message(), &Signature(self.signature)) {
            return Err(DeviceCertError::BadSignature);
        }
        if now < self.issued_at {
            return Err(DeviceCertError::NotYetValid {
                now,
                issued_at: self.issued_at,
            });
        }
        if now >= self.not_after {
            return Err(DeviceCertError::Expired {
                now,
                not_after: self.not_after,
            });
        }
        Ok(())
    }

    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    #[must_use]
    pub const fn subject(&self) -> &Did {
        &self.subject
    }

    #[must_use]
    pub const fn device_public(&self) -> &[u8; 32] {
        &self.device_public
    }

    /// The X25519 static key of the device's Noise handshakes
    #[must_use]
    pub const fn noise_static(&self) -> &[u8; 32] {
        &self.noise_static
    }

    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    #[must_use]
    pub const fn not_after(&self) -> u64 {
        self.not_after
    }

    #[must_use]
    pub const fn cert_id(&self) -> &[u8; 16] {
        &self.cert_id
    }

    #[must_use]
    pub const fn issuer_public(&self) -> &[u8; 32] {
        &self.issuer_public
    }

    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}
