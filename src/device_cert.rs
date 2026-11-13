//! Device certificates: a master key vouches for one device key, and the device's Noise static
//! key, of the same identity for a bounded time.
//!
//! The certificate is fixed width apart from the subject DID, encoded as one canonical byte
//! layout and signed with a context prefix, so a signature over other data under the same
//! master key (a [`crate::signed_did::SignedClaim`], a revocation list) is never accepted as a
//! certificate:
//!
//! ```text
//! signed = DEVICE_CERT_CONTEXT || body (the subject is at most `MAX_SUBJECT_LEN` bytes)
//! body   = version (1) || subject length (u16 BE) || subject (UTF-8, `did:method:id`)
//!          || device_public (32) || noise_static (32) || issued_at (u64 BE) || not_after (u64 BE)
//!          || device_id (16) || issuer_public (32)
//! bytes  = body || signature (64)
//! ```
//!
//! The certificate is valid for `issued_at <= now + MAX_CLOCK_SKEW_SECS` and `now < not_after`; the caller
//! passes `now` (this crate reads no clock). The leeway at the start lets a verifier whose clock runs behind the
//! issuer's accept a certificate issued a moment ago; the end of the window has no leeway.
//!
//! # Device id
//!
//! The 16-byte `device_id` is not chosen by the issuer: it is derived from the subject and the device
//! key, written into the certificate by [`DeviceCert::issue`] and checked by [`DeviceCert::from_bytes`]:
//!
//! ```text
//! device_id = SHA-256(DEVICE_ID_CONTEXT || subject length (u16 BE) || subject || device_public)[..16]
//! ```
//!
//! (`subject` is the `did:method:id` text, at most [`MAX_SUBJECT_LEN`] bytes.) An issuer cannot give
//! two keys one id, and a renewal (the same key and subject, another validity) keeps its id, so
//! revoking an id ([`crate::cert_revocation`]) retires that key for that subject in every period.
//! Version 2 had the same layout with an issuer-chosen id and is refused as
//! [`DeviceCertError::UnsupportedVersion`].

use crate::did::Did;
use alice_sign::{hash_data, KeyPair, PublicKey, Signature};
use std::fmt;

/// The only certificate layout this version reads and writes (version 1, without the Noise static
/// key, and version 2, with an issuer-chosen id, are refused as [`DeviceCertError::UnsupportedVersion`])
pub const DEVICE_CERT_VERSION: u8 = 3;

/// The verifier's leeway for a certificate's start, in seconds.
///
/// A certificate whose `issued_at` is up to this far ahead of the verifier's `now` is accepted, so a device
/// certified on a clock that runs ahead can be used at once by verifiers whose clocks run behind. It applies to
/// `issued_at` only; `not_after` has no leeway.
pub const MAX_CLOCK_SKEW_SECS: u64 = 600;

/// Prefixed to the subject and device key when the device id is derived (see the module documentation)
pub const DEVICE_ID_CONTEXT: &[u8] = b"alice-identity/device-id/v1";

/// The identifier of a device key under a subject: the first 16 bytes of a SHA-256 over the subject and
/// the key (see the module documentation)
///
/// A certificate carries the id of its own key ([`DeviceCert::device_id`]); revocation lists name ids.
/// [`DeviceId::from_raw`] reads an id received as bytes; it does not make the id belong to any key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId([u8; 16]);

impl DeviceId {
    /// The id of `device_public` under `subject`
    ///
    /// # Errors
    /// [`DeviceCertError::SubjectTooLong`] when the subject text is over [`MAX_SUBJECT_LEN`] bytes,
    /// [`DeviceCertError::InvalidSubject`] when the subject does not round-trip as text
    pub fn derive(subject: &Did, device_public: &[u8; 32]) -> Result<Self, DeviceCertError> {
        Ok(Self::of_text(&canonical_subject(subject)?, device_public))
    }

    /// The derivation over a subject text already checked to be canonical and at most
    /// [`MAX_SUBJECT_LEN`] bytes
    fn of_text(subject: &str, device_public: &[u8; 32]) -> Self {
        let len = u16::try_from(subject.len()).expect("subject length checked by the caller");
        let mut m = Vec::with_capacity(DEVICE_ID_CONTEXT.len() + 2 + subject.len() + 32);
        m.extend_from_slice(DEVICE_ID_CONTEXT);
        m.extend_from_slice(&len.to_be_bytes());
        m.extend_from_slice(subject.as_bytes());
        m.extend_from_slice(device_public);
        let digest = hash_data(&m).0;
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        Self(id)
    }

    /// An id read back from its 16 bytes (as received; not checked against any key)
    #[must_use]
    pub const fn from_raw(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for DeviceId {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for DeviceId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// The longest subject (`did:method:id` text, in bytes) a certificate takes, at issue and when decoded
pub const MAX_SUBJECT_LEN: usize = 255;

/// The longest encoded certificate: one whose subject is [`MAX_SUBJECT_LEN`] bytes
pub const MAX_DEVICE_CERT_LEN: usize = 1 + 2 + MAX_SUBJECT_LEN + TAIL + SIGNATURE;

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
    device_id: DeviceId,
    issuer_public: [u8; 32],
    signature: [u8; 64],
}

/// Why a certificate was not issued, decoded or accepted
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceCertError {
    /// The layout version is not [`DEVICE_CERT_VERSION`]
    UnsupportedVersion(u8),
    /// The bytes do not hold one whole certificate (the reason names the field)
    Malformed(&'static str),
    /// The subject is not a DID whose `did:method:id` text reads back as the same DID
    InvalidSubject,
    /// The subject text is longer than [`MAX_SUBJECT_LEN`] bytes (its length is given)
    SubjectTooLong(usize),
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
    /// The stored device id is not the one derived from the subject and the device key
    DeviceIdMismatch,
}

impl fmt::Display for DeviceCertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "unsupported device certificate version {v}"),
            Self::Malformed(what) => write!(f, "malformed device certificate: {what}"),
            Self::InvalidSubject => write!(f, "device certificate subject is not a canonical DID"),
            Self::SubjectTooLong(n) => write!(
                f,
                "device certificate subject is {n} bytes, over {MAX_SUBJECT_LEN}"
            ),
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
            Self::DeviceIdMismatch => write!(
                f,
                "device certificate id is not derived from its subject and device key"
            ),
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
    if text.len() > MAX_SUBJECT_LEN {
        return Err(DeviceCertError::SubjectTooLong(text.len()));
    }
    match Did::parse(&text) {
        Ok(back) if back == *subject => Ok(text),
        _ => Err(DeviceCertError::InvalidSubject),
    }
}

impl DeviceCert {
    /// Sign a certificate for `device_public` and `noise_static` under `subject` with the master key
    ///
    /// # Errors
    /// [`DeviceCertError::InvalidValidity`] when `not_after <= issued_at`,
    /// [`DeviceCertError::SubjectTooLong`] when the subject text is over [`MAX_SUBJECT_LEN`] bytes,
    /// [`DeviceCertError::InvalidSubject`] when the subject does not round-trip as text
    pub fn issue(
        master: &KeyPair,
        subject: &Did,
        device_public: [u8; 32],
        noise_static: [u8; 32],
        issued_at: u64,
        not_after: u64,
    ) -> Result<Self, DeviceCertError> {
        if not_after <= issued_at {
            return Err(DeviceCertError::InvalidValidity);
        }
        let device_id = DeviceId::of_text(&canonical_subject(subject)?, &device_public);
        let mut cert = Self {
            version: DEVICE_CERT_VERSION,
            subject: subject.clone(),
            device_public,
            noise_static,
            issued_at,
            not_after,
            device_id,
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
        b.extend_from_slice(self.device_id.as_bytes());
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
    /// [`DeviceCertError::UnsupportedVersion`], [`DeviceCertError::SubjectTooLong`],
    /// [`DeviceCertError::InvalidSubject`], [`DeviceCertError::DeviceIdMismatch`] when the stored id
    /// is not the one derived from the subject and the device key
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
        if len > MAX_SUBJECT_LEN {
            return Err(DeviceCertError::SubjectTooLong(len));
        }
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
        let device_public: [u8; 32] = field(0, 32).try_into().expect("32 bytes");
        let device_id = DeviceId(field(80, 16).try_into().expect("16 bytes"));
        if device_id != DeviceId::of_text(text, &device_public) {
            return Err(DeviceCertError::DeviceIdMismatch);
        }
        Ok(Self {
            version,
            subject,
            device_public,
            noise_static: field(32, 32).try_into().expect("32 bytes"),
            issued_at: u64_at(64),
            not_after: u64_at(72),
            device_id,
            issuer_public: field(96, 32).try_into().expect("32 bytes"),
            signature: field(128, SIGNATURE).try_into().expect("64 bytes"),
        })
    }

    /// Accept the certificate only if it was issued by `master`, its signature verifies strictly
    /// over the context and body, `issued_at <= now + MAX_CLOCK_SKEW_SECS` and `now < not_after`
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
        // the start has the clock-skew leeway, the end has none
        if now.saturating_add(MAX_CLOCK_SKEW_SECS) < self.issued_at {
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

    /// The id of the device key under the subject (derived, see the module documentation)
    #[must_use]
    pub const fn device_id(&self) -> DeviceId {
        self.device_id
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
