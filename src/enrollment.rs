//! Device enrollment: a new install asks the master for a device certificate without ever holding the
//! master seed.
//!
//! Three messages, each signed and fixed in layout:
//!
//! 1. **Ticket** ([`EnrollmentTicket`]): the master signs a single-use ticket naming the person's DID, its
//!    own public key, a 16-byte ticket id and a short window. It travels from the master's device to the new
//!    install out of band (a QR code or a code shown on one screen and typed on the other). The ticket is the
//!    new install's anchor: the master key in it is the key the grant must come from.
//! 2. **Request** ([`EnrollmentRequest`]): the new install signs, with its own device key, the subject, the
//!    master key and the ticket id of the ticket, its device public key and its Noise static key. The
//!    signature is the proof that the request comes from the holder of the device key it names; a request
//!    whose signature does not verify under that key is refused when decoded. The Noise static key is an
//!    X25519 key and cannot sign: the request binds it under the device key's signature, and its possession is
//!    shown at the first Noise handshake with it.
//! 3. **Grant**: the master's [`EnrollmentDesk`] checks the request against the ticket and issues an ordinary
//!    [`DeviceCert`] for the device key and Noise key. The new install accepts it with
//!    [`EnrollmentRequest::accept_grant`]: it must come from the ticket's master and name this request's
//!    subject and keys.
//!
//! Before approving, the person compares [`EnrollmentRequest::short_code`] on the two screens, so a request
//! swapped on its way to the master shows a different code.
//!
//! ```text
//! ticket:  signed = ENROLLMENT_TICKET_CONTEXT || body
//!          body   = version (1) || subject length (u16 BE) || subject (UTF-8, `did:method:id`)
//!                   || master_public (32) || ticket_id (16) || issued_at (u64 BE) || not_after (u64 BE)
//!          bytes  = body || signature (64, by the master key)
//!          text   = ENROLLMENT_TICKET_TEXT_PREFIX || base32 (RFC 4648, upper case, no padding) of bytes
//! request: signed = ENROLLMENT_REQUEST_CONTEXT || body
//!          body   = version (1) || subject length (u16 BE) || subject || master_public (32) || ticket_id (16)
//!                   || device_public (32) || noise_static (32) || requested_at (u64 BE)
//!          bytes  = body || signature (64, by the device key)
//!          text   = ENROLLMENT_REQUEST_TEXT_PREFIX || base32 of bytes
//! short code = the first 8 Crockford base32 characters of
//!              SHA-256(ENROLLMENT_SHORT_CODE_CONTEXT || request bytes)[..5], as XXXX-XXXX
//! ```
//!
//! A ticket holds for `issued_at <= now + MAX_CLOCK_SKEW_SECS` and `now < not_after`, the window of a device
//! certificate, and for at most [`ENROLLMENT_TICKET_MAX_LIFETIME_SECS`]. The desk accepts a ticket id once
//! (the same record [`crate::invite::InviteRedemptions`] keeps) and refuses a request whose `requested_at`
//! lies outside the ticket's window. The ticket and the request are signed under their own contexts, so a
//! contact invite (the same field order) never reads as a ticket. A ticket for a subject of the method
//! reserved for services is not issued: services are certified by [`crate::service_cert`].
//!
//! The ticket id is chosen by the caller from the operating system's random source; this crate draws no
//! random numbers and reads no clock. Whether the ticket's master key is the one the subject's DID resolves
//! to is the product's check ([`crate::master_key::MasterKeyResolver`]); the new install has the ticket from
//! the person's own device, so the ticket is the anchor until it can resolve the DID.

use crate::base32;
use crate::device_cert::{
    is_service_subject, DeviceCert, DeviceCertError, MAX_CLOCK_SKEW_SECS, MAX_SUBJECT_LEN,
};
use crate::did::Did;
use crate::invite::{Spent, SpentIds};
use alice_crypto::sha256::digest;
use alice_sign::{KeyPair, PublicKey, Signature};
use std::fmt;

/// The only ticket and request layout this version reads and writes
pub const ENROLLMENT_VERSION: u8 = 1;

/// Prefixed to the ticket body before the master signs it (domain separation)
pub const ENROLLMENT_TICKET_CONTEXT: &[u8] = b"alice-identity enrollment-ticket v1";

/// Prefixed to the request body before the device signs it (domain separation)
pub const ENROLLMENT_REQUEST_CONTEXT: &[u8] = b"alice-identity enrollment-request v1";

/// Prefixed to the request bytes before hashing them into the short code
pub const ENROLLMENT_SHORT_CODE_CONTEXT: &[u8] = b"alice-identity enrollment-request short-code v1";

/// The text form of a ticket starts with this
pub const ENROLLMENT_TICKET_TEXT_PREFIX: &str = "ALICE-ENROLL:1:";

/// The text form of a request starts with this
pub const ENROLLMENT_REQUEST_TEXT_PREFIX: &str = "ALICE-ENROLL-REQ:1:";

/// The longest window a ticket may have (15 minutes): it is shown and used while both devices are at hand
pub const ENROLLMENT_TICKET_MAX_LIFETIME_SECS: u64 = 900;

/// Why a ticket or a request was not made, decoded or accepted, or a grant not issued or accepted
///
/// Made by this crate and read by callers; callers never build one.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentError {
    /// The layout version is not [`ENROLLMENT_VERSION`]
    UnsupportedVersion(u8),
    /// The bytes do not hold one whole ticket or request (the reason names the part)
    Malformed(&'static str),
    /// The subject is not a DID whose `did:method:id` text reads back as the same DID, or is too long
    InvalidSubject,
    /// The subject's method is the one reserved for services
    ReservedSubject,
    /// The signature does not verify (strictly) over the context and the body
    BadSignature,
    /// `not_after` is not after `issued_at`
    InvalidValidity,
    /// The ticket's window is longer than [`ENROLLMENT_TICKET_MAX_LIFETIME_SECS`]
    LifetimeTooLong,
    /// `now` is more than `MAX_CLOCK_SKEW_SECS` before the ticket's `issued_at`
    NotYetValid { now: u64, issued_at: u64 },
    /// `now` is at or after the ticket's `not_after`
    Expired { now: u64, not_after: u64 },
    /// The approving key, or the ticket's master key, is not this desk's master
    WrongMaster,
    /// The request names another ticket id or another master key than the ticket
    WrongTicket,
    /// The request names another subject than the ticket
    SubjectMismatch,
    /// The request's `requested_at` lies outside the ticket's window
    RequestOutsideTicket,
    /// The ticket was used already
    AlreadyUsed,
    /// The master cancelled the ticket before it was used
    Cancelled,
    /// The text is not the prefix followed by upper-case RFC 4648 base32
    BadText,
    /// The grant's certificate was not issued or does not verify
    Cert(DeviceCertError),
    /// The grant names another subject, device key or Noise key than the request (the part is named)
    GrantMismatch(&'static str),
}

impl fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "enrollment version {v} is not supported"),
            Self::Malformed(what) => write!(f, "malformed enrollment message: {what}"),
            Self::InvalidSubject => f.write_str("the enrollment subject is not a canonical DID"),
            Self::ReservedSubject => {
                f.write_str("the enrollment subject has the method reserved for services")
            }
            Self::BadSignature => f.write_str("the enrollment message's signature does not verify"),
            Self::InvalidValidity => f.write_str("the ticket ends before it starts"),
            Self::LifetimeTooLong => write!(
                f,
                "the ticket's window is longer than {ENROLLMENT_TICKET_MAX_LIFETIME_SECS} s"
            ),
            Self::NotYetValid { now, issued_at } => {
                write!(f, "the ticket holds from {issued_at}, now is {now}")
            }
            Self::Expired { now, not_after } => {
                write!(f, "the ticket held until {not_after}, now is {now}")
            }
            Self::WrongMaster => f.write_str("the ticket is not this master's"),
            Self::WrongTicket => f.write_str("the request was made for another ticket"),
            Self::SubjectMismatch => {
                f.write_str("the request names another subject than the ticket")
            }
            Self::RequestOutsideTicket => {
                f.write_str("the request was made outside the ticket's window")
            }
            Self::AlreadyUsed => f.write_str("the ticket was used already"),
            Self::Cancelled => f.write_str("the ticket was cancelled"),
            Self::BadText => f.write_str("not the text form of this enrollment message"),
            Self::Cert(e) => write!(f, "the grant: {e}"),
            Self::GrantMismatch(what) => {
                write!(f, "the grant names another {what} than the request")
            }
        }
    }
}

impl std::error::Error for EnrollmentError {}

/// The subject's text, refusing a subject that does not fit or does not read back as itself
fn subject_text(subject: &Did) -> Result<String, EnrollmentError> {
    let text = subject.to_string();
    if text.len() > MAX_SUBJECT_LEN || Did::parse(&text).as_ref() != Ok(subject) {
        return Err(EnrollmentError::InvalidSubject);
    }
    Ok(text)
}

fn push_subject(b: &mut Vec<u8>, subject: &str) {
    b.extend_from_slice(
        &u16::try_from(subject.len())
            .expect("checked against MAX_SUBJECT_LEN")
            .to_be_bytes(),
    );
    b.extend_from_slice(subject.as_bytes());
}

/// Version and subject, and the rest after the subject, which must be `tail` bytes long
fn split_head(bytes: &[u8], tail: usize) -> Result<(Did, &[u8]), EnrollmentError> {
    let (&version, rest) = bytes
        .split_first()
        .ok_or(EnrollmentError::Malformed("version"))?;
    if version != ENROLLMENT_VERSION {
        return Err(EnrollmentError::UnsupportedVersion(version));
    }
    let (len, rest) = rest
        .split_first_chunk::<2>()
        .ok_or(EnrollmentError::Malformed("subject length"))?;
    let len = usize::from(u16::from_be_bytes(*len));
    if len > MAX_SUBJECT_LEN || rest.len() < len {
        return Err(EnrollmentError::Malformed("subject"));
    }
    let (subject, rest) = rest.split_at(len);
    if rest.len() != tail {
        return Err(EnrollmentError::Malformed("length after the subject"));
    }
    let text = std::str::from_utf8(subject).map_err(|_| EnrollmentError::InvalidSubject)?;
    let subject = Did::parse(text).map_err(|_| EnrollmentError::InvalidSubject)?;
    Ok((subject, rest))
}

fn array<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    bytes[at..at + N].try_into().expect("length checked")
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(array(bytes, at))
}

fn decode_text(text: &str, prefix: &str) -> Result<Vec<u8>, EnrollmentError> {
    let body = text.strip_prefix(prefix).ok_or(EnrollmentError::BadText)?;
    if body.is_empty() {
        return Err(EnrollmentError::BadText);
    }
    base32::decode(body).ok_or(EnrollmentError::BadText)
}

/// A single-use ticket the master signs for one new install (see the module documentation)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentTicket {
    subject: Did,
    master_public: [u8; 32],
    ticket_id: [u8; 16],
    issued_at: u64,
    not_after: u64,
    signature: [u8; 64],
}

impl EnrollmentTicket {
    /// Sign a ticket for `subject` with id `ticket_id`, holding from `issued_at` until before `not_after`
    ///
    /// # Errors
    /// In this order: [`EnrollmentError::ReservedSubject`], [`EnrollmentError::InvalidValidity`] when
    /// `not_after <= issued_at`, [`EnrollmentError::LifetimeTooLong`], [`EnrollmentError::InvalidSubject`]
    pub fn issue(
        master: &KeyPair,
        subject: &Did,
        ticket_id: [u8; 16],
        issued_at: u64,
        not_after: u64,
    ) -> Result<Self, EnrollmentError> {
        if is_service_subject(subject) {
            return Err(EnrollmentError::ReservedSubject);
        }
        if not_after <= issued_at {
            return Err(EnrollmentError::InvalidValidity);
        }
        if not_after - issued_at > ENROLLMENT_TICKET_MAX_LIFETIME_SECS {
            return Err(EnrollmentError::LifetimeTooLong);
        }
        subject_text(subject)?;
        let mut ticket = Self {
            subject: subject.clone(),
            master_public: master.public().0,
            ticket_id,
            issued_at,
            not_after,
            signature: [0; 64],
        };
        ticket.signature = master.sign(&ticket.signed_message()).0;
        Ok(ticket)
    }

    /// The bytes the master signs: the context and the body
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        let mut m = ENROLLMENT_TICKET_CONTEXT.to_vec();
        m.extend_from_slice(&self.body());
        m
    }

    fn body(&self) -> Vec<u8> {
        let subject = self.subject.to_string();
        let mut b = Vec::with_capacity(1 + 2 + subject.len() + 32 + 16 + 16);
        b.push(ENROLLMENT_VERSION);
        push_subject(&mut b, &subject);
        b.extend_from_slice(&self.master_public);
        b.extend_from_slice(&self.ticket_id);
        b.extend_from_slice(&self.issued_at.to_be_bytes());
        b.extend_from_slice(&self.not_after.to_be_bytes());
        b
    }

    /// The ticket's bytes: the body and the signature
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.signature);
        b
    }

    /// Decode and accept a ticket: layout, subject, window and the master's signature (not the time; see
    /// [`EnrollmentTicket::verify`])
    ///
    /// # Errors
    /// The first failing check, in that order
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnrollmentError> {
        let (subject, rest) = split_head(bytes, 32 + 16 + 8 + 8 + 64)?;
        let ticket = Self {
            subject,
            master_public: array(rest, 0),
            ticket_id: array(rest, 32),
            issued_at: u64_at(rest, 48),
            not_after: u64_at(rest, 56),
            signature: array(rest, 64),
        };
        if ticket.to_bytes() != bytes {
            return Err(EnrollmentError::Malformed("not the canonical encoding"));
        }
        if ticket.not_after <= ticket.issued_at {
            return Err(EnrollmentError::InvalidValidity);
        }
        if ticket.not_after - ticket.issued_at > ENROLLMENT_TICKET_MAX_LIFETIME_SECS {
            return Err(EnrollmentError::LifetimeTooLong);
        }
        if !PublicKey(ticket.master_public)
            .verify_strict(&ticket.signed_message(), &Signature(ticket.signature))
        {
            return Err(EnrollmentError::BadSignature);
        }
        if is_service_subject(&ticket.subject) {
            return Err(EnrollmentError::ReservedSubject);
        }
        Ok(ticket)
    }

    /// Accept the ticket at `now`: `issued_at <= now + MAX_CLOCK_SKEW_SECS` and `now < not_after`
    ///
    /// # Errors
    /// [`EnrollmentError::NotYetValid`] or [`EnrollmentError::Expired`]
    pub const fn verify(&self, now: u64) -> Result<(), EnrollmentError> {
        if now.saturating_add(MAX_CLOCK_SKEW_SECS) < self.issued_at {
            return Err(EnrollmentError::NotYetValid {
                now,
                issued_at: self.issued_at,
            });
        }
        if now >= self.not_after {
            return Err(EnrollmentError::Expired {
                now,
                not_after: self.not_after,
            });
        }
        Ok(())
    }

    /// The text form: [`ENROLLMENT_TICKET_TEXT_PREFIX`] and the base32 of the bytes
    #[must_use]
    pub fn to_text(&self) -> String {
        format!(
            "{ENROLLMENT_TICKET_TEXT_PREFIX}{}",
            base32::encode(&self.to_bytes())
        )
    }

    /// Decode and accept the text form (as [`EnrollmentTicket::from_bytes`])
    ///
    /// # Errors
    /// [`EnrollmentError::BadText`], then the errors of [`EnrollmentTicket::from_bytes`]
    pub fn from_text(text: &str) -> Result<Self, EnrollmentError> {
        Self::from_bytes(&decode_text(text, ENROLLMENT_TICKET_TEXT_PREFIX)?)
    }

    #[must_use]
    pub const fn subject(&self) -> &Did {
        &self.subject
    }

    #[must_use]
    pub const fn master_public(&self) -> &[u8; 32] {
        &self.master_public
    }

    #[must_use]
    pub const fn ticket_id(&self) -> &[u8; 16] {
        &self.ticket_id
    }

    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    #[must_use]
    pub const fn not_after(&self) -> u64 {
        self.not_after
    }
}

/// A new install's request for a device certificate, signed by its device key (see the module
/// documentation)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRequest {
    subject: Did,
    master_public: [u8; 32],
    ticket_id: [u8; 16],
    device_public: [u8; 32],
    noise_static: [u8; 32],
    requested_at: u64,
    signature: [u8; 64],
}

impl EnrollmentRequest {
    /// Sign a request for `ticket` with the new install's `device` key and its Noise static key
    #[must_use]
    pub fn new(
        device: &KeyPair,
        ticket: &EnrollmentTicket,
        noise_static: [u8; 32],
        requested_at: u64,
    ) -> Self {
        let mut request = Self {
            subject: ticket.subject.clone(),
            master_public: ticket.master_public,
            ticket_id: ticket.ticket_id,
            device_public: device.public().0,
            noise_static,
            requested_at,
            signature: [0; 64],
        };
        request.signature = device.sign(&request.signed_message()).0;
        request
    }

    /// The bytes the device signs: the context and the body
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        let mut m = ENROLLMENT_REQUEST_CONTEXT.to_vec();
        m.extend_from_slice(&self.body());
        m
    }

    fn body(&self) -> Vec<u8> {
        let subject = self.subject.to_string();
        let mut b = Vec::with_capacity(1 + 2 + subject.len() + 32 + 16 + 32 + 32 + 8);
        b.push(ENROLLMENT_VERSION);
        push_subject(&mut b, &subject);
        b.extend_from_slice(&self.master_public);
        b.extend_from_slice(&self.ticket_id);
        b.extend_from_slice(&self.device_public);
        b.extend_from_slice(&self.noise_static);
        b.extend_from_slice(&self.requested_at.to_be_bytes());
        b
    }

    /// The request's bytes: the body and the signature
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.signature);
        b
    }

    /// Decode and accept a request: layout, subject and the device key's signature (the proof of
    /// possession)
    ///
    /// # Errors
    /// The first failing check, in that order
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnrollmentError> {
        let (subject, rest) = split_head(bytes, 32 + 16 + 32 + 32 + 8 + 64)?;
        let request = Self {
            subject,
            master_public: array(rest, 0),
            ticket_id: array(rest, 32),
            device_public: array(rest, 48),
            noise_static: array(rest, 80),
            requested_at: u64_at(rest, 112),
            signature: array(rest, 120),
        };
        if request.to_bytes() != bytes {
            return Err(EnrollmentError::Malformed("not the canonical encoding"));
        }
        if !PublicKey(request.device_public)
            .verify_strict(&request.signed_message(), &Signature(request.signature))
        {
            return Err(EnrollmentError::BadSignature);
        }
        Ok(request)
    }

    /// The text form: [`ENROLLMENT_REQUEST_TEXT_PREFIX`] and the base32 of the bytes
    #[must_use]
    pub fn to_text(&self) -> String {
        format!(
            "{ENROLLMENT_REQUEST_TEXT_PREFIX}{}",
            base32::encode(&self.to_bytes())
        )
    }

    /// Decode and accept the text form (as [`EnrollmentRequest::from_bytes`])
    ///
    /// # Errors
    /// [`EnrollmentError::BadText`], then the errors of [`EnrollmentRequest::from_bytes`]
    pub fn from_text(text: &str) -> Result<Self, EnrollmentError> {
        Self::from_bytes(&decode_text(text, ENROLLMENT_REQUEST_TEXT_PREFIX)?)
    }

    /// The code both screens show before the master approves (`XXXX-XXXX`, Crockford base32)
    #[must_use]
    pub fn short_code(&self) -> String {
        let mut m = ENROLLMENT_SHORT_CODE_CONTEXT.to_vec();
        m.extend_from_slice(&self.to_bytes());
        let code = base32::crockford_prefix(&digest(&m)[..5], 8);
        format!("{}-{}", &code[..4], &code[4..])
    }

    /// Accept the master's grant for this request at `now`: it verifies under the ticket's master key and
    /// names this request's subject, device key and Noise key
    ///
    /// # Errors
    /// [`EnrollmentError::Cert`] with [`DeviceCert::verify`]'s error, then
    /// [`EnrollmentError::GrantMismatch`] naming the first differing part
    pub fn accept_grant(&self, grant: &DeviceCert, now: u64) -> Result<(), EnrollmentError> {
        grant
            .verify(&PublicKey(self.master_public), now)
            .map_err(EnrollmentError::Cert)?;
        if grant.subject() != &self.subject {
            return Err(EnrollmentError::GrantMismatch("subject"));
        }
        if grant.device_public() != &self.device_public {
            return Err(EnrollmentError::GrantMismatch("device key"));
        }
        if grant.noise_static() != &self.noise_static {
            return Err(EnrollmentError::GrantMismatch("noise key"));
        }
        Ok(())
    }

    #[must_use]
    pub const fn subject(&self) -> &Did {
        &self.subject
    }

    #[must_use]
    pub const fn master_public(&self) -> &[u8; 32] {
        &self.master_public
    }

    #[must_use]
    pub const fn ticket_id(&self) -> &[u8; 16] {
        &self.ticket_id
    }

    #[must_use]
    pub const fn device_public(&self) -> &[u8; 32] {
        &self.device_public
    }

    #[must_use]
    pub const fn noise_static(&self) -> &[u8; 32] {
        &self.noise_static
    }

    #[must_use]
    pub const fn requested_at(&self) -> u64 {
        self.requested_at
    }
}

/// The master's side: checks requests against the tickets it issued and records each ticket id once
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentDesk {
    master_public: [u8; 32],
    spent: SpentIds,
}

impl EnrollmentDesk {
    /// An empty desk for the tickets `master` signs
    #[must_use]
    pub fn new(master: PublicKey) -> Self {
        Self {
            master_public: master.0,
            spent: SpentIds::default(),
        }
    }

    /// Approve `request` for `ticket` at `now`: issue a device certificate holding from `now` until before
    /// `not_after` and record the ticket as used. A refused request records nothing.
    ///
    /// # Errors
    /// In this order: [`EnrollmentError::WrongMaster`] (the key or the ticket is not this desk's master's),
    /// [`EnrollmentTicket::verify`]'s errors, [`EnrollmentError::WrongTicket`],
    /// [`EnrollmentError::SubjectMismatch`], [`EnrollmentError::RequestOutsideTicket`],
    /// [`EnrollmentError::AlreadyUsed`] or [`EnrollmentError::Cancelled`], [`EnrollmentError::Cert`]
    pub fn approve(
        &mut self,
        master: &KeyPair,
        ticket: &EnrollmentTicket,
        request: &EnrollmentRequest,
        now: u64,
        not_after: u64,
    ) -> Result<DeviceCert, EnrollmentError> {
        if master.public().0 != self.master_public || ticket.master_public != self.master_public {
            return Err(EnrollmentError::WrongMaster);
        }
        ticket.verify(now)?;
        if request.ticket_id != ticket.ticket_id || request.master_public != ticket.master_public {
            return Err(EnrollmentError::WrongTicket);
        }
        if request.subject != ticket.subject {
            return Err(EnrollmentError::SubjectMismatch);
        }
        if request.requested_at.saturating_add(MAX_CLOCK_SKEW_SECS) < ticket.issued_at
            || request.requested_at >= ticket.not_after
        {
            return Err(EnrollmentError::RequestOutsideTicket);
        }
        match self.spent.get(&ticket.ticket_id) {
            Some(Spent::Redeemed { .. }) => return Err(EnrollmentError::AlreadyUsed),
            Some(Spent::Cancelled) => return Err(EnrollmentError::Cancelled),
            None => {}
        }
        let cert = DeviceCert::issue(
            master,
            &request.subject,
            request.device_public,
            request.noise_static,
            now,
            not_after,
        )
        .map_err(EnrollmentError::Cert)?;
        self.spent.redeem(ticket.ticket_id, ticket.not_after);
        Ok(cert)
    }

    /// Mark `ticket_id` as not to be accepted (a ticket already used stays refused as used)
    pub fn cancel(&mut self, ticket_id: [u8; 16]) {
        self.spent.cancel(ticket_id);
    }

    /// Drop the uses whose tickets have expired at `now` (cancellations stay)
    pub fn prune(&mut self, now: u64) {
        self.spent.prune(now);
    }

    /// The number of recorded ticket ids
    #[must_use]
    pub fn len(&self) -> usize {
        self.spent.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spent.len() == 0
    }
}
