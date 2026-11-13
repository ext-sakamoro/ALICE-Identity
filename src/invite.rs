//! Invites.
//!
//! A signed, single-use token one person gives another (as a link, a code or a QR code) so
//! the other can reach them the first time, without either side giving out a name, an address or a
//! phone number. The invite says who issued it and until when it holds; the issuer keeps the record of
//! which of its invites were used ([`InviteRedemptions`]) and refuses a second use.
//!
//! ```text
//! signed = INVITE_CONTEXT || body
//! body   = version (1)
//!          || issuer length (u16 BE) || issuer (the did:key text of issuer_public)
//!          || issuer_public (32)
//!          || invite_id (16)
//!          || issued_at (u64 BE) || not_after (u64 BE)      (issued_at < not_after)
//! bytes  = body || signature (64)
//! text   = INVITE_TEXT_PREFIX || base32 (RFC 4648, upper case, no padding) of bytes
//! ```
//!
//! The invite id is chosen by the caller, from the operating system's random source (16 bytes make a
//! collision between two invites of one issuer negligible); this crate draws no random numbers and
//! reads no clock. An invite holds for `issued_at <= now + MAX_CLOCK_SKEW_SECS` and `now < not_after`,
//! the window of a device certificate.

use crate::base32;
use crate::contact_card::did_key_matches;
use crate::contact_card::DidKeyMismatch;
use crate::device_cert::{MAX_CLOCK_SKEW_SECS, MAX_SUBJECT_LEN};
use crate::did::Did;
use alice_sign::{KeyPair, PublicKey, Signature};
use std::collections::BTreeMap;
use std::fmt;

/// The only invite layout this version reads and writes
pub const INVITE_VERSION: u8 = 1;

/// Prefixed to the body before signing (domain separation)
pub const INVITE_CONTEXT: &[u8] = b"alice-identity invite v1";

/// The text form starts with this
pub const INVITE_TEXT_PREFIX: &str = "ALICE-INVITE:1:";

/// A signed invite (see the module documentation)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    issuer: Did,
    issuer_public: [u8; 32],
    id: [u8; 16],
    issued_at: u64,
    not_after: u64,
    signature: [u8; 64],
}

/// Why an invite was not made, decoded, accepted or redeemed
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InviteError {
    /// The layout version is not [`INVITE_VERSION`]
    UnsupportedVersion(u8),
    /// The bytes do not hold one whole invite (the reason names the part)
    Malformed(&'static str),
    /// The issuer is not a did:key
    SubjectNotDidKey,
    /// The issuer is the did:key of another key than the signing key
    SubjectKeyMismatch,
    /// The signature does not verify (strictly) over the context and the body
    BadSignature,
    /// `not_after` is not after `issued_at`
    InvalidValidity,
    /// `now` is more than `MAX_CLOCK_SKEW_SECS` before `issued_at`
    NotYetValid { now: u64, issued_at: u64 },
    /// `now` is at or after `not_after`
    Expired { now: u64, not_after: u64 },
    /// The invite was issued by another key than the one these redemptions belong to
    WrongIssuer,
    /// The invite was used already
    AlreadyRedeemed,
    /// The issuer cancelled the invite before it was used
    Cancelled,
    /// The text is not the prefix followed by upper-case RFC 4648 base32
    BadText,
}

impl fmt::Display for InviteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "invite version {v} is not supported"),
            Self::Malformed(what) => write!(f, "malformed invite: {what}"),
            Self::SubjectNotDidKey => f.write_str("the invite's issuer is not a did:key"),
            Self::SubjectKeyMismatch => {
                f.write_str("the invite's issuer is the did:key of another key")
            }
            Self::BadSignature => f.write_str("the invite's signature does not verify"),
            Self::InvalidValidity => f.write_str("the invite ends before it starts"),
            Self::NotYetValid { now, issued_at } => {
                write!(f, "the invite holds from {issued_at}, now is {now}")
            }
            Self::Expired { now, not_after } => {
                write!(f, "the invite held until {not_after}, now is {now}")
            }
            Self::WrongIssuer => f.write_str("the invite is another issuer's"),
            Self::AlreadyRedeemed => f.write_str("the invite was used already"),
            Self::Cancelled => f.write_str("the invite was cancelled"),
            Self::BadText => f.write_str("not the text form of an invite"),
        }
    }
}

impl std::error::Error for InviteError {}

impl From<DidKeyMismatch> for InviteError {
    fn from(e: DidKeyMismatch) -> Self {
        match e {
            DidKeyMismatch::NotDidKey => Self::SubjectNotDidKey,
            DidKeyMismatch::OtherKey => Self::SubjectKeyMismatch,
        }
    }
}

impl Invite {
    /// Sign an invite with id `invite_id` holding from `issued_at` until before `not_after`
    ///
    /// # Errors
    /// [`InviteError::InvalidValidity`] when `not_after <= issued_at`
    pub fn issue(
        master: &KeyPair,
        invite_id: [u8; 16],
        issued_at: u64,
        not_after: u64,
    ) -> Result<Self, InviteError> {
        if not_after <= issued_at {
            return Err(InviteError::InvalidValidity);
        }
        let public = master.public();
        let mut invite = Self {
            issuer: Did::key_ed25519(&public),
            issuer_public: public.0,
            id: invite_id,
            issued_at,
            not_after,
            signature: [0; 64],
        };
        invite.signature = master.sign(&invite.signed_message()).0;
        Ok(invite)
    }

    /// The bytes the issuer signs: the context and the body
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        let mut m = INVITE_CONTEXT.to_vec();
        m.extend_from_slice(&self.body());
        m
    }

    fn body(&self) -> Vec<u8> {
        let issuer = self.issuer.to_string();
        let mut b = Vec::with_capacity(1 + 2 + issuer.len() + 32 + 16 + 16);
        b.push(INVITE_VERSION);
        b.extend_from_slice(
            &u16::try_from(issuer.len())
                .expect("a did:key fits")
                .to_be_bytes(),
        );
        b.extend_from_slice(issuer.as_bytes());
        b.extend_from_slice(&self.issuer_public);
        b.extend_from_slice(&self.id);
        b.extend_from_slice(&self.issued_at.to_be_bytes());
        b.extend_from_slice(&self.not_after.to_be_bytes());
        b
    }

    /// The invite's bytes: the body and the signature
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.signature);
        b
    }

    /// Decode and accept an invite: layout, issuer, validity order and signature (not the time; see
    /// [`Invite::verify`])
    ///
    /// # Errors
    /// The first failing check, in that order
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InviteError> {
        let (&version, rest) = bytes
            .split_first()
            .ok_or(InviteError::Malformed("version"))?;
        if version != INVITE_VERSION {
            return Err(InviteError::UnsupportedVersion(version));
        }
        let (len, rest) = rest
            .split_first_chunk::<2>()
            .ok_or(InviteError::Malformed("issuer length"))?;
        let len = usize::from(u16::from_be_bytes(*len));
        if len > MAX_SUBJECT_LEN || rest.len() < len {
            return Err(InviteError::Malformed("issuer"));
        }
        let (issuer, rest) = rest.split_at(len);
        if rest.len() != 32 + 16 + 8 + 8 + 64 {
            return Err(InviteError::Malformed("length after the issuer"));
        }
        let text = std::str::from_utf8(issuer).map_err(|_| InviteError::SubjectNotDidKey)?;
        let issuer = Did::parse(text).map_err(|_| InviteError::SubjectNotDidKey)?;
        let field = |at: usize, n: usize| &rest[at..at + n];
        let u64_at = |at: usize| u64::from_be_bytes(field(at, 8).try_into().expect("8 bytes"));
        let issuer_public: [u8; 32] = field(0, 32).try_into().expect("32 bytes");
        did_key_matches(&issuer, &issuer_public)?;
        let invite = Self {
            issuer,
            issuer_public,
            id: field(32, 16).try_into().expect("16 bytes"),
            issued_at: u64_at(48),
            not_after: u64_at(56),
            signature: field(64, 64).try_into().expect("64 bytes"),
        };
        if invite.to_bytes() != bytes {
            return Err(InviteError::Malformed("not the canonical encoding"));
        }
        if invite.not_after <= invite.issued_at {
            return Err(InviteError::InvalidValidity);
        }
        if !PublicKey(issuer_public)
            .verify_strict(&invite.signed_message(), &Signature(invite.signature))
        {
            return Err(InviteError::BadSignature);
        }
        Ok(invite)
    }

    /// Accept the invite at `now`: `issued_at <= now + MAX_CLOCK_SKEW_SECS` and `now < not_after`
    ///
    /// # Errors
    /// [`InviteError::NotYetValid`] or [`InviteError::Expired`]
    pub const fn verify(&self, now: u64) -> Result<(), InviteError> {
        if now.saturating_add(MAX_CLOCK_SKEW_SECS) < self.issued_at {
            return Err(InviteError::NotYetValid {
                now,
                issued_at: self.issued_at,
            });
        }
        if now >= self.not_after {
            return Err(InviteError::Expired {
                now,
                not_after: self.not_after,
            });
        }
        Ok(())
    }

    /// The text form: [`INVITE_TEXT_PREFIX`] and the base32 of the bytes
    #[must_use]
    pub fn to_text(&self) -> String {
        format!("{INVITE_TEXT_PREFIX}{}", base32::encode(&self.to_bytes()))
    }

    /// Decode and accept the text form (as [`Invite::from_bytes`])
    ///
    /// # Errors
    /// [`InviteError::BadText`] when the text is not the prefix and upper-case base32, then the errors
    /// of [`Invite::from_bytes`]
    pub fn from_text(text: &str) -> Result<Self, InviteError> {
        let body = text
            .strip_prefix(INVITE_TEXT_PREFIX)
            .ok_or(InviteError::BadText)?;
        if body.is_empty() {
            return Err(InviteError::BadText);
        }
        Self::from_bytes(&base32::decode(body).ok_or(InviteError::BadText)?)
    }

    #[must_use]
    pub const fn issuer(&self) -> &Did {
        &self.issuer
    }

    #[must_use]
    pub const fn issuer_public(&self) -> &[u8; 32] {
        &self.issuer_public
    }

    #[must_use]
    pub const fn invite_id(&self) -> &[u8; 16] {
        &self.id
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

/// What the record holds for one invite id
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Spent {
    /// Used; kept until the invite's `not_after` (after it, the invite is refused as expired anyway)
    Redeemed { not_after: u64 },
    /// Cancelled by the issuer before use; kept until the issuer drops the record
    Cancelled,
}

/// The issuer's record of its used and cancelled invites
///
/// [`InviteRedemptions::redeem`] accepts an invite of this issuer once; [`InviteRedemptions::cancel`]
/// marks an id as not to be accepted. [`InviteRedemptions::prune`] drops the redemptions of invites
/// that have expired (they are refused by their expiry), so the record holds at most the invites still
/// within their window, plus the cancellations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRedemptions {
    issuer_public: [u8; 32],
    spent: BTreeMap<[u8; 16], Spent>,
}

impl InviteRedemptions {
    /// An empty record for the invites `issuer` signs
    #[must_use]
    pub const fn new(issuer: PublicKey) -> Self {
        Self {
            issuer_public: issuer.0,
            spent: BTreeMap::new(),
        }
    }

    /// Accept `invite` at `now` and record it as used
    ///
    /// The invite must be this issuer's, within its window, and neither used nor cancelled; a refused
    /// invite is not recorded.
    ///
    /// # Errors
    /// [`InviteError::WrongIssuer`], then [`Invite::verify`]'s errors, then
    /// [`InviteError::AlreadyRedeemed`] or [`InviteError::Cancelled`]
    pub fn redeem(&mut self, invite: &Invite, now: u64) -> Result<(), InviteError> {
        if invite.issuer_public != self.issuer_public {
            return Err(InviteError::WrongIssuer);
        }
        invite.verify(now)?;
        match self.spent.get(&invite.id) {
            Some(Spent::Redeemed { .. }) => Err(InviteError::AlreadyRedeemed),
            Some(Spent::Cancelled) => Err(InviteError::Cancelled),
            None => {
                self.spent.insert(
                    invite.id,
                    Spent::Redeemed {
                        not_after: invite.not_after,
                    },
                );
                Ok(())
            }
        }
    }

    /// Mark `invite_id` as not to be accepted (an invite already used stays refused as used)
    pub fn cancel(&mut self, invite_id: [u8; 16]) {
        self.spent.entry(invite_id).or_insert(Spent::Cancelled);
    }

    /// Drop the redemptions whose invites have expired at `now` (cancellations stay)
    pub fn prune(&mut self, now: u64) {
        self.spent.retain(|_, s| match s {
            Spent::Redeemed { not_after } => now < *not_after,
            Spent::Cancelled => true,
        });
    }

    /// The number of recorded ids
    #[must_use]
    pub fn len(&self) -> usize {
        self.spent.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spent.is_empty()
    }
}
