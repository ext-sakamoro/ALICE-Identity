//! Contact cards.
//!
//! What one person hands another (in person as a QR code, or pasted as text) so the
//! other can reach their devices and check their keys. The card carries no field a person fills in —
//! no name, no picture, no address — only the identity's did:key, its master key, the certificates of
//! its devices and the list of devices it has revoked, all signed by the master key.
//!
//! ```text
//! signed = CONTACT_CARD_CONTEXT || body
//! body   = version (1)
//!          || subject length (u16 BE) || subject (the did:key text of master_public)
//!          || master_public (32)
//!          || issued_at (u64 BE)
//!          || count (u8, 1 ..= MAX_CARD_CERTS) || (length (u16 BE) || DeviceCert bytes) * count
//!          || revocation length (u32 BE, 0 = none) || RevocationList bytes
//! bytes  = body || signature (64)
//! text   = CONTACT_CARD_TEXT_PREFIX || base32 (RFC 4648, upper case, no padding) of bytes
//! ```
//!
//! A card is accepted ([`ContactCard::from_bytes`]) only when the subject is the did:key of the master
//! key, the master's signature verifies strictly, every certificate was issued by that master for that
//! subject, the revocation list (when present) was issued by that master, and no carried certificate
//! is revoked by it. [`ContactCard::verify`] then checks each certificate's validity at `now` (the
//! caller passes `now`; this crate reads no clock).
//!
//! The short code ([`ContactCard::short_code`]) is the first 40 bits of
//! `SHA-256(CONTACT_CARD_SHORT_CODE_CONTEXT || bytes)` in Crockford base32, written `XXXX-XXXX`: two
//! people read it to each other to confirm they hold the same card. It is not a secret and does not
//! authenticate anything on its own.

use crate::base32;
use crate::cert_revocation::{RevocationList, RevocationListError};
use crate::device_cert::{DeviceCert, DeviceCertError, MAX_SUBJECT_LEN};
use crate::did::Did;
use alice_crypto::sha256::digest;
use alice_sign::{KeyPair, PublicKey, Signature};
use std::fmt;

/// The only card layout this version reads and writes
pub const CONTACT_CARD_VERSION: u8 = 1;

/// Prefixed to the body before signing (domain separation)
pub const CONTACT_CARD_CONTEXT: &[u8] = b"alice-identity contact-card v1";

/// Prefixed to the card bytes before the short code's hash
pub const CONTACT_CARD_SHORT_CODE_CONTEXT: &[u8] = b"alice-identity contact-card short-code v1";

/// The text form starts with this
pub const CONTACT_CARD_TEXT_PREFIX: &str = "ALICE-CARD:1:";

/// The most device certificates one card carries
pub const MAX_CARD_CERTS: usize = 16;

/// A signed contact card (see the module documentation)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactCard {
    subject: Did,
    master_public: [u8; 32],
    issued_at: u64,
    device_certs: Vec<DeviceCert>,
    revocations: Option<RevocationList>,
    signature: [u8; 64],
}

/// Why a card was not made, decoded or accepted
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactCardError {
    /// The layout version is not [`CONTACT_CARD_VERSION`]
    UnsupportedVersion(u8),
    /// The bytes do not hold one whole card (the reason names the part)
    Malformed(&'static str),
    /// The subject is not a did:key
    SubjectNotDidKey,
    /// The subject is a did:key of another key than the master key
    SubjectKeyMismatch,
    /// The master's signature does not verify (strictly) over the context and the body
    BadSignature,
    /// The card carries no device certificate
    NoCerts,
    /// The card carries more than [`MAX_CARD_CERTS`] certificates (their number is given)
    TooManyCerts(usize),
    /// The certificate at this index was issued by another master or for another subject
    CertIssuerMismatch(usize),
    /// The certificate at this index is revoked by the card's revocation list
    RevokedCert(usize),
    /// The certificate at this index does not decode or does not verify at `now`
    Cert(usize, DeviceCertError),
    /// The revocation list was issued by another master
    RevocationIssuerMismatch,
    /// The revocation list does not decode or does not verify
    Revocation(RevocationListError),
    /// The text is not the prefix followed by upper-case RFC 4648 base32
    BadText,
}

impl fmt::Display for ContactCardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(v) => write!(f, "contact card version {v} is not supported"),
            Self::Malformed(what) => write!(f, "malformed contact card: {what}"),
            Self::SubjectNotDidKey => f.write_str("the card's subject is not a did:key"),
            Self::SubjectKeyMismatch => {
                f.write_str("the card's subject is the did:key of another key than its master")
            }
            Self::BadSignature => f.write_str("the card's signature does not verify"),
            Self::NoCerts => f.write_str("the card carries no device certificate"),
            Self::TooManyCerts(n) => {
                write!(
                    f,
                    "the card carries {n} certificates, at most {MAX_CARD_CERTS}"
                )
            }
            Self::CertIssuerMismatch(i) => {
                write!(
                    f,
                    "certificate {i} is not issued by the card's master for its subject"
                )
            }
            Self::RevokedCert(i) => write!(f, "certificate {i} is revoked by the card's list"),
            Self::Cert(i, e) => write!(f, "certificate {i}: {e}"),
            Self::RevocationIssuerMismatch => {
                f.write_str("the revocation list is issued by another master")
            }
            Self::Revocation(e) => write!(f, "revocation list: {e}"),
            Self::BadText => f.write_str("not the text form of a contact card"),
        }
    }
}

impl std::error::Error for ContactCardError {}

/// The master key a did:key subject names, checked against `master_public`
pub(crate) fn did_key_matches(
    subject: &Did,
    master_public: &[u8; 32],
) -> Result<(), DidKeyMismatch> {
    if subject.method != "key" {
        return Err(DidKeyMismatch::NotDidKey);
    }
    let key = subject
        .ed25519_public_key()
        .map_err(|_| DidKeyMismatch::NotDidKey)?;
    if key.0 == *master_public {
        Ok(())
    } else {
        Err(DidKeyMismatch::OtherKey)
    }
}

/// Why a subject is not the did:key of a master key
pub(crate) enum DidKeyMismatch {
    NotDidKey,
    OtherKey,
}

impl From<DidKeyMismatch> for ContactCardError {
    fn from(e: DidKeyMismatch) -> Self {
        match e {
            DidKeyMismatch::NotDidKey => Self::SubjectNotDidKey,
            DidKeyMismatch::OtherKey => Self::SubjectKeyMismatch,
        }
    }
}

/// The checks shared by issue and decode: the count, each certificate's issuer and subject, the list's
/// issuer, and that no carried certificate is revoked
fn check_contents(
    subject: &Did,
    master_public: &[u8; 32],
    certs: &[DeviceCert],
    revocations: Option<&RevocationList>,
) -> Result<(), ContactCardError> {
    if certs.is_empty() {
        return Err(ContactCardError::NoCerts);
    }
    if certs.len() > MAX_CARD_CERTS {
        return Err(ContactCardError::TooManyCerts(certs.len()));
    }
    for (i, c) in certs.iter().enumerate() {
        if c.issuer_public() != master_public || c.subject() != subject {
            return Err(ContactCardError::CertIssuerMismatch(i));
        }
    }
    if let Some(list) = revocations {
        if list.issuer_public() != master_public {
            return Err(ContactCardError::RevocationIssuerMismatch);
        }
        list.verify(&PublicKey(*master_public))
            .map_err(ContactCardError::Revocation)?;
        if let Some(i) = certs.iter().position(|c| list.contains(&c.device_id())) {
            return Err(ContactCardError::RevokedCert(i));
        }
    }
    Ok(())
}

impl ContactCard {
    /// Sign a card for `master`'s did:key carrying `certs` and, when given, `revocations`
    ///
    /// # Errors
    /// [`ContactCardError::NoCerts`] / [`ContactCardError::TooManyCerts`] for the count,
    /// [`ContactCardError::CertIssuerMismatch`] for a certificate of another master or subject,
    /// [`ContactCardError::RevocationIssuerMismatch`] / [`ContactCardError::Revocation`] for the list,
    /// [`ContactCardError::RevokedCert`] when the list revokes a carried certificate
    pub fn issue(
        master: &KeyPair,
        certs: &[DeviceCert],
        revocations: Option<&RevocationList>,
        issued_at: u64,
    ) -> Result<Self, ContactCardError> {
        let public = master.public();
        let subject = Did::key_ed25519(&public);
        check_contents(&subject, &public.0, certs, revocations)?;
        let mut card = Self {
            subject,
            master_public: public.0,
            issued_at,
            device_certs: certs.to_vec(),
            revocations: revocations.cloned(),
            signature: [0; 64],
        };
        card.signature = master.sign(&card.signed_message()).0;
        Ok(card)
    }

    /// The bytes the master signs: the context and the body
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        let body = self.body();
        let mut m = Vec::with_capacity(CONTACT_CARD_CONTEXT.len() + body.len());
        m.extend_from_slice(CONTACT_CARD_CONTEXT);
        m.extend_from_slice(&body);
        m
    }

    fn body(&self) -> Vec<u8> {
        let subject = self.subject.to_string();
        let mut b = Vec::with_capacity(512);
        b.push(CONTACT_CARD_VERSION);
        b.extend_from_slice(
            &u16::try_from(subject.len())
                .expect("a did:key fits")
                .to_be_bytes(),
        );
        b.extend_from_slice(subject.as_bytes());
        b.extend_from_slice(&self.master_public);
        b.extend_from_slice(&self.issued_at.to_be_bytes());
        b.push(u8::try_from(self.device_certs.len()).expect("at most MAX_CARD_CERTS"));
        for c in &self.device_certs {
            let bytes = c.to_bytes();
            b.extend_from_slice(
                &u16::try_from(bytes.len())
                    .expect("a certificate fits")
                    .to_be_bytes(),
            );
            b.extend_from_slice(&bytes);
        }
        let list = self
            .revocations
            .as_ref()
            .map(RevocationList::to_bytes)
            .unwrap_or_default();
        b.extend_from_slice(
            &u32::try_from(list.len())
                .expect("a list fits")
                .to_be_bytes(),
        );
        b.extend_from_slice(&list);
        b
    }

    /// The card's bytes: the body and the signature
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.body();
        b.extend_from_slice(&self.signature);
        b
    }

    /// Decode and accept a card (every check of the module documentation except the certificates'
    /// validity at a time, which [`ContactCard::verify`] checks)
    ///
    /// # Errors
    /// The first failing check: layout, subject, signature, then the contents
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ContactCardError> {
        let mut r = Reader(bytes);
        let version = r.u8("version")?;
        if version != CONTACT_CARD_VERSION {
            return Err(ContactCardError::UnsupportedVersion(version));
        }
        let len = usize::from(r.u16("subject length")?);
        if len > MAX_SUBJECT_LEN {
            return Err(ContactCardError::Malformed("subject length"));
        }
        let text = std::str::from_utf8(r.take(len, "subject")?)
            .map_err(|_| ContactCardError::SubjectNotDidKey)?;
        let subject = Did::parse(text).map_err(|_| ContactCardError::SubjectNotDidKey)?;
        let master_public: [u8; 32] = r.array("master key")?;
        did_key_matches(&subject, &master_public)?;

        let issued_at = r.u64("issued at")?;
        let count = usize::from(r.u8("certificate count")?);
        let mut device_certs = Vec::with_capacity(count);
        for i in 0..count {
            let n = usize::from(r.u16("certificate length")?);
            let c = DeviceCert::from_bytes(r.take(n, "certificate")?)
                .map_err(|e| ContactCardError::Cert(i, e))?;
            device_certs.push(c);
        }
        let n = usize::try_from(r.u32("revocation length")?)
            .map_err(|_| ContactCardError::Malformed("revocation length"))?;
        let revocations = if n == 0 {
            None
        } else {
            Some(
                RevocationList::from_bytes(r.take(n, "revocation list")?)
                    .map_err(ContactCardError::Revocation)?,
            )
        };
        let signature: [u8; 64] = r.array("signature")?;
        if !r.0.is_empty() {
            return Err(ContactCardError::Malformed("bytes after the signature"));
        }
        let card = Self {
            subject,
            master_public,
            issued_at,
            device_certs,
            revocations,
            signature,
        };
        // the decoded fields must encode back to the same body, so the signature covers exactly them
        if card.to_bytes() != bytes {
            return Err(ContactCardError::Malformed("not the canonical encoding"));
        }
        if !PublicKey(master_public).verify_strict(&card.signed_message(), &Signature(signature)) {
            return Err(ContactCardError::BadSignature);
        }
        check_contents(
            &card.subject,
            &card.master_public,
            &card.device_certs,
            card.revocations.as_ref(),
        )?;
        Ok(card)
    }

    /// Check every carried certificate at `now` (each must be valid then: issued at most
    /// `MAX_CLOCK_SKEW_SECS` ahead of `now` and not expired)
    ///
    /// # Errors
    /// [`ContactCardError::Cert`] with the index of the first certificate that does not verify
    pub fn verify(&self, now: u64) -> Result<(), ContactCardError> {
        let master = PublicKey(self.master_public);
        for (i, c) in self.device_certs.iter().enumerate() {
            c.verify(&master, now)
                .map_err(|e| ContactCardError::Cert(i, e))?;
        }
        Ok(())
    }

    /// The text form: [`CONTACT_CARD_TEXT_PREFIX`] and the base32 of the bytes
    #[must_use]
    pub fn to_text(&self) -> String {
        format!(
            "{CONTACT_CARD_TEXT_PREFIX}{}",
            base32::encode(&self.to_bytes())
        )
    }

    /// Decode and accept the text form (as [`ContactCard::from_bytes`])
    ///
    /// # Errors
    /// [`ContactCardError::BadText`] when the text is not the prefix and upper-case base32, then the
    /// errors of [`ContactCard::from_bytes`]
    pub fn from_text(text: &str) -> Result<Self, ContactCardError> {
        let body = text
            .strip_prefix(CONTACT_CARD_TEXT_PREFIX)
            .ok_or(ContactCardError::BadText)?;
        if body.is_empty() {
            return Err(ContactCardError::BadText);
        }
        let bytes = base32::decode(body).ok_or(ContactCardError::BadText)?;
        Self::from_bytes(&bytes)
    }

    /// The short code two people read to each other: `XXXX-XXXX` (see the module documentation)
    #[must_use]
    pub fn short_code(&self) -> String {
        let mut m = CONTACT_CARD_SHORT_CODE_CONTEXT.to_vec();
        m.extend_from_slice(&self.to_bytes());
        let code = base32::crockford_prefix(&digest(&m)[..5], 8);
        format!("{}-{}", &code[..4], &code[4..])
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
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    #[must_use]
    pub fn device_certs(&self) -> &[DeviceCert] {
        &self.device_certs
    }

    #[must_use]
    pub const fn revocations(&self) -> Option<&RevocationList> {
        self.revocations.as_ref()
    }
}

/// Reads the fields of a card from the front of its bytes
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    const fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], ContactCardError> {
        if self.0.len() < n {
            return Err(ContactCardError::Malformed(what));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], ContactCardError> {
        Ok(self.take(N, what)?.try_into().expect("N bytes"))
    }

    fn u8(&mut self, what: &'static str) -> Result<u8, ContactCardError> {
        Ok(self.take(1, what)?[0])
    }

    fn u16(&mut self, what: &'static str) -> Result<u16, ContactCardError> {
        Ok(u16::from_be_bytes(self.array(what)?))
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, ContactCardError> {
        Ok(u32::from_be_bytes(self.array(what)?))
    }

    fn u64(&mut self, what: &'static str) -> Result<u64, ContactCardError> {
        Ok(u64::from_be_bytes(self.array(what)?))
    }
}
