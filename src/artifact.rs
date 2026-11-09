//! Artifact signatures: a device key signs the digest of any artifact for one stated purpose
//!
//! The device key is the one a [`DeviceCert`] names; the verifier checks the certificate against
//! the subject's master key and its revocation list, then the signature. The caller states the
//! purpose as a context (such as `alice-mls/artifact/v1`) and the verifier must name the context it
//! expects, so a signature made for one purpose never verifies for another.
//!
//! Only a digest is signed. Bind everything the signature must protect into that one digest: a
//! carrier that signs a payload under a law reference passes `SHA-256(law_ref || payload_digest)`,
//! so the same payload under another law reference has another signature.
//!
//! ```text
//! signed = ARTIFACT_DOMAIN || u8 context length || context || u8 digest algorithm
//!          || SHA-256 of the whole certificate (32)
//! bytes  = u8 version (1) || u8 context length || context || u8 digest algorithm
//!          || digest (32) || u16 BE certificate length || certificate || signature (64)
//! ```
//!
//! The fixed domain keeps the signed message apart from those of the device certificate and the
//! revocation list; the length prefix keeps context and digest apart; the digest of the whole
//! certificate ties the signature to that certificate (issuer, subject, window and id), so another
//! issuer's certificate for the same device key, even with the same id, does not carry it.
//! Verification is strict (it refuses a non-canonical scalar and small-order keys).

use alice_sign::{hash_data, KeyPair, PublicKey, Signature};

use crate::cert_revocation::CertRevocations;
use crate::device_cert::{DeviceCert, DeviceCertError};

/// The domain every artifact signature's message starts with
pub const ARTIFACT_DOMAIN: &[u8] = b"alice-identity artifact v1";

/// The version of the encoding
pub const ARTIFACT_VERSION: u8 = 1;

/// The longest context, in bytes
pub const MAX_CONTEXT_LEN: usize = 64;

/// The longest encoded [`ArtifactSignature`] for a context of `context_len` bytes: one carrying a certificate
/// of [`crate::device_cert::MAX_DEVICE_CERT_LEN`] bytes
#[must_use]
pub const fn max_encoded_len(context_len: usize) -> usize {
    // version, context length, context, digest algorithm, digest, certificate length, certificate, signature
    1 + 1 + context_len + 1 + 32 + 2 + crate::device_cert::MAX_DEVICE_CERT_LEN + 64
}

/// The digest algorithm of a [`PayloadDigest`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlg {
    /// SHA-256 (code 1)
    Sha256,
}

impl DigestAlg {
    const fn code(self) -> u8 {
        match self {
            Self::Sha256 => 1,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Sha256),
            _ => None,
        }
    }
}

/// The digest of an artifact, computed by the caller
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadDigest {
    alg: DigestAlg,
    bytes: [u8; 32],
}

impl PayloadDigest {
    /// A SHA-256 digest the caller computed
    #[must_use]
    pub const fn sha256(bytes: [u8; 32]) -> Self {
        Self {
            alg: DigestAlg::Sha256,
            bytes,
        }
    }

    #[must_use]
    pub const fn alg(&self) -> DigestAlg {
        self.alg
    }

    #[must_use]
    pub const fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

/// The SHA-256 digest of `payload`
#[must_use]
pub fn sha256_payload(payload: &[u8]) -> PayloadDigest {
    PayloadDigest::sha256(hash_data(payload).0)
}

/// Why an artifact signature was not made, decoded or accepted
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    /// The context is empty, longer than [`MAX_CONTEXT_LEN`], not printable ASCII, or starts or
    /// ends with a space
    InvalidContext,
    /// The signing key is not the device key the certificate names
    KeyMismatch,
    /// The encoding version is not [`ARTIFACT_VERSION`]
    UnsupportedVersion(u8),
    /// The digest algorithm code is unknown
    UnsupportedDigest(u8),
    /// The bytes do not hold one whole signature (the reason names the field)
    Malformed(&'static str),
    /// The signature was made for another context than the one expected
    ContextMismatch,
    /// The signature covers another digest than the one expected
    DigestMismatch,
    /// The device certificate does not decode or does not verify
    Cert(DeviceCertError),
    /// The device certificate is revoked
    Revoked,
    /// The signature does not verify (strictly) under the certificate's device key
    BadSignature,
}

impl std::fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidContext => f.write_str("the context is not 1 to 64 printable ASCII bytes"),
            Self::KeyMismatch => f.write_str("the signing key is not the certificate's device key"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported artifact signature version {v}"),
            Self::UnsupportedDigest(a) => write!(f, "unsupported digest algorithm {a}"),
            Self::Malformed(what) => write!(f, "malformed artifact signature: {what}"),
            Self::ContextMismatch => f.write_str("the signature was made for another context"),
            Self::DigestMismatch => f.write_str("the signature covers another digest"),
            Self::Cert(e) => write!(f, "device certificate: {e}"),
            Self::Revoked => f.write_str("the device certificate is revoked"),
            Self::BadSignature => f.write_str("the artifact signature does not verify"),
        }
    }
}

impl std::error::Error for ArtifactError {}

fn check_context(context: &[u8]) -> Result<(), ArtifactError> {
    let printable = context.iter().all(|b| (0x20..=0x7e).contains(b));
    if context.is_empty()
        || context.len() > MAX_CONTEXT_LEN
        || !printable
        || context.first() == Some(&b' ')
        || context.last() == Some(&b' ')
    {
        return Err(ArtifactError::InvalidContext);
    }
    Ok(())
}

/// A device key's signature over an artifact digest, with the certificate that names the key
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSignature {
    context: Vec<u8>,
    digest: PayloadDigest,
    cert: DeviceCert,
    signature: [u8; 64],
}

impl ArtifactSignature {
    /// The bytes the signature covers (see the module documentation)
    #[must_use]
    pub fn signed_message(&self) -> Vec<u8> {
        let mut m = ARTIFACT_DOMAIN.to_vec();
        // the context length is at most MAX_CONTEXT_LEN, checked on every way in
        m.extend_from_slice(&[u8::try_from(self.context.len()).unwrap_or(u8::MAX)]);
        m.extend_from_slice(&self.context);
        m.extend_from_slice(&[self.digest.alg.code()]);
        m.extend_from_slice(&self.digest.bytes);
        m.extend_from_slice(&hash_data(&self.cert.to_bytes()).0);
        m
    }

    /// The encoding (see the module documentation)
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let cert = self.cert.to_bytes();
        let mut b = vec![ARTIFACT_VERSION];
        b.extend_from_slice(&[u8::try_from(self.context.len()).unwrap_or(u8::MAX)]);
        b.extend_from_slice(&self.context);
        b.extend_from_slice(&[self.digest.alg.code()]);
        b.extend_from_slice(&self.digest.bytes);
        // signing refuses a longer certificate, and decoding reads at most u16::MAX bytes
        b.extend_from_slice(&u16::try_from(cert.len()).unwrap_or(u16::MAX).to_be_bytes());
        b.extend_from_slice(&cert);
        b.extend_from_slice(&self.signature);
        b
    }

    /// Decode exactly one signature
    ///
    /// # Errors
    /// [`ArtifactError::UnsupportedVersion`], [`ArtifactError::UnsupportedDigest`],
    /// [`ArtifactError::InvalidContext`], [`ArtifactError::Cert`] when the certificate does not
    /// decode, or [`ArtifactError::Malformed`] when a field is cut short or bytes follow
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArtifactError> {
        let mut r = Reader(bytes);
        let version = r.take(1, "version")?[0];
        if version != ARTIFACT_VERSION {
            return Err(ArtifactError::UnsupportedVersion(version));
        }
        let context_len = usize::from(r.take(1, "context length")?[0]);
        let context = r.take(context_len, "context")?.to_vec();
        check_context(&context)?;
        let code = r.take(1, "digest algorithm")?[0];
        let alg = DigestAlg::from_code(code).ok_or(ArtifactError::UnsupportedDigest(code))?;
        let mut digest = [0u8; 32];
        digest.copy_from_slice(r.take(32, "digest")?);
        let cert_len = r.take(2, "certificate length")?;
        let cert_len = usize::from(u16::from_be_bytes([cert_len[0], cert_len[1]]));
        let cert = DeviceCert::from_bytes(r.take(cert_len, "certificate")?)
            .map_err(ArtifactError::Cert)?;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(r.take(64, "signature")?);
        if !r.0.is_empty() {
            return Err(ArtifactError::Malformed("bytes after the signature"));
        }
        Ok(Self {
            context,
            digest: PayloadDigest { alg, bytes: digest },
            cert,
            signature,
        })
    }

    #[must_use]
    pub fn context(&self) -> &[u8] {
        &self.context
    }

    #[must_use]
    pub const fn digest(&self) -> &PayloadDigest {
        &self.digest
    }

    #[must_use]
    pub const fn cert(&self) -> &DeviceCert {
        &self.cert
    }

    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    const fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], ArtifactError> {
        if self.0.len() < n {
            return Err(ArtifactError::Malformed(what));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }
}

/// Whether the verifier checks the certificate against a revocation list
///
/// Skipping the check is a statement the caller makes, not a default: pass
/// [`Revocation::NoListAvailable`] only when no revocation list for the issuer is held.
#[derive(Debug, Clone, Copy)]
pub enum Revocation<'a> {
    /// Refuse a certificate the issuer's newest list in these revocations revokes
    Checked(&'a CertRevocations),
    /// No revocation list is held for the issuer; revocation is not checked
    NoListAvailable,
}

/// Sign `digest` for `context` with the device key `cert` names
///
/// Bind everything the signature must protect into `digest` (see the module documentation).
///
/// # Errors
/// [`ArtifactError::InvalidContext`], [`ArtifactError::KeyMismatch`] when `device` is not the
/// key the certificate names, or [`ArtifactError::Malformed`] when the certificate is longer than
/// the encoding's 16-bit length field
pub fn sign_artifact(
    device: &KeyPair,
    cert: &DeviceCert,
    context: &[u8],
    digest: &PayloadDigest,
) -> Result<ArtifactSignature, ArtifactError> {
    check_context(context)?;
    if device.public().0 != *cert.device_public() {
        return Err(ArtifactError::KeyMismatch);
    }
    if cert.to_bytes().len() > usize::from(u16::MAX) {
        return Err(ArtifactError::Malformed(
            "certificate longer than 65535 bytes",
        ));
    }
    let mut sig = ArtifactSignature {
        context: context.to_vec(),
        digest: *digest,
        cert: cert.clone(),
        signature: [0; 64],
    };
    sig.signature = device.sign(&sig.signed_message()).0;
    Ok(sig)
}

/// Accept `sig` when it was made for `expected_context` over `expected_digest` by a device whose
/// certificate `master` issued, valid at `now` and not revoked by `revocation`
///
/// # Errors
/// In this order: [`ArtifactError::InvalidContext`] (the expected context),
/// [`ArtifactError::ContextMismatch`], [`ArtifactError::DigestMismatch`],
/// [`ArtifactError::Cert`] (issuer, signature, validity at `now`), [`ArtifactError::Revoked`],
/// [`ArtifactError::BadSignature`]
pub fn verify_artifact(
    sig: &ArtifactSignature,
    master: &PublicKey,
    expected_context: &[u8],
    expected_digest: &PayloadDigest,
    now: u64,
    revocation: Revocation<'_>,
) -> Result<(), ArtifactError> {
    check_context(expected_context)?;
    if sig.context != expected_context {
        return Err(ArtifactError::ContextMismatch);
    }
    if sig.digest != *expected_digest {
        return Err(ArtifactError::DigestMismatch);
    }
    sig.cert.verify(master, now).map_err(ArtifactError::Cert)?;
    if let Revocation::Checked(list) = revocation {
        if list.revokes(&sig.cert) {
            return Err(ArtifactError::Revoked);
        }
    }
    let device = PublicKey(*sig.cert.device_public());
    if !device.verify_strict(&sig.signed_message(), &Signature(sig.signature)) {
        return Err(ArtifactError::BadSignature);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SignedArtifact: a law reference and a payload kept or carried with the signature that binds them
// ---------------------------------------------------------------------------

/// The version of the [`SignedArtifact`] encoding
pub const SIGNED_ARTIFACT_VERSION: u8 = 1;

/// The digest a [`SignedArtifact`] signs: `SHA-256(law_ref || SHA-256(payload))`
///
/// The payload digest has a fixed length at the end, so no other `(law_ref, payload)` gives the
/// same input: the same payload under another law reference, or another payload under the same
/// one, has another digest.
#[must_use]
pub fn bound_digest(law_ref: &[u8], payload: &[u8]) -> PayloadDigest {
    let mut both = law_ref.to_vec();
    both.extend_from_slice(&hash_data(payload).0);
    PayloadDigest::sha256(hash_data(&both).0)
}

/// A law reference and a payload with the artifact signature that binds them (see
/// [`bound_digest`]), as one unit to send or to store
///
/// ```text
/// bytes = u8 version (1) || u32 BE law_ref length || law_ref
///         || u32 BE payload length || payload
///         || u32 BE signature length || ArtifactSignature bytes
/// ```
///
/// Its parts are read only through [`SignedArtifact::open`], which checks the signature first: a
/// receiver and a reader of storage call the same function, so a unit read back from storage is
/// held to what a received one is. A unit whose law reference or payload was changed, or rewritten
/// together with the signature of other ones, is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedArtifact {
    law_ref: Vec<u8>,
    payload: Vec<u8>,
    signature: ArtifactSignature,
}

/// The parts of a [`SignedArtifact`] whose signature [`SignedArtifact::open`] accepted
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    law_ref: Vec<u8>,
    payload: Vec<u8>,
    signature: ArtifactSignature,
}

impl Verified {
    /// The law reference the signature covers
    #[must_use]
    pub fn law_ref(&self) -> &[u8] {
        &self.law_ref
    }

    /// The payload the signature covers
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The signature that was accepted
    #[must_use]
    pub const fn signature(&self) -> &ArtifactSignature {
        &self.signature
    }
}

impl SignedArtifact {
    /// Sign `law_ref` and `payload` together for `context` with the device key `cert` names
    ///
    /// # Errors
    /// As [`sign_artifact`], and [`ArtifactError::Malformed`] when a part is longer than the
    /// encoding's 32-bit length field
    pub fn sign(
        device: &KeyPair,
        cert: &DeviceCert,
        context: &[u8],
        law_ref: &[u8],
        payload: &[u8],
    ) -> Result<Self, ArtifactError> {
        if u32::try_from(law_ref.len()).is_err() || u32::try_from(payload.len()).is_err() {
            return Err(ArtifactError::Malformed(
                "a part longer than 2^32 - 1 bytes",
            ));
        }
        let signature = sign_artifact(device, cert, context, &bound_digest(law_ref, payload))?;
        Ok(Self {
            law_ref: law_ref.to_vec(),
            payload: payload.to_vec(),
            signature,
        })
    }

    /// The encoding (see the type documentation)
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let signature = self.signature.to_bytes();
        let mut b = vec![SIGNED_ARTIFACT_VERSION];
        for part in [&self.law_ref[..], &self.payload[..], &signature[..]] {
            // signing refuses a longer part, and a signature is far shorter
            b.extend_from_slice(&u32::try_from(part.len()).unwrap_or(u32::MAX).to_be_bytes());
            b.extend_from_slice(part);
        }
        b
    }

    /// Decode `bytes` and accept them only when the signature was made for `expected_context` over
    /// [`bound_digest`] of the law reference and the payload they carry, by a device whose
    /// certificate `master` issued, valid at `now` and not revoked by `revocation`
    ///
    /// The one way in for both a received unit and one read back from storage.
    ///
    /// # Errors
    /// [`ArtifactError::UnsupportedVersion`] or [`ArtifactError::Malformed`] when the bytes are not
    /// one unit, then as [`ArtifactSignature::from_bytes`] and [`verify_artifact`]: a changed law
    /// reference or payload is [`ArtifactError::DigestMismatch`], a changed signature
    /// [`ArtifactError::BadSignature`]
    pub fn open(
        bytes: &[u8],
        master: &PublicKey,
        expected_context: &[u8],
        now: u64,
        revocation: Revocation<'_>,
    ) -> Result<Verified, ArtifactError> {
        let mut r = Reader(bytes);
        let version = r.take(1, "version")?[0];
        if version != SIGNED_ARTIFACT_VERSION {
            return Err(ArtifactError::UnsupportedVersion(version));
        }
        let law_ref = take_part(&mut r, "law reference")?;
        let payload = take_part(&mut r, "payload")?;
        let signature = ArtifactSignature::from_bytes(take_part(&mut r, "signature")?)?;
        if !r.0.is_empty() {
            return Err(ArtifactError::Malformed("bytes after the signature"));
        }
        verify_artifact(
            &signature,
            master,
            expected_context,
            &bound_digest(law_ref, payload),
            now,
            revocation,
        )?;
        Ok(Verified {
            law_ref: law_ref.to_vec(),
            payload: payload.to_vec(),
            signature,
        })
    }
}

fn take_part<'a>(r: &mut Reader<'a>, what: &'static str) -> Result<&'a [u8], ArtifactError> {
    let len = r.take(4, what)?;
    let len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]);
    // a length past the end is refused by take; usize holds every u32 on the targets this builds for
    let len = usize::try_from(len).map_err(|_| ArtifactError::Malformed(what))?;
    r.take(len, what)
}
