//! Content hash of what this crate produces for fixed keys: [`IDENTITY_SEMANTICS_ID`] (ALICE-Law G6)
//!
//! The recorded-bit tests in `tests/semantics_golden.rs` pin the bytes the crate produces from fixed Ed25519
//! seeds: a device certificate, an artifact signature, a signed claim set, a `did:key` and a compact JWS.
//! [`IDENTITY_SEMANTICS_ID`] folds those digests. The crate depends on no Law-bearing crate (alice-sign, which
//! gives it Ed25519 and SHA-256, has no identifier), so no upstream identifier is folded. Two builds with the
//! same identifier produce the same bytes for every pinned scenario.
//!
//! # Hex form
//!
//! ```text
//! 195f53fb4e6e8925246aab5037b41d17f792e8a2d14e2f439adaf4bf0815e029
//! ```
//!
//! # Fold
//!
//! The procedure of the `SEMANTICS_ID` fold of `alice-det-math`: sort the entries by name (ascending byte
//! order), then SHA-256 over, for each entry in that order, the name length as 4 bytes big-endian (`u32`), the
//! name bytes and the 32 digest bytes.
//!
//! # Independent of cargo features
//!
//! The table and the identifier are constants that no `cfg` gates (the crate has no features), so every build
//! reports the same identifier.
//!
//! # Staleness
//!
//! [`IDENTITY_SEMANTICS_CHECKED_AT`] names the crate version and toolchain the pins were last checked on; a
//! different version or toolchain fails `tests/identity_semantics_id.rs` until they are checked again.

/// Decodes 64 hex digits into 32 bytes at compile time; anything else is a compile error.
const fn hex32(s: &str) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not a lower-case hex digit"),
        }
    }
    let b = s.as_bytes();
    assert!(b.len() == 64, "a digest is 64 hex digits");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(b[2 * i]) * 16 + nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// The entries [`IDENTITY_SEMANTICS_ID`] folds: one per recorded-bit scenario of `tests/semantics_golden.rs`,
/// named as that file names it
pub const IDENTITY_SEMANTICS_PINS: &[(&str, [u8; 32])] = &[
    (
        "device certificate",
        hex32("5b007b2cc3f4e2238774eed0b02fa7c710b03e8e2251916740b46427c5cda418"),
    ),
    (
        "artifact signature",
        hex32("5c7e5cdbc180d7f888b1ea8e374b3a3ab3d8b6629101adfb33a654dbf2696b70"),
    ),
    (
        "signed claim",
        hex32("bcd9a6d8d8f3b424a0dc9e4b493b5ac17c5c15834e18727a9ff97686c4ed4b92"),
    ),
    (
        "did:key",
        hex32("f9c3f1afd7f5166ac217fe97df231353b8c3fd91f9f3b985ba033876a692c1b3"),
    ),
    (
        "compact jws",
        hex32("afc7989ada00fc73b7b5f5965998b9d69d63e85be747a2e1910c3bba3ba12898"),
    ),
];

/// The crate version and toolchain the pins were last checked against
pub const IDENTITY_SEMANTICS_CHECKED_AT: (&str, &str) = ("1.2.0", "1.98.1");

/// Content hash of what this crate produces for fixed keys: the fold of [`IDENTITY_SEMANTICS_PINS`]
/// described in the [module documentation](self)
pub const IDENTITY_SEMANTICS_ID: [u8; 32] =
    hex32("195f53fb4e6e8925246aab5037b41d17f792e8a2d14e2f439adaf4bf0815e029");
