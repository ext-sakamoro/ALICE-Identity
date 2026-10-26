# Changelog

## [Unreleased]

### 破壊的変更

- `DeviceCert` の layout を version 2 にする: body の device key の次に Noise の静的鍵 `noise_static` (X25519、32 byte) を置き、master の署名に含める `DEVICE_CERT_VERSION` は 2、`DEVICE_CERT_CONTEXT` は `alice-identity device-cert v2` `DeviceCert::issue` は `noise_static` を device key の次の引数に取る version 1 の証明書は `DeviceCert::from_bytes` が `DeviceCertError::UnsupportedVersion(1)` で拒む 証明書と artifact signature は 32 byte 長くなる
- 出力が hash の反復順に依存しないよう、map / set を順序つきにする (ALICE-Law G13) `Credential.claims` は `BTreeMap<String, String>`、`ClaimSchema.field_types` は `BTreeMap<String, String>`、`ClaimSchema::validate` の引数は `&BTreeMap<String, String>` 型の違う claim が複数ある時、`validate` は key の最も小さい claim の `InvalidClaimType` を返す `TrustGraph::trust_path` は同じ長さの経路のうち DID の小さい側を通る経路を返し、`TrustGraph::trustees_of` は DID の順に返す
- 証明書の subject (`did:method:id` の文字列) を `MAX_SUBJECT_LEN` (255 byte) までにする `DeviceCert::issue` と `DeviceCert::from_bytes` は超える subject を `DeviceCertError::SubjectTooLong` で拒む 証明書の長さは最大 `MAX_DEVICE_CERT_LEN` (450 byte)

### Added

- `conformance/g11.toml` (ALICE-Law の `g11_table_gen.py` で生成した G11 の表) と `.github/g11-table-pin` / `scripts/g11_table.sh` (CI の clippy job と preflight で表を検査) shared-files の pin を ALICE-Law 0f545c29 に上げる
- `alice-law-conformance.toml` (ALICE-Law G1〜G14 の状態と証跡、各 pass に測った変異) と `conformance/g11-own.toml` (G11 の表のこの repository の行)
- `semantics` module: `IDENTITY_SEMANTICS_ID` (固定の Ed25519 seed から作る device certificate、artifact signature、signed claim、`did:key`、compact JWS の bytes の digest を畳み込んだ 32 byte の識別子) / `IDENTITY_SEMANTICS_PINS` / `IDENTITY_SEMANTICS_CHECKED_AT` と、試験 `tests/semantics_golden.rs` / `tests/identity_semantics_id.rs`
- clippy.toml に float の超越関数 (52 項目)、float の max / min / clamp、時計 (`Instant` / `SystemTime`) の禁止を足す canary は 66 項目
- CI: release profile の試験 (x86_64 / aarch64)、float 環境 (ubuntu / macOS / Windows)、共有 file の照合、fma の否定の検査 (構文木と release IR)、byte の境界の走査、識別子の移動の検査、semver の検査
- `Did` に `PartialOrd` / `Ord` (method、次に id の順 = `did:method:id` の文字列の順)
- clippy の `disallowed-types` で `HashMap` / `HashSet` / `RandomState` を禁じ、canary (`scripts/clippy_canary.py`) で各項目が検出されることを CI と preflight で確かめる
- 試験 `tests/unspecified_order.rs`: 同じ長さの経路、挿入順の違う trustee、型の違う claim 2 件で出力の順を固定
- `DeviceCert::noise_static`
- `MAX_SUBJECT_LEN` / `MAX_DEVICE_CERT_LEN` / `DeviceCertError::SubjectTooLong`
- `artifact::max_encoded_len`: context の長さごとの、符号化した artifact signature の最大の長さ (最長の証明書の時)
- `Did::key_ed25519` / `Did::ed25519_public_key`: Ed25519 の公開鍵と `did:key` (multibase `z` + base58btc、multicodec `0xed 0x01`) の変換 読み戻しは別の method / multibase / multicodec、base58btc の外の文字、34 byte 以外の長さを `IdentityError::InvalidDid` で断る
- `base58` module (`encode` / `decode`、base58btc)

### Changed
- CI (ALICE-Law G11): ALICE-Law の `scripts/g11_self_check.py` を pin の revision で全 OS の float-environment job と preflight で走らせる (表、表の行、共有の写し、自前の写しが目標か、manifest の 4 つ)
- CI (ALICE-Law G11): `scripts/id_move_check.py` と試験を ALICE-Law 4e694684 の表の目標の bytes (決め直した版) にし、`.github/shared-files-pin` をその rev に移した
- CI (ALICE-Law G11): `.github/shared-files-pin` と `.github/g11-table-pin` を ALICE-Law b4275beb に上げた (self-check が pin と crate の tree を commit した bytes で読むので、改行を変換する Windows の checkout でも検査する) 共有の写しの bytes は同じ
- `.gitattributes` で text file を全 OS で LF で取り出す (Windows で共有の file が表の bytes と一致する)
- toolchain の pin を 1.92.0 から 1.98.1 にする (共有の検査器が読む rustdoc JSON の形式に合わせる) `RevocationList::from_bytes` の id の切り出しを `as_chunks` にする (bytes は変わらない)
- README の licence の節を `LicenseRef-Proprietary` の一文と問い合わせ先にする
