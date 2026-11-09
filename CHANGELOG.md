# Changelog

## [Unreleased]

### 破壊的変更

- 証明書の端末の識別子を発行者が与える値から、subject と device key から導く値にする: `device_id = SHA-256("alice-identity/device-id/v1" || subject の長さ (u16 BE) || subject || device_public)[..16]` (`DEVICE_ID_CONTEXT`) layout は同じで `DEVICE_CERT_VERSION` を 3 にする (version 2 は発行者が選んだ id を持つので `DeviceCertError::UnsupportedVersion(2)` で拒む) `DeviceCert::issue` は id の引数を取らず、`DeviceCert::from_bytes` は格納された id が導いた値と違うと新しい `DeviceCertError::DeviceIdMismatch` で拒む `DeviceCert::cert_id` を `DeviceCert::device_id` (`DeviceId` を返す) に置き換える 同じ鍵と subject の更新 (別の有効期間) は同じ id を持ち、発行者が 2 つの鍵に 1 つの id を与えることはできない
- 失効の一覧は `DeviceId` で引く: `RevocationList::issue` / `contains` / `revoked` と `CertRevocations::is_revoked` は `DeviceId` を取る (符号化は同じ) id を失効させると、その subject の下のその鍵の証明書がすべての期間で失効する
- 下流の利用側は 2.0 に移る必要がある: `DeviceCert::issue` は id の引数を取らず、証明書は version 3
- `IDENTITY_SEMANTICS_ID` を 195f53fb… から 44701b17… に移す (device certificate と artifact signature の pin が動く、signed claim / `did:key` / compact JWS は同じ)

- `DeviceCert` の layout を version 2 にする: body の device key の次に Noise の静的鍵 `noise_static` (X25519、32 byte) を置き、master の署名に含める `DEVICE_CERT_VERSION` は 2、`DEVICE_CERT_CONTEXT` は `alice-identity device-cert v2` `DeviceCert::issue` は `noise_static` を device key の次の引数に取る version 1 の証明書は `DeviceCert::from_bytes` が `DeviceCertError::UnsupportedVersion(1)` で拒む 証明書と artifact signature は 32 byte 長くなる
- 出力が hash の反復順に依存しないよう、map / set を順序つきにする (ALICE-Law G13) `Credential.claims` は `BTreeMap<String, String>`、`ClaimSchema.field_types` は `BTreeMap<String, String>`、`ClaimSchema::validate` の引数は `&BTreeMap<String, String>` 型の違う claim が複数ある時、`validate` は key の最も小さい claim の `InvalidClaimType` を返す `TrustGraph::trust_path` は同じ長さの経路のうち DID の小さい側を通る経路を返し、`TrustGraph::trustees_of` は DID の順に返す
- 証明書の subject (`did:method:id` の文字列) を `MAX_SUBJECT_LEN` (255 byte) までにする `DeviceCert::issue` と `DeviceCert::from_bytes` は超える subject を `DeviceCertError::SubjectTooLong` で拒む 証明書の長さは最大 `MAX_DEVICE_CERT_LEN` (450 byte)

### Added

- `device_cert::DeviceId` (16 byte、`derive` / `from_raw` / `as_bytes` / `Display` は小文字 hex) と `DEVICE_ID_CONTEXT`、試験 `tests/device_id.rs` (外部の hashlib で計算した 4 つの値、発行者が選んだ id を持つ正しく署名された証明書の拒否、version 2 の拒否、更新で同じ id、別名の subject と別の鍵で別の id、id の失効が更新にも効くこと)

- `artifact::SignedArtifact` / `artifact::Verified` / `artifact::bound_digest` / `SIGNED_ARTIFACT_VERSION`: law の参照と payload を、両方を束ねる成果物署名 (`SHA-256(law_ref || SHA-256(payload))`) と 1 つの単位で送る・保存する 部分は `SignedArtifact::open` からだけ読め、open は署名を先に確かめる (受信と保存からの読み戻しが同じ関数を呼ぶ) law の参照・payload・署名の書き換えと、古い署名のまま別の参照と payload に揃えた書き換えを断る 符号化は version (1) と 3 つの部分 (u32 BE の長さ付き) 試験 `tests/signed_artifact.rs` (配置を手で組んだ oracle、書き換え 4 通り、目的・master の違い、形の崩れ)
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
- CI: `actions/cache` を v6 に (v5 は廃止予定の node20 で動き、actionlint が error にする)
- 依存: alice-sign を rev の固定から `branch = "main"` に変える (同じ alice-sign を引く他の crate と同じ取り方にして、1 つの build に alice-sign が 1 つだけ入るようにする) 使う commit は Cargo.lock が決める
- CI (ALICE-Law G9 / G11): 識別子の移動の検査器 (`scripts/id_move_check.py` と試験) を共有の新しい bytes にし、新しく足した associated const を受けるようにした 他の共有の file も ALICE-Law 40973a8a の表が計画した bytes にし、shared-files と G11 の表の pin を上げた
- **Breaking:** `credential::VerifiableCredential` は alice-sign の `cred::SignedCredential` (issuer の `did:key` の Ed25519 鍵で署名、時刻窓 `[issued_at, expires_at)`) と `cred::claims::ClaimSet` (salt つきの claim の Merkle の根) になる `VerifiableCredential::issue(issuer, terms, claims, reserved_salts)` で発行し、`present(fields)` で一部の claim だけを見せる `CredentialPresentation` を作る 主体と種類は claim `@subject` / `@type` として常に見せる
- **Breaking:** `CredentialVerifier::verify(presentation, now, revoked)` は署名・時刻窓・失効・見せた claim が署名に覆われていることを確かめて `VerifiedClaims` を返す 以前は空でない `proof` を有効とし、期限の秒 (`now == expires_at`) を有効としていた 期限の秒からは `CredentialExpired`、`issued_at` の前は新しい `IdentityError::CredentialNotYetValid`
- 依存: alice-sign の pin を 8a1b00d8 から bb79209e (feature `cred`) に上げた その版の alice-sign は `LicenseRef-Proprietary` なので `deny.toml` に例外を足した
- **Breaking:** `VerifiableCredential::issue` は `@` で始まる claim の名前 (credential 自身の項目の予約) と、`expires_at` が `issued_at` の後でない (一度も有効にならない) 条件を `SchemaValidation` で断る `CredentialVerifier::verify` は別の credential の形式を新しい `IdentityError::UnsupportedCredentialFormat { stored, expected }`、署名に覆われない開示を新しい `IdentityError::DisclosureRefused` で返す
- **Breaking:** `VerifiablePresentation` は `CredentialPresentation` の列になり、何も確かめていなかった `proof` の field を除いた `selective_disclosure::SelectiveDisclosure` (署名を写したまま claim を減らしていた) を除き、`VerifiableCredential::present` に置き換えた
- CI (ALICE-Law G11): ALICE-Law の `scripts/g11_self_check.py` を pin の revision で全 OS の float-environment job と preflight で走らせる (表、表の行、共有の写し、自前の写しが目標か、manifest の 4 つ)
- CI (ALICE-Law G11): `scripts/id_move_check.py` と試験を ALICE-Law 4e694684 の表の目標の bytes (決め直した版) にし、`.github/shared-files-pin` をその rev に移した
- CI (ALICE-Law G11): `.github/shared-files-pin` と `.github/g11-table-pin` を ALICE-Law b4275beb に上げた (self-check が pin と crate の tree を commit した bytes で読むので、改行を変換する Windows の checkout でも検査する) 共有の写しの bytes は同じ
- CI (ALICE-Law G11): `.github/shared-files-pin` と `.github/g11-table-pin` を ALICE-Law 9cb423c9 に上げた (self-check が subprocess の出力を UTF-8 で読む) 共有の写しの bytes は同じ
- `.gitattributes` で text file を全 OS で LF で取り出す (Windows で共有の file が表の bytes と一致する)
- toolchain の pin を 1.92.0 から 1.98.1 にする (共有の検査器が読む rustdoc JSON の形式に合わせる) `RevocationList::from_bytes` の id の切り出しを `as_chunks` にする (bytes は変わらない)
- README の licence の節を `LicenseRef-Proprietary` の一文と問い合わせ先にする
