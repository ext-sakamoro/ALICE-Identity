# Changelog

## [Unreleased]

### 破壊的変更

- 版を 3.0.0 にする 利用側は `alice-identity` の要求を "3.0" に上げる (git main から取る crate も同じ、"2.0" のままでは解決しない)
- 公開の error enum 8 つ (`IdentityError` / `RevocationListError` / `DeviceCertError` / `InviteError` / `ContactCardError` / `ArtifactError` / `SafetyNumberError` / `ResolveError`) を `#[non_exhaustive]` にする crate の外で網羅 match している箇所は `_` の腕が要る 以後 variant を足しても破壊的変更にならない
- 失効は戻らない: `CertRevocations::accept` は、保持中の一覧が失効させている端末を 1 つでも落とす新しい一覧 (sequence が高くても) を `RevocationListError::DropsRevoked { device_id }` (新しい variant) で拒否し、保持中の一覧を残す 以前は sequence が高ければ受け入れたので、新しい一覧で失効を取り消せた

- 証明書の端末の識別子を発行者が与える値から、subject と device key から導く値にする: `device_id = SHA-256("alice-identity/device-id/v1" || subject の長さ (u16 BE) || subject || device_public)[..16]` (`DEVICE_ID_CONTEXT`) layout は同じで `DEVICE_CERT_VERSION` を 3 にする (version 2 は発行者が選んだ id を持つので `DeviceCertError::UnsupportedVersion(2)` で拒む) `DeviceCert::issue` は id の引数を取らず、`DeviceCert::from_bytes` は格納された id が導いた値と違うと新しい `DeviceCertError::DeviceIdMismatch` で拒む `DeviceCert::cert_id` を `DeviceCert::device_id` (`DeviceId` を返す) に置き換える 同じ鍵と subject の更新 (別の有効期間) は同じ id を持ち、発行者が 2 つの鍵に 1 つの id を与えることはできない
- 失効の一覧は `DeviceId` で引く: `RevocationList::issue` / `contains` / `revoked` と `CertRevocations::is_revoked` は `DeviceId` を取る (符号化は同じ) id を失効させると、その subject の下のその鍵の証明書がすべての期間で失効する
- 下流の利用側は 2.0 に移る必要がある: `DeviceCert::issue` は id の引数を取らず、証明書は version 3
- `IDENTITY_SEMANTICS_ID` を 195f53fb… から 76603ef9… に移す (device certificate と artifact signature の pin が動く、signed claim / `did:key` / compact JWS は同じ、2.0.0 の公開前に contact card / invite / safety number の 3 つの pin を足したので途中の値 44701b17… からも動く)

- `DeviceCert` の layout を version 2 にする: body の device key の次に Noise の静的鍵 `noise_static` (X25519、32 byte) を置き、master の署名に含める `DEVICE_CERT_VERSION` は 2、`DEVICE_CERT_CONTEXT` は `alice-identity device-cert v2` `DeviceCert::issue` は `noise_static` を device key の次の引数に取る version 1 の証明書は `DeviceCert::from_bytes` が `DeviceCertError::UnsupportedVersion(1)` で拒む 証明書と artifact signature は 32 byte 長くなる
- 出力が hash の反復順に依存しないよう、map / set を順序つきにする (ALICE-Law G13) `Credential.claims` は `BTreeMap<String, String>`、`ClaimSchema.field_types` は `BTreeMap<String, String>`、`ClaimSchema::validate` の引数は `&BTreeMap<String, String>` 型の違う claim が複数ある時、`validate` は key の最も小さい claim の `InvalidClaimType` を返す `TrustGraph::trust_path` は同じ長さの経路のうち DID の小さい側を通る経路を返し、`TrustGraph::trustees_of` は DID の順に返す
- 証明書の subject (`did:method:id` の文字列) を `MAX_SUBJECT_LEN` (255 byte) までにする `DeviceCert::issue` と `DeviceCert::from_bytes` は超える subject を `DeviceCertError::SubjectTooLong` で拒む 証明書の長さは最大 `MAX_DEVICE_CERT_LEN` (450 byte)

### Added
- `service_cert` module: サービス (例 relay) の署名鍵と Noise の静的鍵を、運用者の master 鍵が期限付きで保証する証明書 新しい byte layout は作らず、version 3 の `DeviceCert` の subject を予約した DID `did:alice-service:<service>` (`SERVICE_DID_METHOD` = `alice-service`) にしたもの `IDENTITY_SEMANTICS_ID` は動かない サービス名は 1〜`MAX_SERVICE_NAME_LEN` (63) byte の `a-z` / `0-9` / `-` で、`-` で始まらず終わらない (違反は `ServiceCertError::BadServiceName`) `issue_service_cert` は有効期間 (`not_after - issued_at`) が `SERVICE_CERT_MAX_LIFETIME_SECS` (30 日) を超えると `LifetimeTooLong` で拒み、`verify_service_cert(cert, master, service, now, revocation)` は名前・`DeviceCert::verify` (発行者・署名・有効期間の窓)・subject (別の method は `NotAService`、別のサービスは `WrongService`)・30 日の上限・失効 (`Revoked`) の順に確かめて Noise の静的鍵を返す 更新は同じ鍵で新しい証明書を発行し、`DeviceId` は subject と署名鍵から導くので同じ id を保ち、id の失効は更新にも効く 署名する master 鍵は運用者の offline の鍵で、サービスと一緒に配置しない 試験 `tests/service_cert.rs` (19、符号化の golden は Python の hashlib と PyNaCl で外部計算、CI の test / release job で件数つき) 変異 12 件 (subject の検査を外す・method の検査を外す・上限の境界を verify と issue で 1 ずらす・失効を無視・`DeviceCert::verify` を飛ばす・上限の検査を verify と issue で外す・名前規則の 3 箇所・Noise 鍵でなく署名鍵を返す) はすべて red

- CI: 他の crate の `PREVIOUS_*_SEMANTICS_IDS` は一覧全体としてだけ使える (`contains` / `len` / `is_empty`、全体を回す iterator や for、引数として丸ごと渡す) とし、添字・slice のパターン・`.first` / `next` / `take` などを拒む `scripts/upstream_previous_ids_check.py` と試験を足した (ALICE-Edge と同じ中身の共有 file) 上流は major で一覧を空にする 走査した .rs が 0 件なら失敗 (ci.yml と preflight)

- `master_recovery` module (feature `recovery`、OS の乱数源を使うので既定では off、既定の build は wasm32-unknown-unknown のまま): 端末を失った時に同じ DID のまま master 鍵を戻す 復旧 code (`alice_crypto::recovery_code`) で seed を封じる `MasterRecoveryBlob` (AD は文脈 + master 公開鍵) と、k-of-n の share に分ける `split_master` / 戻す `recover_master` 戻した seed の公開鍵が DID の鍵でなければ使わない (DID が改ざんの検査になり、前もって鍵を持たずに変えた share や他人の blob を拒否する) k 枚より多い時は DID の鍵を返す組のうち多項式が最も多くの share を通る組を使い、外れた share の x を返す (k 枚以上が本物なら正確) 組の数が `MAX_RECOVERY_SETS` (4096) を超える探索は `TooManyShares` で拒否 (全部が 1 つの多項式に乗る時は探索しない) 試験 `tests/master_recovery.rs` (10 本) と CI の段 (feature recovery の試験を件数つきで、clippy も) 変異 9 件 (失効の落としを受ける・extend が前の id を持たない・sequence を進めない・発行者を見ない・seed の鍵を比べない・全部が乗る近道を外す・最多の組でなく最初の組・外れを名指さない・探索の上限なし) はすべて red
- `RevocationList::extend(master, issued_at, more)`: 前の一覧の端末を全部持ち、`more` を足して次の sequence で署名した一覧 発行者でない鍵は `IssuerMismatch`、sequence が `u64::MAX` の一覧は `Malformed`

- `contact_card::ContactCard`: 人に渡す連絡先カード (QR / 貼り付け) 中身は did:key・master key・端末証明書 (1〜`MAX_CARD_CERTS` = 16 枚)・失効の一覧だけで、人が書き込む欄 (名前・画像・住所) は無い master が署名し (`CONTACT_CARD_CONTEXT`)、`from_bytes` は subject が master の did:key であること・署名・各証明書の発行者と subject・失効の一覧の発行者・失効した端末を載せていないことを確かめる `verify(now)` は各証明書を `now` で確かめる 文字列形 `ALICE-CARD:1:` + base32 (RFC 4648、大文字、padding なし、QR の英数字 mode に入る)、照合用の短い code `short_code()` (SHA-256 の先頭 40 bit を Crockford base32 で `XXXX-XXXX`)
- `invite::Invite` / `InviteRedemptions`: 1 回限りの署名付き招待 (did:key・鍵・呼び出し側が渡す 16 byte の id・有効期間、`INVITE_CONTEXT`) 有効期間は端末証明書と同じ規則 (始まりに `MAX_CLOCK_SKEW_SECS` の猶予、終わりは無し) 発行者の `InviteRedemptions` が `redeem` で 1 回だけ受け (2 回目は `AlreadyRedeemed`、他の発行者のものは `WrongIssuer`)、`cancel(invite_id)` で使う前に取り消し (`Cancelled`)、`prune(now)` で期限切れの記録を捨てる 文字列形 `ALICE-INVITE:1:` + base32
- `safety_number::safety_number(a, b)`: 2 人の master 公開鍵から決まる 60 桁の数字 (各自 SHA-256 を 5200 回反復して 30 桁、昇順に連結) どちらの側でも同じで、どちらかの鍵の 1 bit でも変わると変わる QR で照合する 64 byte (`as_bytes`) 同じ鍵 2 つは `SameParty`
- `base32` module (RFC 4648 と Crockford)
- 依存に alice-crypto (git main、0.7、`default-features = false, features = ["sha256"]`) を足し、安全番号と短い code の SHA-256 をそこから取る (`rng` を持たないので OS の乱数源を link せず、wasm32-unknown-unknown でも build できる)
- 試験: `tests/contact_card.rs` (13) / `tests/invite.rs` (11) / `tests/safety_number.rs` (5、1 bit の反転 512 通り) / `tests/no_network.rs` (src に通信・時計の呼び出しが 0 件、依存に通信の crate が無い) 期待値は Python の独立実装 `scripts/gen_contact_vectors.py` (hashlib・base64・pynacl) の出力 `tests/data/contact_vectors.json` 手で入れた変異 13 本は全て red `tests/semantics_golden.rs` に contact card / invite / safety number の pin を足した (digest は vector の bytes を外部で計算)
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
- feature `recovery`: `master_recovery` の内部で seed を 32 byte に写した複製を使い終わりに消す (`zeroize`、alice-crypto 経由で既に build に入っている crate) 呼び出し側の seed は既に消える buffer
- 手元の `scripts/preflight.sh` を生成し直す: SHA で固定した `dtolnay/rust-toolchain` の commit を toolchain と読んで `has_toolchain` で毎回止まっていた (toolchain は `rust-toolchain.toml` に従う)
- 検証の変更: `DeviceCert::verify` は `issued_at <= now + MAX_CLOCK_SKEW_SECS` (600 秒) を受け入れる 時計が進んだ端末で今の時刻で発行された証明書を、時計が遅れた検証側がすぐに受け入れる 猶予は始まりだけで `not_after` には無い (`now < not_after` のまま)、失効の検査は変わらない `IDENTITY_SEMANTICS_ID` は作る bytes の識別子なので動かない 試験 `tests/clock_skew.rs` (600 秒先は受け入れ、601 秒先は `NotYetValid`、`not_after` が now と now - 1 は `Expired`) 変異 2 件 (猶予を `not_after` にも足す、始まりの境界を 1 秒ずらす) は red
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
