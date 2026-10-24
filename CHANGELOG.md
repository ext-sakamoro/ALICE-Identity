# Changelog

## [Unreleased]

### 破壊的変更

- `DeviceCert` の layout を version 2 にする: body の device key の次に Noise の静的鍵 `noise_static` (X25519、32 byte) を置き、master の署名に含める `DEVICE_CERT_VERSION` は 2、`DEVICE_CERT_CONTEXT` は `alice-identity device-cert v2` `DeviceCert::issue` は `noise_static` を device key の次の引数に取る version 1 の証明書は `DeviceCert::from_bytes` が `DeviceCertError::UnsupportedVersion(1)` で拒む 証明書と artifact signature は 32 byte 長くなる

### Added

- `DeviceCert::noise_static`

### Changed

- README の licence の節を `LicenseRef-Proprietary` の一文と問い合わせ先にする
