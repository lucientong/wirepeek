# Wirepeek Release Checklist

Use this before tagging a release.

## Pre-tag

- [ ] `CHANGELOG.md` has a dated section for the new version
- [ ] CMake `project(VERSION …)` matches the tag (currently 1.2.0)
- [ ] Default build (`WIREPEEK_ENABLE_TLS_DECRYPT=OFF`) configures and passes `ctest`
- [ ] OpenSSL build (`-DWIREPEEK_ENABLE_TLS_DECRYPT=ON`, OpenSSL ≥ 3) passes `ctest`, including `TlsCrypto*` / `TlsDecryptIntegration*`
- [ ] ASan/UBSan job green
- [ ] libFuzzer smoke includes `tls_record`
- [ ] README / README.zh-CN support matrix and `--tls-keylog` docs match reality
- [ ] No invented throughput claims

## TLS 1.2.0 specifics

- [ ] Supported: TLS 1.2/1.3 AES-GCM + ChaCha20-Poly1305 via SSLKEYLOGFILE
- [ ] Unsupported called out: CBC, 0-RTT, DTLS, QUIC, RSA private-key decrypt without keylog
- [ ] Privacy note: decryption only with operator-provided secrets; auth failure is fail-closed
- [ ] Live keylog append/truncate does not crash capture path

## Tag & publish

- [ ] Tag `vX.Y.Z` and push
- [ ] Confirm GitHub Actions release workflow artifacts
- [ ] Smoke the published binary: `--help`, `--read` fixture, optional `--tls-keylog` on OpenSSL build
