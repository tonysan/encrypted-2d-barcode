# Security Policy

## Current Status

This repository has an early no-build static app. It is not production-ready and has not had an external security review.

Do not rely on this repository for storing or recovering important secrets until a reviewed release exists.

## Security Goals

The planned app should:

- Run as static files.
- Perform encryption and decryption locally in the browser.
- Avoid backend secret handling entirely.
- Avoid accounts, telemetry, analytics, and server-side recovery.
- Avoid runtime CDN scripts and remote fonts.
- Avoid storing secrets in localStorage or sessionStorage.
- Fail authenticated decryption cleanly on wrong passphrases, wrong keys, or corrupted payloads.
- Use URL fragments, not query parameters, for hosted payload URLs.
- Prefer browser Web Crypto primitives.
- Use a tiny strict-profile JWE implementation instead of a broad JOSE dependency for v1.

## Non-Goals

The planned app cannot protect users from:

- Compromised browsers.
- Compromised operating systems.
- Malicious browser extensions.
- Keyloggers.
- Screenshots or screen recording.
- Weak passphrases.
- Lost WebAuthn credentials.
- Lost WebAuthn origin/RP ID.
- Broken or unavailable WebAuthn PRF support.
- Destroyed, unreadable, or unavailable printed barcodes without backup copies.

## Cryptography Profile

Passphrase mode uses JSON Web Encryption Compact Serialization with:

```text
alg = PBES2-HS512+A256KW
enc = A256GCM
```

WebAuthn PRF mode uses JWE Compact Serialization with:

```text
alg = dir
enc = A256GCM
```

The WebAuthn PRF protected header stores only non-secret recovery metadata:

```text
app = erk-webauthn-prf-v1
cid = base64url credential ID
rp  = WebAuthn RP ID
ps  = base64url random 32-byte PRF salt
```

The direct key is derived locally from `prf.results.first` with HKDF-SHA-256:

```text
IKM  = WebAuthn prf.results.first
salt = UTF8("encrypted-2d-barcode WebAuthn PRF HKDF salt v1") || 0x00 || ps
info = UTF8("ERK1 WebAuthn PRF A256GCM direct key v1") || 0x00 || UTF8(rp) || 0x00 || cid
L    = 32 bytes
```

The app may store the non-secret credential ID locally to reuse one site passkey for future codes. It must not store plaintext, PRF output, derived keys, passphrases, or credential secrets in browser storage.

Unsupported algorithms, unsupported headers, remote key references, compression, and unreviewed JWE behavior must fail closed.

## Dependency Policy

Runtime dependencies must be kept small, pinned, locally bundled or vendored, and documented.

The project should maintain an inventory for each runtime dependency:

- Name.
- Version.
- Source URL.
- License.
- Checksum.
- Purpose.
- Security notes.

No runtime dependency should make network calls during create or recover flows.

Approved v1 runtime dependencies:

- `qrcode-generator@1.4.4`: MIT-licensed QR Code matrix generation, pinned in `package-lock.json`, copied locally into `static/vendor/` during build.

## Reporting Security Issues

Please do not open public issues for suspected vulnerabilities involving secret exposure, cryptographic behavior, or supply-chain compromise.

Use GitHub's private vulnerability reporting for this repository if available. If private reporting is unavailable, contact the repository owner directly before publishing details.

Useful report details include:

- Affected commit or release.
- Browser and operating system.
- Reproduction steps.
- Expected behavior.
- Actual behavior.
- Whether the issue requires a compromised browser, extension, operating system, dependency, hosting setup, or normal app usage.

## Release Security Requirements

Before a release is considered suitable for real secret handling, it should have:

- Passing tests for encryption/decryption, wrong passphrase, corrupted payloads, and JWE profile rejection.
- JWE test vectors.
- Dependency inventory.
- License inventory.
- No runtime CDN scripts.
- No remote fonts.
- No service worker in v1.
- Release checksums.
- Static ZIP artifact.
- Recommended hosting security headers.
- Manual browser recovery tests.
- WebAuthn PRF compatibility notes if that mode is included.
