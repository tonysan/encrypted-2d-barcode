# Encrypted 2D Barcode

A planned static web app for encrypting an arbitrary string locally and turning it into a printable or scannable 2D barcode.

The app is intended to replace a clumsy command-line recovery flow:

```text
Before:
string -> command-line encryption -> encrypted string -> 2D barcode
scan barcode -> copy encrypted string -> command-line decryption -> string

After:
open webapp -> enter string -> choose unlock mode -> get 2D barcode
open webapp -> scan/paste barcode -> unlock locally -> get string
```

## Project Status

This repository now has a no-build static scaffold with the Phase 1-4 core started:

- Plain payload creation and recovery.
- Passphrase encrypted payload creation and recovery.
- Strict-profile JWE Compact implementation on browser Web Crypto.
- Local QR-compatible 2D barcode generation.
- Native `BarcodeDetector` scan hooks where the browser supports them.
- Manual paste fallback.
- URL-fragment import/export.

WebAuthn PRF is intentionally still scaffolded for a later phase.

The deployable browser app lives in [static/](static/). Repository root contains docs, tests, and project metadata.

See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the phased build plan.

## Goals

- Static HTML, CSS, and JavaScript or TypeScript only.
- No backend, database, accounts, telemetry, analytics, CDN runtime scripts, or server-side recovery.
- Encrypt and decrypt locally in the browser.
- Generate a QR-compatible 2D barcode from the output payload.
- Recover by scanning where supported or by pasting the payload in the same static app.
- Support passphrase recovery from a local or offline copy where browser APIs allow.
- Support WebAuthn PRF later as an advanced browser-native mode on compatible HTTPS origins.

## Planned Modes

### Plain Mode

No encryption. The barcode contains the string or an app-marked plain payload.

This mode is unsafe for secrets and must be clearly labeled in the UI.

### Passphrase Mode

The default encrypted mode.

Planned payload format:

```text
ERK1.<compact-jwe>
```

The encrypted body is planned to use JSON Web Encryption Compact Serialization with a strict allowlisted profile:

```text
alg = PBES2-HS512+A256KW
enc = A256GCM
```

`ERK1` is only an app marker. It is not a custom encryption envelope.

### WebAuthn PRF Mode

Advanced encrypted mode for compatible browsers, authenticators, and HTTPS origins.

Planned payload format:

```text
ERK1.<compact-jwe>
```

The encrypted body is planned to use JWE Compact Serialization with:

```text
alg = dir
enc = A256GCM
```

The direct encryption key is derived locally from WebAuthn PRF output using an app-defined profile. This mode is origin/RP ID bound and may become unrecoverable if the original origin, browser support, or credential is unavailable.

## Data Format Direction

This project should not invent a new encryption format.

The v1 implementation uses a tiny strict-profile JWE Compact encoder/decoder with browser Web Crypto primitives rather than importing a broad JOSE/JWT/JWE dependency. The app rejects unsupported algorithms, unsupported headers, remote key references, compression, and behavior outside the reviewed profile.

## Security Boundaries

The app is designed so that:

- Secrets are entered locally.
- Passphrases are used locally.
- WebAuthn PRF output is used locally.
- Encryption and decryption happen locally.
- Barcode scanning happens locally.
- Payloads are not sent to a server.
- Decrypted strings are not sent to a server.
- Secrets are not stored in localStorage or sessionStorage.

The app does not protect against a compromised browser, compromised operating system, malicious extension, screen capture, keylogger, weak passphrase, lost WebAuthn credential, lost WebAuthn origin, or destroyed printed code.

See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## Static Hosting

The app should be deployed from [static/](static/) only. Passphrase mode should work from a local or offline copy where supported by the browser. WebAuthn modes require a compatible secure origin and should be self-hosted on a stable HTTPS domain before relying on them for long-lived recovery.

For Cloudflare Pages Git integration:

```text
Framework preset: None / Static HTML
Production branch: main
Build command: npm run build
Build output directory: static
```

The build script validates tests and required static deployment files. It does not bundle or fetch runtime dependencies.

See [SELF_HOSTING.md](SELF_HOSTING.md).

## Supply Chain Position

Because this app handles high-value secrets, dependencies are part of the security model.

Planned rules:

- Prefer browser Web Crypto over third-party crypto implementations.
- Implement only the strict JWE profile needed by the app.
- Avoid broad JOSE dependencies in v1.
- Pin and inventory dependencies.
- Vendor or bundle runtime dependencies locally.
- Use no CDN runtime scripts.
- Use no remote fonts.
- Avoid service workers in v1.
- Publish release checksums.
- Display app version/build hash.

## License

Apache License 2.0. See [LICENSE](LICENSE).
