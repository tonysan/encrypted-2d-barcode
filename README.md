# Encrypted 2D Barcode

A static web app for encrypting an arbitrary string locally and turning it into a printable or scannable 2D barcode.

The app is intended to replace a clumsy command-line recovery flow:

```text
Before:
string -> command-line encryption -> encrypted string -> 2D barcode
scan barcode -> copy encrypted string -> command-line decryption -> string

After:
open webapp -> enter string -> choose unlock mode -> get 2D barcode
scan encrypted QR -> open webapp -> unlock locally -> get string
```

## Project Status

This repository now has a no-build static app with the Phase 1-6 core started:

- Plain payload creation and recovery.
- Passphrase encrypted payload creation and recovery.
- Strict-profile JWE Compact implementation on browser Web Crypto.
- Local QR-compatible 2D barcode generation.
- Manual paste recovery.
- URL-fragment import/export.
- Advanced passkey encrypted payload creation and recovery.

Passkey mode still needs manual validation on the hosted HTTPS deployment before it should be trusted for real recovery workflows.

The deployable browser app lives in [static/](static/). Repository root contains docs, tests, and project metadata.

See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the phased build plan.

## Goals

- Static HTML, CSS, and JavaScript or TypeScript only.
- No backend, database, accounts, telemetry, analytics, CDN runtime scripts, or server-side recovery.
- Encrypt and decrypt locally in the browser.
- Generate a QR-compatible 2D barcode from the output payload.
- Recover encrypted codes by opening the generated QR URL, or by pasting a payload in the same static app.
- Support passphrase recovery from a local or offline copy where browser APIs allow.
- Support passkey recovery as an advanced browser-native mode on compatible HTTPS origins.

## Planned Modes

### Plain Mode

No encryption. The barcode contains exactly the string.

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

### Passkey Mode

Advanced encrypted mode for compatible browsers, authenticators, and HTTPS origins.

Passkey-protected encryption first asks the browser to read an existing passkey for this site, including passkeys available from a phone, tablet, or security key. If no usable passkey is available, the app can create one reusable passkey for this site named `Encrypted 2D Barcode`. Each code still gets a fresh encryption key from a new random salt. If the browser or unlock device cannot provide the required key material, the app switches back to passphrase mode.

Payload format:

```text
ERK1.<compact-jwe>
```

The encrypted body uses JWE Compact Serialization with:

```text
alg = dir
enc = A256GCM
```

The protected header stores only non-secret recovery metadata:

```text
app = erk-webauthn-prf-v1
cid = base64url credential ID
rp  = WebAuthn RP ID
ps  = base64url random 32-byte PRF salt
```

The direct AES-GCM key is derived locally from `prf.results.first` using this HKDF-SHA-256 profile:

```text
IKM  = WebAuthn prf.results.first
salt = UTF8("encrypted-2d-barcode WebAuthn PRF HKDF salt v1") || 0x00 || ps
info = UTF8("ERK1 WebAuthn PRF A256GCM direct key v1") || 0x00 || UTF8(rp) || 0x00 || cid
L    = 32 bytes
```

This mode is origin/RP ID bound and may become unrecoverable if the original origin, browser support, or credential is unavailable. The app reuses one discoverable WebAuthn credential for the site and stores only its non-secret credential ID locally so later codes can use the same passkey. It stores no plaintext, PRF output, derived key, passphrase, or credential secret in browser storage.

## Data Format Direction

This project should not invent a new encryption format.

The v1 implementation uses a tiny strict-profile JWE Compact encoder/decoder with browser Web Crypto primitives rather than importing a broad JOSE/JWT/JWE dependency. The app rejects unsupported algorithms, unsupported headers, remote key references, compression, and behavior outside the reviewed profile.

## Security Boundaries

The app is designed so that:

- Secrets are entered locally.
- Passphrases are used locally.
- WebAuthn PRF output is used locally.
- Encryption and decryption happen locally.
- Payload parsing and recovery happen locally.
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

The build script validates tests and required static deployment files, then copies the pinned `qrcode-generator` browser file into `static/vendor/` for same-origin deployment.

For local development:

```text
npm run dev
```

The dev server serves the app at `http://127.0.0.1:8788/` by default.

When the app is opened from an HTTP(S) domain, encrypted QR codes contain the current page URL plus the payload in the fragment:

```text
https://your-domain.example/#ERK1.<compact-jwe>
```

Plain mode QR codes always contain only the plain payload:

```text
the exact string entered by the user
```

When opened from a local file or non-web origin, encrypted QR codes contain the payload only:

```text
ERK1.<compact-jwe>
```

For passkey mode, create codes from the final stable custom HTTPS domain. Passkey recovery is origin/RP ID bound.

The page is mode-aware:

- No URL fragment: show the create/encrypt screen only.
- URL fragment present: show the recover/decrypt screen only.

See [SELF_HOSTING.md](SELF_HOSTING.md).

## Supply Chain Position

Because this app handles high-value secrets, dependencies are part of the security model.

Planned rules:

- Prefer browser Web Crypto over third-party crypto implementations.
- Implement only the strict JWE profile needed by the app.
- Avoid broad JOSE dependencies in v1.
- Use `qrcode-generator@1.4.4` for QR standards logic instead of maintaining a custom QR encoder.
- Pin and inventory dependencies.
- Vendor or bundle runtime dependencies locally.
- Use no CDN runtime scripts.
- Use no remote fonts.
- Avoid service workers in v1.
- Publish release checksums.

# Vendored Runtime Dependencies

The deployed `static/vendor/` directory is generated by `npm run build` and is not committed.

The build currently copies:

- `qrcode-generator@1.4.4`
- Source: `node_modules/qrcode-generator/qrcode.js`
- Deploy target: `static/vendor/qrcode-generator.js`
- Upstream: `https://github.com/kazuhikoarase/qrcode-generator`
- License: MIT
- Lockfile integrity: `sha512-HM7yY8O2ilqhmULxGMpcHSF1EhJJ9yBj8gvDEuZ6M+KGJ0YY2hKpnXvRD+hZPLrDVck3ExIGhmPtSdcjC+guuw==`
- Purpose: QR Code matrix generation for recovery URLs.

The v1 runtime still uses browser Web Crypto and a local strict-profile JWE Compact implementation in `app.js`. Recovery is handled through URL fragments or manual paste; the app does not request camera access.

## License

Apache License 2.0. See [LICENSE](LICENSE).
