# Encrypted 2D Barcode

## TLDR

Encrypted 2D Barcode is a static browser app for turning compact strings into printable or scannable QR-compatible codes.

It has three modes:

- Plain: creates an ordinary QR code with no redirect, tracking, or encryption.
- Passphrase: encrypts locally in the browser and requires the passphrase to recover.
- Passkey: uses browser WebAuthn PRF support so recovery is bound to a compatible passkey credential on the original RP ID.

The app has no backend, accounts, telemetry, analytics, server-side recovery, runtime CDN scripts, remote fonts, service worker, or database. Encryption and recovery happen locally in the browser. Payloads, passphrases, WebAuthn PRF output, derived keys, and decrypted plaintext should not be sent to a server.

This project is not trying to become the canonical hosted QR service. A hosted or demo instance, if any, is only a convenience and test surface. Serious users should self-host a reviewed release on infrastructure they control, especially for passkey mode because WebAuthn recovery is RP-ID/origin bound.

Current status: this repository is pre-release and has not had an external security review. Do not rely on it for important secrets until a reviewed release exists.

## Quick How To Use

Open the static app from `static/index.html`, a local dev server, or a self-hosted HTTPS deployment.

To create a plain code:

1. Select `Plain text`.
2. Enter the exact text or URL.
3. Generate, download, or print the code.

Plain mode is not encrypted. Anyone who scans the code can read it.

To create a passphrase-protected code:

1. Select `Passphrase`.
2. Enter the content.
3. Enter and confirm a passphrase.
4. Generate, download, or print the code.
5. Store or send the passphrase separately from the code.

Anyone with the encrypted QR can attempt offline guesses. Use a high-entropy passphrase.

To create a passkey-protected code:

1. Open the app from the final stable HTTPS domain you expect to use for recovery.
2. Select `Passkey`.
3. Confirm the passkey warning.
4. Let the browser use or create the site passkey.
5. Generate, download, or print the code.
6. Test recovery before relying on the printed code.

Passkey mode requires compatible browser WebAuthn PRF support, a compatible authenticator, the same RP ID/origin later, and the same recoverable credential later. The browser may require biometric or PIN verification. Losing the credential, domain, browser support, or authenticator support can make recovery impossible.

To recover:

1. Open a scanned recovery URL or paste the code/link into the decrypt panel.
2. Enter the passphrase, or complete the passkey prompt.
3. The app decrypts locally and shows the result in protected display mode.

Protected display uses a canvas and auto-hide behavior to reduce casual DOM exposure. It does not protect against a compromised browser, operating system, extension, screenshot tool, screen recorder, clipboard monitor, or keylogger.

For local development:

```text
npm run dev
```

The dev server serves `static/` at `http://127.0.0.1:8788/` by default.

## How To Self Host

Host only the deployable static app files from `static/`:

```text
static/index.html
static/init.js
static/app.js
static/passkey.js
static/ui.js
static/style.css
static/_headers
static/vendor/qrcode-generator.js
static/LICENSE
```

Do not serve repository-root docs, tests, planning files, or development-only files as part of the app.

For Cloudflare Pages Git integration:

```text
Framework preset: None / Static HTML
Production branch: main
Build command: npm run build
Build output directory: static
Root directory: blank or /
```

The build command runs local tests, verifies required static deployment files, and copies the pinned QR runtime into `static/vendor/` for same-origin deployment.

Encrypted QR codes are domain-aware. When the app runs on an HTTP(S) page, encrypted QR codes contain the current page URL with the recovery payload in the fragment:

```text
https://your-domain.example/#ERK1.<compact-jwe>
```

The fragment is not sent to the server during normal HTTP requests. Plain mode QR codes contain only the plain payload. When opened from a local file or non-web origin, encrypted QR codes contain only the payload:

```text
ERK1.<compact-jwe>
```

For long-lived passkey payloads:

- Use a stable HTTPS domain you control.
- Do not rely on a temporary demo domain.
- Do not rely on a domain you may lose.
- Create and recover a test payload before creating real payloads.
- Test recovery before relying on a printed barcode.
- Create production passkey codes from the final custom domain, not a temporary preview URL.

If the original origin, RP ID, credential, browser support, or authenticator support is unavailable later, passkey recovery may fail.

Hosted deployments should use restrictive headers where practical. The current Cloudflare Pages headers live in `static/_headers`.

Starting point:

```text
Cache-Control: no-store
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; font-src 'self'; worker-src 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()
```

A release should make it possible to verify which files are included, which dependency versions are included, which checksums match the release, and that no runtime network calls are needed after static assets load.

Recommended serious-use workflow:

1. Download the reviewed release ZIP.
2. Verify the release checksum.
3. Host the static files on a domain you control.
4. Serve over HTTPS.
5. Use restrictive security headers.
6. Create a test code.
7. Reload the app.
8. Scan or paste the test code.
9. Confirm recovery works before relying on real secrets.

## Full Tech Details

### Runtime And Data Handling

The deployable app is static HTML, CSS, and JavaScript. Runtime code should make no network calls during create or recover flows after static assets are loaded.

Security boundaries:

- Secrets are entered locally.
- Passphrases are used locally.
- WebAuthn PRF output is used locally.
- Encryption and decryption happen locally.
- Payload parsing and recovery happen locally.
- Payloads are not sent to a server.
- Decrypted strings are not sent to a server.
- Secrets are not stored in localStorage or sessionStorage.

Only non-secret passkey credential metadata may be stored locally so the app can request the same credential later.

### Payload Markers

Encrypted payloads use:

```text
ERK1.<compact-jwe>
```

`ERK1` is only an app marker. It is not a MAC, signature, checksum, or custom encryption layer.

Plain mode currently emits the exact plain string. Legacy `ERP1.<encoded-plain-string>` payloads may remain recoverable for compatibility, but new plain QR codes should not use that wrapper.

### Passphrase Profile

Passphrase mode uses JSON Web Encryption Compact Serialization with:

```text
alg = PBES2-HS512+A256KW
enc = A256GCM
```

The passphrase-derived key wraps a random content-encryption key. The content is encrypted with `A256GCM`. Wrong passphrases and corrupted payloads must fail authenticated decryption without displaying garbage plaintext.

### Passkey Profile

Passkey mode is advanced and pre-release. The current profile is browser-native, JWE-registered, and symmetric-only:

```text
alg = A256KW
enc = A256GCM
```

The passkey recipient model is:

```text
KEK = HKDF-SHA-512(WebAuthn PRF output, profile metadata)
```

The payload contains a random 256-bit content-encryption key wrapped with `A256KW`. Content encryption uses `A256GCM`.

The protected header stores only non-secret recovery metadata:

```text
app = erk-webauthn-prf-v1
cid = base64url credential ID
rp  = WebAuthn RP ID
ps  = base64url random 32-byte PRF salt
```

The HKDF profile is:

```text
IKM  = WebAuthn prf.results.first
salt = UTF8("encrypted-2d-barcode WebAuthn PRF HKDF salt v1") || 0x00 || ps
info = UTF8("ERK1 WebAuthn PRF A256KW KEK v1") || 0x00 || UTF8(rp) || 0x00 || cid
L    = 32 bytes
```

Older pre-release `alg=dir` passkey payloads are intentionally rejected. Do not rely on pre-release passkey payloads for long-lived recovery.

### Strict JWE Profile

This app intentionally implements only the small JWE subset it needs with browser Web Crypto. It should not become a broad JOSE/JWT/JWE library.

The implementation must reject unsupported algorithms, unsupported encryption methods, unsupported protected headers, remote key references such as `jku` or `x5u`, compression, and unreviewed JWE behavior.

### Threat Model

The app is intended to protect against:

- Backend/operator exposure, because there is no backend secret handling.
- Server-side database compromise, because there is no database.
- Accidental query-string logging, because payload URLs use fragments.
- Passive network observers after static assets are loaded.
- Someone finding an encrypted printed code without the passphrase or WebAuthn credential.
- Command-line copy/paste mistakes from older manual workflows.

The app does not protect against:

- Compromised browsers.
- Compromised operating systems.
- Malicious browser extensions.
- Keyloggers.
- Screen capture or screen recording.
- Clipboard monitoring.
- Weak passphrases.
- User error when choosing plain mode for secrets.
- Lost passphrases.
- Lost WebAuthn credentials.
- Lost or changed WebAuthn origin/RP ID.
- Browser or authenticator incompatibility with WebAuthn PRF.
- Damaged, destroyed, or unreadable printed codes without backup copies.
- A compromised hosted deployment serving malicious JavaScript.

### Supply Chain

Supply-chain compromise is a major threat because the app's security depends on the JavaScript the user runs.

Rules:

- Prefer browser Web Crypto over third-party crypto implementations.
- Keep the strict JWE implementation narrow and reviewable.
- Avoid broad JOSE dependencies unless a later security review shows they are safer.
- Keep runtime dependencies small, pinned, locally bundled, and documented.
- Use no CDN runtime scripts.
- Use no remote fonts.
- Use no service worker in v1.
- Publish release checksums.
- Verify no runtime network calls during create or recover.

Approved runtime dependency:

- `qrcode-generator@1.4.4`
- Source: `node_modules/qrcode-generator/qrcode.js`
- Deploy target: `static/vendor/qrcode-generator.js`
- Upstream: `https://github.com/kazuhikoarase/qrcode-generator`
- License: MIT
- Lockfile integrity: `sha512-HM7yY8O2ilqhmULxGMpcHSF1EhJJ9yBj8gvDEuZ6M+KGJ0YY2hKpnXvRD+hZPLrDVck3ExIGhmPtSdcjC+guuw==`
- Purpose: QR Code matrix generation for recovery URLs.

### License

Apache License 2.0. See [LICENSE](LICENSE).
