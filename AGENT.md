# AGENT.md

This file is the AI-agent handoff for this repository. Keep `README.md` user-facing. Put implementation backlog, accepted risks, and agent-specific instructions here.

## Product Direction

Encrypted 2D Barcode is a static browser app for local QR-compatible creation and recovery of compact strings.

Core modes:

- Plain mode: honest QR generation with no redirect, tracking, or encryption.
- Passphrase mode: general-purpose local encrypted recovery.
- Passkey mode: differentiator; WebAuthn PRF/passkey-bound encrypted QR recovery.

This project is not trying to become the canonical hosted QR service. A hosted or demo instance, if any, is only a convenience and test surface. Serious users should self-host a reviewed release on infrastructure they control, especially for passkey mode because WebAuthn recovery is RP-ID/origin bound.

## Non-Negotiable Security Boundaries

- No backend, database, accounts, telemetry, analytics, CDN runtime scripts, service worker, or server-side recovery.
- Encryption and decryption happen locally in the browser.
- Payloads, plaintext, passphrases, WebAuthn PRF output, and derived keys must not be sent to a server.
- Secrets must not be stored in localStorage or sessionStorage.
- Passkey mode may store only non-secret credential metadata needed to request the same credential later.
- Plain mode must remain clearly labeled as not encrypted.
- Keep the JWE implementation strict and narrow. Do not turn this into a broad JOSE library.
- Reject unsupported algorithms, unsupported headers, remote key references, compression, and unreviewed JWE behavior.

## Accepted Risks And Product Decisions

- Phase 2 preserved the current passkey credential-selection behavior. Do not treat it as an accidental bug in later cleanup.
- A future phase may revisit credential-selection UX.
- Passphrase mode should warn about weak passphrases and offline guessing, but this iteration should continue allowing any non-empty passphrase.
- Camera scanning, image import, QR auto-splitting, multi-recipient fallback, and passphrase generation are deferred.
- A hosted/demo instance is not the trust anchor for serious use.

## Current Crypto Profile And Backlog

Current passphrase mode:

```text
alg = PBES2-HS512+A256KW
enc = A256GCM
```

Current passkey mode is browser-native, JWE-registered, and symmetric-only:

```text
alg = A256KW
enc = A256GCM
KEK = HKDF-SHA-512(WebAuthn PRF output, profile metadata)
```

The WebAuthn PRF protected header keeps only non-secret recovery metadata:

```text
app = erk-webauthn-prf-v1
cid = base64url credential ID
rp  = WebAuthn RP ID
ps  = base64url random 32-byte PRF salt
```

HKDF profile for passkey KEK derivation:

```text
IKM  = WebAuthn prf.results.first
salt = UTF8("encrypted-2d-barcode WebAuthn PRF HKDF salt v1") || 0x00 || ps
info = UTF8("ERK1 WebAuthn PRF A256KW KEK v1") || 0x00 || UTF8(rp) || 0x00 || cid
L    = 32 bytes
```

Legacy pre-release `alg=dir` passkey payloads are intentionally rejected. Keep the `erk-webauthn-prf-v1` app marker unless the user explicitly changes that decision.

## Phase Backlog

### Completed Phase 2: Passkey Security And JWE Profile Hardening

- Keep current passkey selection flow unchanged.
- Set WebAuthn creation, bound request, and discoverable request options to `userVerification: "required"`.
- Move passkey JWE from `alg=dir` direct encryption to `alg=A256KW` key wrapping.
- Generate a random 256-bit CEK per passkey payload.
- Derive a 256-bit AES-KW KEK with HKDF-SHA-512 from WebAuthn PRF output and profile metadata.
- Wrap the CEK in the JWE encrypted-key segment using `A256KW`.
- Encrypt content with the CEK using `A256GCM`.
- Reject old `alg=dir` WebAuthn payloads.
- Update tests and README tech details after implementation.

### Skipped Phase 3: Passphrase UX

- Add non-blocking strength feedback.
- Add visible offline-guessing warning.
- Continue allowing any non-empty passphrase.

The user explicitly skipped this phase for now.

### Completed Phase 4: Defensive Limits And Crypto API Cleanup

- Added reviewed size caps for encrypted plaintext, plain QR content, final QR content, recovery input, compact JWE, JWE segments, protected header, and inbound `p2c`.
- Current cap values: encrypted plaintext 512 UTF-8 bytes, plain QR content 1800 UTF-8 bytes, final QR content 1800 UTF-8 bytes, recovery input 4096 UTF-8 bytes, compact JWE 3072 chars, JWE segment 2048 chars, decoded protected header 768 bytes, inbound `p2c` 1000000.
- Oversized-content errors explain that multi-code splitting is future work.
- The create form warns at 80% of the active mode's input limit and blocks generation before encryption when content is over the limit.
- Public/browser JWE APIs do not accept caller-supplied IVs.
- WebAuthn KEK CryptoKey inputs are validated for AES-KW, 256-bit length, `secret` type, and required usages.

### Phase 5: Recovery Check Mode

- Add a `Check` recovery action that validates decryptability without rendering or copying plaintext.
- Report mode, checksum, and content length after a successful check.
- This lets users verify printed codes, passphrases, passkeys, RP IDs, and hosted domains without revealing the secret on screen.
- Keep camera scanning and image import out of scope.
- Keep `camera=()` in `static/_headers`.

## Commands

Use Windows-friendly commands in this repository.

```text
npm.cmd test
npm.cmd run build
npm.cmd run dev
```

`npm.cmd test` runs the Node test suite. `npm.cmd run build` runs tests and prepares `static/vendor/qrcode-generator.js`. `npm.cmd run dev` prepares static files and serves `static/` at `http://127.0.0.1:8788/`.

## Documentation Rules

- Keep README user-facing.
- Keep implementation backlog and AI instructions in this file.
- Keep `SECURITY.md` as a short GitHub-compatible security stub.
- Do not reintroduce standalone `SELF_HOSTING.md`, `THREAT_MODEL.md`, or `IMPLEMENTATION_PLAN.md` unless the user explicitly requests separate docs again.
- If docs mention passkey mode, be precise: it is credential-specific, RP-ID/origin-bound, and depends on compatible browser/authenticator PRF support.

## Test Expectations

Before finishing implementation work, run:

```text
npm.cmd test
```

For frontend-affecting changes, also manually check the browser flow where feasible:

- Plain create/recover.
- Passphrase create/recover.
- Wrong passphrase failure.
- Corrupted payload failure.
- Passkey availability messaging on the relevant origin.
- No unexpected network calls in normal create/recover flows.
