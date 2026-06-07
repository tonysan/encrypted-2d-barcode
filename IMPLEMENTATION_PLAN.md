# Static String Encryption Barcode App - Engineering Plan

## 1. Product Idea

This app is a static browser-based usability layer for encrypting an arbitrary string and recovering it from a printable or scannable 2D barcode.

The app does not invent a new crypto system. It makes this workflow easier:

```text
Before:
string -> command-line encryption -> encrypted string -> 2D barcode
scan barcode -> copy encrypted string -> command-line decryption -> string

After:
open webapp -> enter string -> choose unlock mode -> get 2D barcode
open webapp -> scan/paste barcode -> unlock locally -> get string
```

The value of the app is usability:

- No backend.
- No accounts.
- No telemetry.
- No server-side recovery.
- No command-line handoff for normal use.
- No secrets sent over the network.
- Browser-native WebAuthn PRF support where available.
- Passphrase recovery that can work from a static/offline copy where browser APIs allow.

## 2. Scope

### In Scope

- Static HTML/CSS/JavaScript or TypeScript web app.
- Encrypt an arbitrary user-provided string locally.
- Decrypt an encrypted payload locally.
- Generate a 2D barcode for the output.
- Scan a 2D barcode using the camera.
- Paste payload manually as a fallback.
- Support three modes:
  - Plain, no encryption.
  - Passphrase encryption.
  - WebAuthn PRF encryption.
- Support URL-fragment import/export for hosted use.
- Provide clear warnings for plaintext and WebAuthn origin-bound recovery.
- Use a tiny strict-profile JWE implementation built on browser Web Crypto rather than a broad JOSE dependency.

### Out of Scope for v1

- Backend services.
- Accounts.
- Databases.
- Analytics or telemetry.
- Cloud functions.
- CDN runtime scripts.
- Multi-recipient or hybrid unlock.
- Multi-chunk barcode sets.
- Custom encryption envelope format.
- COSE/CBOR/Base45 optimization.
- Argon2id/WASM.
- Recovery templates for specific services.
- Full general-purpose JOSE/JWT/JWE library support.

These can be revisited after the core usability loop works.

## 3. Core Flows

### Encrypt Flow

```text
User string
  -> selected mode
  -> local browser encryption or plaintext packaging
  -> portable payload string
  -> 2D barcode
```

Mode behavior:

- Plain mode: barcode contains the cleartext string or a plain app-marked payload.
- Passphrase mode: barcode contains a standard encrypted JWE Compact payload.
- WebAuthn PRF mode: barcode contains a standard encrypted JWE Compact payload using a key derived from WebAuthn PRF output.

### Decrypt Flow

```text
2D barcode scan or manual paste
  -> payload detection
  -> local browser unlock
  -> authenticated decryption
  -> protected display of string
```

Unlock behavior:

- Plain mode: display the decoded string after warning that it was not encrypted.
- Passphrase mode: ask for passphrase and decrypt locally.
- WebAuthn PRF mode: request WebAuthn PRF from the browser and decrypt locally.

## 4. Data Format Strategy

Use existing standards for encrypted payloads.

Implementation rule: implement only the tiny JWE subset this app needs, using browser Web Crypto primitives. Do not import a broad JOSE package for v1. A broad dependency supports many algorithms and header behaviors this app will reject anyway, increasing supply-chain and review surface.

### Passphrase Payloads

Use JSON Web Encryption Compact Serialization.

Recommended v1 profile:

```text
JWE Compact Serialization
alg = PBES2-HS512+A256KW
enc = A256GCM
```

The app output can be:

```text
ERK1.<compact-jwe>
```

`ERK1` is only an app marker. It is not a custom crypto envelope.

The app must reject unsupported or unsafe JWE headers, including:

- Unknown `alg`.
- Unknown `enc`.
- Remote key references such as `jku` or `x5u`.
- Compression unless explicitly reviewed later.
- Any unencrypted security-critical metadata.

The implementation should be strict enough that unsupported JWE features are not partially parsed or ignored. Unknown critical behavior should fail closed.

### WebAuthn PRF Payloads

Use JWE Compact Serialization for the encrypted object.

Recommended v1 profile:

```text
JWE Compact Serialization
alg = dir
enc = A256GCM
```

The direct encryption key is derived locally from WebAuthn PRF output using a documented app profile.

This profile must define:

- Required secure origin behavior.
- RP ID/origin expectations.
- How the PRF output is converted into a JWE content encryption key.
- What non-secret credential metadata is stored for recovery.
- How origin mismatch and unavailable credential errors are reported.

This is the only intentionally app-specific crypto-adjacent part, because WebAuthn PRF does not provide a standard JOSE recipient algorithm.

The WebAuthn PRF profile should reuse the same strict compact-JWE encoder/decoder and only change how the encryption key is obtained.

### Plain Payloads

Plain mode may use either:

```text
ERP1.<encoded-plain-string>
```

or direct cleartext in the barcode.

Using an app marker is preferred so the scanner can detect that the barcode came from this app and show a clear warning before display.

Plain mode must be visually and textually impossible to confuse with encryption.

### URL Fragment Mode

For hosted use:

```text
https://example.com/#ERK1.<compact-jwe>
```

Rules:

- Payloads go in the URL fragment only.
- Never put payloads in query parameters.
- On load, detect supported fragments.
- Offer to clear the fragment after import.
- Keep payload-only mode for offline and self-hosted use.

## 5. Security Model

The app protects against:

- Someone finding a printed encrypted barcode without the unlock factor.
- Server/operator exposure, because the server only serves static files.
- Query-string logging, because URL payloads use fragments.
- Passive network observers after static assets are loaded.
- Accidental CLI copy/paste mistakes in the old workflow.

The app does not protect against:

- Compromised browser.
- Compromised operating system.
- Malicious extensions.
- Screen capture.
- Keyloggers.
- Weak passphrases.
- Lost WebAuthn credential.
- Lost WebAuthn origin/RP ID.
- Browser/platform removal or breakage of WebAuthn PRF support.
- Destroyed or unreadable printed barcode without another backup.

## 6. Security Invariants

These rules should be treated as non-negotiable:

- All encryption and decryption happens locally in the browser.
- No secret string is sent to any server.
- No passphrase is sent to any server.
- No WebAuthn PRF output is sent to any server.
- No camera image is sent to any server.
- No decrypted plaintext is sent to any server.
- No secret is written to localStorage or sessionStorage.
- Wrong passphrase/key fails authenticated decryption.
- Corrupted encrypted payload fails authenticated decryption.
- Query-string payloads are rejected or ignored.
- Runtime release uses no CDN scripts.
- Plain mode is clearly labeled as unsafe for secrets.
- JWE parsing is strict and allowlist-based.
- Unsupported algorithms and headers fail closed.
- No broad JOSE dependency is used in the v1 runtime.

## 7. Supply Chain Strategy

The app handles high-value user secrets, so supply-chain risk is part of the security model.

Rules for v1:

- Prefer browser Web Crypto over third-party crypto implementations.
- Implement only the strict JWE Compact profile needed by the app.
- Do not include a general-purpose JOSE/JWT/JWE dependency unless a later security review shows it is safer than the narrow implementation.
- Keep barcode generation and scanning dependencies small, local, pinned, and documented.
- No CDN runtime scripts.
- No remote fonts.
- No service worker in v1.
- No runtime package registry access.
- No automated dependency update merges for security-sensitive packages.
- Maintain a dependency inventory with source, version, license, checksum, and purpose.
- Publish release checksums.
- Display app version/build hash in the UI.

Supply-chain tests should verify:

- No network calls occur during create/recover after static assets load.
- No unexpected dependency files are included in the release ZIP.
- Runtime code does not write secrets to localStorage or sessionStorage.
- CSP can be configured with `connect-src 'none'` for normal operation.

## 8. Protected Display

The default decrypted display should reduce casual DOM exposure:

- Render decrypted string to an HTML canvas by default.
- Hide after a timeout.
- Hide on tab blur.
- Hide on visibility change.
- Disable copy by default.
- Offer explicit copy with a warning.

Documentation must be direct: canvas display is not secure against a compromised browser, OS, extension, screenshot tool, screen recorder, or keylogger. JavaScript memory cleanup is best-effort only.

## 9. Proposed File Structure

Keep the app small and auditable.

```text
/
  index.html
  style.css
  app.js
  README.md
  SECURITY.md
  THREAT_MODEL.md
  SELF_HOSTING.md
  IMPLEMENTATION_PLAN.md
  LICENSE
  checksums.txt
  /src
    main.ts
    ui-create.ts
    ui-recover.ts
    protected-display.ts
    payload-detect.ts
    plain-payload.ts
    jwe-compact.ts
    jwe-passphrase-profile.ts
    jwe-webauthn-prf-profile.ts
    webcrypto.ts
    webauthn-prf.ts
    barcode-generate.ts
    barcode-scan.ts
    url-fragment.ts
    errors.ts
  /tests
    plain-payload.test.ts
    jwe-compact.test.ts
    jwe-passphrase-profile.test.ts
    jwe-corruption.test.ts
    jwe-test-vectors.test.ts
    payload-detect.test.ts
    url-fragment.test.ts
    webauthn-prf-profile.test.ts
  /vendor
    README.md
```

If plain JavaScript is chosen instead of TypeScript, preserve the same module boundaries.

## 10. Phased Implementation Plan

### Phase 0: Scope and Docs

Goal: document the simple product and security boundaries before coding.

Tasks:

- Write README with the before/after workflow.
- Write SECURITY.md.
- Write THREAT_MODEL.md.
- Write SELF_HOSTING.md placeholder.
- Document static/no-backend/no-telemetry requirements.
- Document the chosen JWE profiles.
- Document that `ERK1` and `ERP1` are app markers, not new encryption formats.
- Document the strict-profile JWE implementation approach.
- Document supply-chain rules.

Exit criteria:

- A contributor understands the app is a static usability wrapper around standard encrypted payloads.

### Phase 1: Plain and Passphrase MVP

Goal: make the core browser flow work without barcode scanning yet.

Tasks:

- Build one static page with Create and Recover views.
- Add plain mode with strong unsafe-for-secrets labeling.
- Add passphrase mode using JWE Compact.
- Implement the narrow JWE Compact profile with Web Crypto.
- Enforce passphrase creation rules.
- Allow decryption attempts for older payloads even if the passphrase would fail current creation rules.
- Add payload output text area.
- Add manual paste recovery.
- Add protected canvas display.
- Reject unsupported JWE profiles.
- Add JWE test vectors.
- Reject query-string payloads.

Exit criteria:

- User can open the app locally.
- User can enter a string and passphrase.
- App returns `ERK1.<compact-jwe>`.
- User can reload, paste payload, enter passphrase, and recover the string.
- Wrong passphrase fails cleanly.
- Corrupted payload fails cleanly.
- Plain mode works and is visibly unsafe.
- No backend or network call is needed for passphrase mode.
- No broad JOSE dependency is used.

### Phase 2: Barcode Generation

Goal: replace manual payload copy with a printable/scannable code.

Tasks:

- Add local vendored 2D barcode generation dependency.
- Generate a barcode for plain and encrypted payloads.
- Add download/print support.
- Show human-readable payload text as fallback.
- Add basic print CSS.
- Display app version and creation date near printed output.

Exit criteria:

- User can create a passphrase-encrypted string and print or save a barcode.
- User can still recover manually from the text payload.

### Phase 3: Barcode Scanning

Goal: complete the usability loop.

Tasks:

- Add local vendored barcode scanning dependency.
- Add camera scanning flow.
- Add image upload scanning flow if feasible.
- Preserve manual paste fallback.
- Detect supported app markers.
- Show clear error for unknown barcode content.
- Recover passphrase JWE from a scanned barcode.

Exit criteria:

- User can create a barcode, reload the app, scan it, enter passphrase, and recover the string.

### Phase 4: URL Fragment Mode

Goal: support hosted recovery links without leaking payloads through query strings.

Tasks:

- Add URL export: `https://host/#ERK1.<compact-jwe>`.
- Parse supported `location.hash` payloads on page load.
- Offer to clear the hash after import.
- Reject or ignore query-string payloads.

Exit criteria:

- Hosted app can import encrypted payloads from URL fragments.
- Payload-only mode still works for offline/local workflows.

### Phase 5: WebAuthn PRF Prototype

Goal: test whether the browser/origin/authenticator can provide PRF output.

Tasks:

- Add HTTPS/secure-context detection.
- Show current origin and RP ID.
- Add WebAuthn availability check.
- Add PRF extension support check.
- Add platform authenticator test.
- Add security key test where possible.
- Explain origin-bound recovery before enabling creation.

Exit criteria:

- User can tell whether the current environment supports WebAuthn PRF before creating a WebAuthn-dependent barcode.

### Phase 6: WebAuthn PRF Encryption

Goal: support browser-native passwordless encryption as an advanced mode.

Tasks:

- Add WebAuthn PRF create flow.
- Derive a JWE direct encryption key from PRF output using the documented app profile.
- Create `ERK1.<compact-jwe>` payloads with `alg=dir` and `enc=A256GCM`.
- Store only non-secret metadata needed to request the same credential later.
- Add WebAuthn PRF recover flow.
- Detect origin/RP mismatch.
- Fail clearly if credential or PRF support is unavailable.
- Require explicit warnings/acknowledgements.
- Reuse the strict compact-JWE implementation.

Exit criteria:

- On a compatible HTTPS origin, user can create a WebAuthn PRF encrypted barcode and recover it using the same credential.

### Phase 7: Release Hardening

Goal: make the static release trustworthy and self-hostable.

Tasks:

- Remove all CDN/runtime remote dependencies.
- Vendor or bundle barcode/JWE dependencies locally.
- Confirm there is no broad JOSE runtime dependency unless explicitly approved by security review.
- Add dependency inventory.
- Add license inventory.
- Add checksums.
- Create downloadable static ZIP release.
- Document recommended security headers.
- Verify no network calls after static asset load.
- Verify no secret storage in localStorage/sessionStorage.

Exit criteria:

- User can download, verify, and self-host the app as static files.

### Phase 8: Polish and Compatibility

Goal: improve reliability without expanding the crypto model.

Tasks:

- Improve mobile scanning UX.
- Improve print layout.
- Add accessibility pass.
- Add browser compatibility matrix.
- Add recovery drill guide.
- Add better error messages.
- Add test vectors for JWE passphrase payloads.
- Add app version/hash display in UI.

Exit criteria:

- The app is practical for repeated real-world create/scan/recover workflows.

## 11. Test Plan

### Unit Tests

- Plain payload encode/decode.
- Payload marker detection.
- Passphrase JWE encrypt/decrypt roundtrip.
- JWE compact serialization shape.
- JWE protected-header allowlist.
- JWE test vectors.
- Wrong passphrase failure.
- Corrupted JWE failure.
- Unsupported JWE header rejection.
- Unknown JWE algorithm rejection.
- Unknown JWE encryption method rejection.
- Remote JWE key header rejection.
- URL fragment parsing.
- Query-string payload rejection.
- Protected display state transitions.

### Browser Tests

- Open app locally.
- Create plain payload.
- Create passphrase encrypted payload.
- Reload and recover from manual paste.
- Wrong passphrase shows clean error.
- Corrupted payload shows clean error.
- Decrypted value displays in protected canvas mode.
- Copy requires explicit action.
- URL fragment import works.
- Hash clearing requires confirmation.

### Barcode Tests

- Generate barcode from plain payload.
- Generate barcode from passphrase payload.
- Scan generated barcode from screen.
- Scan printed barcode where practical.
- Recover from scanned payload.
- Recover through manual text fallback.
- Unknown barcode content shows clear error.

### WebAuthn PRF Tests

Automated coverage may be limited, so include a manual matrix:

- Unsupported browser.
- Insecure origin.
- HTTPS origin with no PRF support.
- Platform authenticator support.
- Security key support.
- Origin mismatch recovery failure.
- Missing credential recovery failure.
- Successful create/recover on compatible setup.

## 12. Compatibility Risks

### WebAuthn PRF

WebAuthn PRF is the riskiest feature.

Risks:

- Browser support varies.
- Authenticator support varies.
- HTTPS is required.
- Recovery is origin/RP ID bound.
- The same physical key does not guarantee the same output across registrations.
- Losing the credential can make recovery impossible.
- Losing the domain/origin can make recovery impossible.

Mitigations:

- Keep passphrase mode as the default encrypted mode.
- Mark WebAuthn PRF as advanced.
- Show origin/RP ID before creation.
- Require explicit acknowledgements.
- Recommend testing recovery before relying on a barcode.
- Document self-hosting on a stable HTTPS domain.

### Barcode Reliability

Risks:

- Dense payloads may scan poorly.
- Poor printers and bad lighting can break recovery.
- Large strings may exceed practical single-code capacity.

Mitigations:

- Keep v1 strings reasonably sized.
- Show payload text fallback.
- Add print guidance.
- Defer multi-chunk support until real demand appears.

### Static Hosting

Risks:

- Hosted deployments may have weak security headers.
- Users may trust public demo origins for long-lived WebAuthn PRF recovery.

Mitigations:

- Provide SELF_HOSTING.md.
- Recommend strict CSP and no-referrer policy.
- Discourage long-lived WebAuthn PRF payloads on demo domains.

### Supply Chain

Risks:

- Malicious or compromised dependency can steal strings, passphrases, PRF output, or decrypted plaintext.
- Large crypto libraries increase review surface.
- Barcode scanner dependencies may touch camera frames and browser APIs.
- Build tooling compromise can produce a malicious release artifact.
- Hosted deployment compromise can serve JavaScript different from the reviewed release.

Mitigations:

- Use browser Web Crypto for cryptographic primitives.
- Keep a tiny strict-profile JWE layer in app code.
- Pin and inventory dependencies.
- Avoid CDN runtime scripts.
- Avoid service workers in v1.
- Publish checksums for releases.
- Show app version/build hash.
- Verify no runtime network calls during create/recover.

## 13. Deferred Features

Do not build these until the simple app works:

- Multi-chunk barcode payloads.
- Hybrid passphrase plus WebAuthn unlock.
- Multiple WebAuthn credentials per payload.
- JWE General JSON Serialization.
- COSE/CBOR.
- Base45.
- Multipart UR.
- Argon2id/WASM.
- Service-specific recovery templates.
- Broad JOSE dependency support.

Each deferred feature should have a concrete usability or reliability reason before it enters scope.

## 14. MVP Success Criteria

The MVP is complete when:

- User opens the static app.
- User enters an arbitrary string.
- User chooses plain or passphrase mode.
- User gets a barcode.
- User reloads the app.
- User scans or pastes the barcode payload.
- User enters the passphrase if encrypted.
- User gets the original string back.
- Wrong passphrase fails cleanly.
- Corrupted encrypted payload fails cleanly.
- No backend is involved.
- No secrets are stored in localStorage/sessionStorage.
- No secrets are sent over the network.
- Encrypted payloads use the strict JWE Compact profile implemented with browser Web Crypto.
- JWE behavior is covered by test vectors.
