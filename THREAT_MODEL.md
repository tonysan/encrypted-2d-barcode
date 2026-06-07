# Threat Model

## Summary

This app is planned as a static browser-based tool for turning an arbitrary string into a plain or encrypted 2D barcode, then recovering the string locally from a URL fragment or pasted payload.

The main security property is local-only handling: the server should only serve static files and should never receive secrets, passphrases, WebAuthn PRF output, encrypted payloads, or decrypted strings.

## Assets

Assets that need protection:

- User-entered string.
- Passphrase.
- WebAuthn PRF output.
- Derived encryption keys.
- Decrypted plaintext.
- Encrypted payload before the user intentionally prints, saves, or shares it.

## Trust Assumptions

The design assumes:

- The browser correctly implements Web Crypto.
- The browser correctly enforces WebAuthn origin/RP ID behavior.
- The user is running the expected static app files.
- The user's browser, operating system, and extensions are not compromised.
- The user chooses an appropriate passphrase when using passphrase mode.
- The user keeps any printed encrypted barcode and unlock factor available.

## Protects Against

The planned app should protect against:

- Exposure to a backend operator, because there is no backend secret handling.
- Server-side database compromise, because there is no database.
- Accidental query-string logging, because payload URLs use fragments.
- Passive network observers after static assets are loaded.
- Someone finding an encrypted printed barcode without the passphrase or WebAuthn credential.
- Command-line copy/paste mistakes from the older manual workflow.

## Does Not Protect Against

The app does not protect against:

- Compromised browser.
- Compromised operating system.
- Malicious browser extensions.
- Keyloggers.
- Screen capture or screen recording.
- Clipboard monitoring.
- Weak passphrases.
- User error when choosing plain mode for secrets.
- Lost passphrase.
- Lost WebAuthn credential.
- Lost or changed WebAuthn origin/RP ID.
- Browser or authenticator incompatibility with WebAuthn PRF.
- Damaged, destroyed, or unreadable printed barcodes without backup copies.
- A compromised hosted deployment serving malicious JavaScript.

## Plain Mode Risk

Plain mode is intentionally unencrypted. Anyone who scans or reads a plain barcode can recover the string.

Plain mode must be visually distinct from encrypted modes and must warn that it is unsafe for secrets.

## Passphrase Mode Risk

Passphrase mode depends on passphrase strength and the correctness of the strict JWE profile implementation.

The UI recommends 16 or more characters, but creation accepts any non-empty passphrase the user chooses.

Wrong passphrases and corrupted payloads must fail authenticated decryption without displaying garbage plaintext.

## WebAuthn PRF Risk

WebAuthn PRF mode is advanced and origin-bound.

Risks:

- Requires HTTPS or another browser-recognized secure context.
- Requires browser support.
- Requires authenticator support.
- Requires the same origin/RP ID later.
- Requires the same registered credential later.
- Same physical authenticator does not guarantee the same PRF output across registrations.
- If all credentials are lost, recovery may be impossible.
- If the original domain is lost or unavailable, recovery may be impossible.

Mitigations:

- Keep passphrase mode as the default encrypted mode.
- Show origin and RP ID before WebAuthn PRF creation.
- Require explicit acknowledgements.
- Encourage recovery testing before relying on a barcode.
- Recommend self-hosting on a stable HTTPS domain for long-lived WebAuthn PRF use.

## Supply Chain Risk

Supply-chain compromise is a major threat because the app's security depends on the JavaScript the user runs.

Risks:

- Malicious dependency exfiltrates secrets.
- Compromised dependency update changes crypto behavior.
- Broad crypto library adds unused algorithm and parser surface.
- QR generator dependency adds unexpected network or data-handling behavior.
- Build system creates an artifact that differs from reviewed source.
- Hosted deployment serves different files than a reviewed release.

Mitigations:

- Prefer browser Web Crypto.
- Implement only a tiny strict-profile JWE layer.
- Avoid broad JOSE dependencies in v1.
- Pin dependencies.
- Inventory dependencies.
- Avoid CDN runtime scripts.
- Avoid service workers in v1.
- Publish checksums.
- Verify no runtime network calls during create/recover.

## Protected Display Risk

Protected display mode should render decrypted strings to canvas by default and hide them after timeout, blur, or visibility change.

This reduces casual DOM exposure but does not provide strong protection against local compromise, screenshots, screen recording, extensions, or keyloggers. JavaScript cannot guarantee secure memory wiping.
