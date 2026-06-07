# Self-Hosting

## Current Status

This repository is in Phase 0. There is not yet a release ZIP or working static app to host.

This document describes the intended self-hosting model.

## Hosting Model

The app should be distributed as static files only:

```text
index.html
app.js
style.css
LICENSE
SECURITY.md
THREAT_MODEL.md
SELF_HOSTING.md
checksums.txt
vendored or bundled runtime dependencies
```

No server-side code, database, account system, telemetry, analytics, CDN runtime script, or cloud function should be required.

## Recommended Workflow for a Future Release

1. Download the release ZIP.
2. Verify the release checksum from `checksums.txt`.
3. Unzip the static files.
4. Host the files on a domain you control.
5. Serve the site over HTTPS.
6. Use restrictive security headers where possible.
7. Open the hosted app.
8. Create a test barcode.
9. Reload the app.
10. Scan or paste the test barcode.
11. Confirm recovery works before relying on real secrets.

## Local and Offline Use

Passphrase mode should be designed to work from a local or offline static copy where browser APIs allow.

Camera scanning and WebAuthn may not work from local files in all browsers. Manual paste recovery should remain available.

## WebAuthn PRF Hosting Warning

WebAuthn PRF recovery is tied to browser origin/RP ID behavior.

For long-lived WebAuthn PRF payloads:

- Use a stable HTTPS domain you control.
- Do not rely on a temporary demo domain.
- Do not rely on a domain you may lose.
- Run the WebAuthn PRF compatibility test before creating real payloads.
- Test recovery before relying on a printed barcode.

If the original origin, credential, browser support, or authenticator support is unavailable later, WebAuthn PRF recovery may fail.

## Suggested Security Headers

Hosted deployments should use restrictive headers where practical. Exact headers may need adjustment after implementation.

Starting point:

```text
Content-Security-Policy: default-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Permissions-Policy: camera=(self), microphone=(), geolocation=(), payment=()
```

If inline scripts or styles are used during early development, the CSP must be revisited before release.

## Release Verification Goals

A release should make it possible to verify:

- Which files are included.
- Which dependency versions are included.
- Which checksums match the release.
- Which build/version hash is shown by the app.
- That no runtime network calls are needed after static assets load.
