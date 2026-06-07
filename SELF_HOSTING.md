# Self-Hosting

## Current Status

This repository has an early no-build static app scaffold. There is not yet a reviewed release ZIP.

You can open `static/index.html` directly for local testing. A formal release should still package and checksum the static files before real use.

## Hosting Model

The deployable app lives in `static/` and should be distributed as static files only:

```text
static/index.html
static/app.js
static/style.css
static/_headers
static/LICENSE
```

No server-side code, database, account system, telemetry, analytics, CDN runtime script, or cloud function should be required.

Repo-root docs, tests, and planning files are not part of the Cloudflare Pages deploy output.

## Cloudflare Pages Settings

For Git integration:

```text
Framework preset: None / Static HTML
Production branch: main
Build command: npm run build
Build output directory: static
Root directory: blank or /
```

The build command runs local tests and verifies the required files in `static/`. Cloudflare should serve only `static/`, not the repository root.

Generated QR codes are domain-aware. When the app runs on an HTTP(S) domain, the QR contains the current page URL with the recovery payload in the fragment. Create production QR codes from the final custom domain, not the temporary `pages.dev` preview, if you want scans to open the custom domain.

The app uses the URL fragment to choose its initial screen. A normal visit shows create/encrypt only. A visit with any fragment shows recover/decrypt only.

The app sets `Cache-Control: no-store` in `static/_headers` and versions the `app.js` and `style.css` URLs from `index.html` so behavior changes are not hidden by stale browser caches.

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

Camera scanning depends on browser support for camera access and native `BarcodeDetector`. It may not work from local files or in all browsers. Manual paste recovery must remain available.

WebAuthn is not implemented yet and will require a compatible secure origin when added.

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

Hosted deployments should use restrictive headers where practical. The current Cloudflare Pages headers live in `static/_headers`.

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
