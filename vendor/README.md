# Vendored Runtime Dependencies

No vendored runtime dependencies are currently included.

The v1 runtime uses browser Web Crypto and a local strict-profile JWE Compact implementation in `app.js`.

Barcode generation is implemented locally for QR-compatible output. Barcode scanning uses the browser's native `BarcodeDetector` API when available and keeps manual paste as the required fallback.
