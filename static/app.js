(function initRuntime(root) {
  "use strict";

  /*
   * Audit map:
   * - QR standards logic is delegated to pinned qrcode-generator.
   * - Cryptographic primitives are delegated to Web Crypto.
   * - This file owns only the small app profile, format validation, and UI flow.
   * - The base64 helpers below are JOSE Compact Serialization glue. They adapt
   *   bytes to unpadded base64url because browsers expose standard base64 via
   *   btoa/atob, not a universal base64url API.
   */

  const ENCRYPTED_PREFIX = "ERK1.";
  const PLAIN_PREFIX = "ERP1.";
  const PASSWORD_ALG = "PBES2-HS512+A256KW";
  const DIRECT_ALG = "dir";
  const CONTENT_ALG = "A256GCM";
  const DEFAULT_P2C = 210000;
  const MAX_P2C = 5000000;
  const GCM_TAG_BYTES = 16;
  const QR_ERROR_CORRECTION = "M";
  const QR_MARGIN_MODULES = 4;
  const QR_MODULE_PIXELS = 10;
  const WEBAUTHN_PROFILE = "erk-webauthn-prf-v1";
  const WEBAUTHN_PRF_SALT_BYTES = 32;
  const AES_256_KEY_BYTES = 32;
  const AES_GCM_IV_BYTES = 12;
  const WEBAUTHN_TIMEOUT_MS = 120000;
  const WEBAUTHN_HKDF_SALT_LABEL = "encrypted-2d-barcode WebAuthn PRF HKDF salt v1";
  const WEBAUTHN_HKDF_INFO_LABEL = "ERK1 WebAuthn PRF A256GCM direct key v1";

  // Web Crypto is the security boundary. Node's webcrypto fallback lets tests
  // exercise the same API shape without adding a crypto dependency.
  function getCrypto() {
    if (root.crypto && root.crypto.subtle && root.crypto.getRandomValues) {
      return root.crypto;
    }
    if (typeof require === "function") {
      return require("node:crypto").webcrypto;
    }
    throw new Error("Web Crypto is not available.");
  }

  function utf8Encode(value) {
    return new TextEncoder().encode(value);
  }

  function utf8Decode(bytes) {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  }

  function toUint8Array(value) {
    if (value instanceof Uint8Array) {
      return new Uint8Array(value);
    }
    if (value instanceof ArrayBuffer) {
      return new Uint8Array(value);
    }
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    throw new Error("Expected binary data.");
  }

  // Standard base64 bridge, not a custom base64 codec. Browser btoa accepts a
  // binary string, so we chunk Uint8Array input to avoid argument limits.
  function bytesToBase64(bytes) {
    if (typeof Buffer !== "undefined") {
      return Buffer.from(bytes).toString("base64");
    }
    let binary = "";
    const chunk = 0x8000;
    for (let index = 0; index < bytes.length; index += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(index, index + chunk));
    }
    return btoa(binary);
  }

  // Reverse of bytesToBase64. Node Buffer is used in tests; browser atob is the
  // platform primitive in production.
  function base64ToBytes(value) {
    if (typeof Buffer !== "undefined") {
      return new Uint8Array(Buffer.from(value, "base64"));
    }
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  }

  // JWE Compact Serialization uses unpadded base64url for every binary segment.
  // This converts platform base64 to that alphabet and strips padding.
  function base64UrlEncode(bytes) {
    return bytesToBase64(bytes)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
  }

  // Strict base64url parser for untrusted QR/URL input. Padding is rejected
  // because JWE Compact segments are unpadded.
  function base64UrlDecode(value, options) {
    const allowEmpty = Boolean(options && options.allowEmpty);
    if (value === "" && allowEmpty) {
      return new Uint8Array();
    }
    if (typeof value !== "string" || value.length === 0) {
      throw new Error("Invalid base64url value.");
    }
    if (!/^[A-Za-z0-9_-]+$/.test(value) || value.includes("=")) {
      throw new Error("Invalid base64url value.");
    }
    const padLength = (4 - (value.length % 4)) % 4;
    return base64ToBytes(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padLength));
  }

  // All nonces, salts, and content-encryption keys come from Web Crypto RNG.
  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    getCrypto().getRandomValues(bytes);
    return bytes;
  }

  // Web Crypto and JOSE often pass data as separate byte arrays. This utility is
  // used only to build specified inputs such as PBES2 salt and ciphertext+tag.
  function concatBytes() {
    let total = 0;
    for (const bytes of arguments) {
      total += bytes.length;
    }
    const output = new Uint8Array(total);
    let offset = 0;
    for (const bytes of arguments) {
      output.set(bytes, offset);
      offset += bytes.length;
    }
    return output;
  }

  // Plain mode deliberately has no envelope: the QR payload is exactly the user
  // string. That keeps unencrypted codes small and easy to inspect.
  function encodePlainPayload(text) {
    return String(text);
  }

  // ERP1 is an early plain-mode envelope kept only so old generated payloads can
  // still be recovered. New plain payloads skip this wrapper.
  function decodePlainPayload(payload) {
    if (payload.startsWith(PLAIN_PREFIX)) {
      return utf8Decode(base64UrlDecode(payload.slice(PLAIN_PREFIX.length)));
    }
    return String(payload);
  }

  // Policy is intentionally minimal: reject empty passphrases, but do not try to
  // grade or block user-chosen passphrase length/complexity.
  function normalizePassphrase(passphrase) {
    const value = passphrase == null ? "" : String(passphrase);
    if (value.length === 0) {
      throw new Error("Passphrase cannot be empty.");
    }
    return value;
  }

  // JOSE PBES2 derives the AES-KW key from passphrase and salt. The salt input
  // is UTF8(alg) || 0x00 || p2s per JOSE, which separates this profile from
  // other algorithms that might reuse the same passphrase and salt.
  async function derivePbes2Key(passphrase, salt, iterations) {
    const crypto = getCrypto();
    const passwordKey = await crypto.subtle.importKey(
      "raw",
      utf8Encode(passphrase),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    const saltInput = concatBytes(utf8Encode(PASSWORD_ALG), new Uint8Array([0]), salt);
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        hash: "SHA-512",
        salt: saltInput,
        iterations
      },
      passwordKey,
      {
        name: "AES-KW",
        length: 256
      },
      false,
      ["wrapKey", "unwrapKey"]
    );
  }

  // The ERK1. prefix already identifies this app payload, so the protected JWE
  // header stays minimal and does not include typ.
  function makeProtectedHeader(p2s, p2c) {
    return {
      alg: PASSWORD_ALG,
      enc: CONTENT_ALG,
      p2c,
      p2s: base64UrlEncode(p2s)
    };
  }

  function normalizeRpId(rpId) {
    const value = String(rpId || "").trim().toLowerCase();
    if (
      value.length === 0 ||
      value.length > 253 ||
      value.includes("..") ||
      value.startsWith(".") ||
      value.endsWith(".") ||
      !/^[a-z0-9.-]+$/.test(value)
    ) {
      throw new Error("Invalid WebAuthn RP ID.");
    }
    return value;
  }

  function makeWebAuthnProtectedHeader(credentialId, rpId, prfSalt) {
    const credentialIdValue = typeof credentialId === "string"
      ? credentialId
      : base64UrlEncode(toUint8Array(credentialId));
    const prfSaltValue = typeof prfSalt === "string"
      ? prfSalt
      : base64UrlEncode(toUint8Array(prfSalt));
    return {
      alg: DIRECT_ALG,
      enc: CONTENT_ALG,
      app: WEBAUTHN_PROFILE,
      cid: credentialIdValue,
      rp: normalizeRpId(rpId),
      ps: prfSaltValue
    };
  }

  // Single serialization point for protected headers. JSON.stringify is the
  // normal JWE header serialization; the resulting bytes are authenticated.
  function stringifyHeader(header) {
    return JSON.stringify(header);
  }

  // Headers come from the QR/URL and are therefore untrusted. Decode and parse
  // them before the stricter profile validation below.
  function parseProtectedHeader(protectedSegment) {
    const raw = utf8Decode(base64UrlDecode(protectedSegment));
    let header;
    try {
      header = JSON.parse(raw);
    } catch (error) {
      throw new Error("Malformed JWE protected header.");
    }
    if (!header || typeof header !== "object" || Array.isArray(header)) {
      throw new Error("Malformed JWE protected header.");
    }
    return header;
  }

  // Strict profile gate. Rejecting unknown protected headers blocks features we
  // have not reviewed, including remote key references, compression, kid, and
  // typ. This keeps the implementation smaller than a general JOSE library.
  function validatePassphraseHeader(header) {
    const allowed = new Set(["alg", "enc", "p2c", "p2s"]);
    for (const key of Object.keys(header)) {
      if (!allowed.has(key)) {
        throw new Error("Unsupported JWE protected header.");
      }
    }
    if (header.alg !== PASSWORD_ALG) {
      throw new Error("Unsupported JWE algorithm.");
    }
    if (header.enc !== CONTENT_ALG) {
      throw new Error("Unsupported JWE encryption method.");
    }
    if (!Number.isInteger(header.p2c) || header.p2c < 1000 || header.p2c > MAX_P2C) {
      throw new Error("Unsupported JWE PBES2 iteration count.");
    }
    base64UrlDecode(header.p2s);
  }

  // WebAuthn PRF uses alg=dir because the CEK is derived locally from PRF
  // output. The protected header stores only non-secret recovery metadata.
  function validateDirectHeader(header) {
    const allowed = new Set(["alg", "enc", "app", "cid", "rp", "ps"]);
    for (const key of Object.keys(header)) {
      if (!allowed.has(key)) {
        throw new Error("Unsupported JWE protected header.");
      }
    }
    if (header.alg !== DIRECT_ALG) {
      throw new Error("Unsupported JWE algorithm.");
    }
    if (header.enc !== CONTENT_ALG) {
      throw new Error("Unsupported JWE encryption method.");
    }
    if (header.app !== WEBAUTHN_PROFILE) {
      throw new Error("Unsupported WebAuthn PRF profile.");
    }
    if (typeof header.cid !== "string" || typeof header.ps !== "string" || typeof header.rp !== "string") {
      throw new Error("Malformed WebAuthn PRF header.");
    }
    const credentialId = base64UrlDecode(header.cid);
    if (credentialId.length === 0) {
      throw new Error("Malformed WebAuthn credential ID.");
    }
    const prfSalt = base64UrlDecode(header.ps);
    if (prfSalt.length !== WEBAUTHN_PRF_SALT_BYTES) {
      throw new Error("Malformed WebAuthn PRF salt.");
    }
    return {
      credentialId,
      credentialIdBase64Url: header.cid,
      rpId: normalizeRpId(header.rp),
      prfSalt
    };
  }

  // Compact JWE is exactly five dot-separated segments:
  // protected header, encrypted key, IV, ciphertext, authentication tag.
  function splitCompactJwe(compactJwe) {
    const parts = compactJwe.split(".");
    if (parts.length !== 5) {
      throw new Error("Expected JWE Compact Serialization.");
    }
    return {
      protectedSegment: parts[0],
      encryptedKeySegment: parts[1],
      ivSegment: parts[2],
      ciphertextSegment: parts[3],
      tagSegment: parts[4]
    };
  }

  // Create the only passphrase-encrypted profile this app emits:
  // 1. random CEK encrypts the string with AES-GCM;
  // 2. passphrase-derived KEK wraps that CEK with AES-KW;
  // 3. the protected header segment is authenticated as AES-GCM AAD.
  async function encryptPassphraseJwe(plaintext, passphrase, options) {
    const normalizedPassphrase = normalizePassphrase(passphrase);
    const crypto = getCrypto();
    const p2c = options && options.p2c ? options.p2c : DEFAULT_P2C;
    if (!Number.isInteger(p2c) || p2c < 1000 || p2c > MAX_P2C) {
      throw new Error("Unsupported PBES2 iteration count.");
    }
    const p2s = randomBytes(16);
    const iv = randomBytes(12);
    const cekBytes = randomBytes(32);
    // CEK means content-encryption key. It is random per payload and is not
    // derived directly from the passphrase.
    const cekForEncrypt = await crypto.subtle.importKey(
      "raw",
      cekBytes,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt"]
    );
    const kek = await derivePbes2Key(normalizedPassphrase, p2s, p2c);
    const header = makeProtectedHeader(p2s, p2c);
    const protectedSegment = base64UrlEncode(utf8Encode(stringifyHeader(header)));
    const encryptedKey = new Uint8Array(await crypto.subtle.wrapKey("raw", cekForEncrypt, kek, "AES-KW"));
    // Web Crypto returns AES-GCM as ciphertext || tag; JWE stores those two
    // pieces in separate Compact Serialization segments.
    const encrypted = new Uint8Array(await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: utf8Encode(protectedSegment),
        tagLength: 128
      },
      cekForEncrypt,
      utf8Encode(plaintext)
    ));
    const ciphertext = encrypted.slice(0, encrypted.length - GCM_TAG_BYTES);
    const tag = encrypted.slice(encrypted.length - GCM_TAG_BYTES);
    return [
      protectedSegment,
      base64UrlEncode(encryptedKey),
      base64UrlEncode(iv),
      base64UrlEncode(ciphertext),
      base64UrlEncode(tag)
    ].join(".");
  }

  // Recover the passphrase JWE by validating the protected header first, then
  // deriving the KEK, unwrapping the CEK, and verifying AES-GCM authentication.
  async function decryptPassphraseJwe(compactJwe, passphrase) {
    const normalizedPassphrase = normalizePassphrase(passphrase);
    const crypto = getCrypto();
    const parts = splitCompactJwe(compactJwe);
    const header = parseProtectedHeader(parts.protectedSegment);
    validatePassphraseHeader(header);
    const salt = base64UrlDecode(header.p2s);
    const kek = await derivePbes2Key(normalizedPassphrase, salt, header.p2c);
    const encryptedKey = base64UrlDecode(parts.encryptedKeySegment);
    const iv = base64UrlDecode(parts.ivSegment);
    const ciphertext = base64UrlDecode(parts.ciphertextSegment, { allowEmpty: true });
    const tag = base64UrlDecode(parts.tagSegment);
    let cek;
    try {
      cek = await crypto.subtle.unwrapKey(
        "raw",
        encryptedKey,
        kek,
        "AES-KW",
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
      );
    } catch (error) {
      throw new Error("Wrong passphrase or corrupted payload.");
    }
    try {
      const plaintext = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: utf8Encode(parts.protectedSegment),
          tagLength: 128
        },
        cek,
        concatBytes(ciphertext, tag)
      );
      return utf8Decode(new Uint8Array(plaintext));
    } catch (error) {
      throw new Error("Wrong passphrase or corrupted payload.");
    }
  }

  function looksLikeCryptoKey(value) {
    return Boolean(value && typeof value === "object" && value.type && value.algorithm && value.usages);
  }

  async function importAesGcmKey(keyMaterial, usages) {
    if (looksLikeCryptoKey(keyMaterial)) {
      return keyMaterial;
    }
    const keyBytes = toUint8Array(keyMaterial);
    if (keyBytes.length !== AES_256_KEY_BYTES) {
      throw new Error("Direct JWE key must be 256 bits.");
    }
    return getCrypto().subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM", length: 256 },
      false,
      usages
    );
  }

  async function encryptDirectJwe(plaintext, keyMaterial, header, options) {
    const crypto = getCrypto();
    validateDirectHeader(header);
    const iv = options && options.iv ? toUint8Array(options.iv) : randomBytes(AES_GCM_IV_BYTES);
    if (iv.length !== AES_GCM_IV_BYTES) {
      throw new Error("AES-GCM IV must be 96 bits.");
    }
    const key = await importAesGcmKey(keyMaterial, ["encrypt"]);
    const protectedSegment = base64UrlEncode(utf8Encode(stringifyHeader(header)));
    const encrypted = new Uint8Array(await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: utf8Encode(protectedSegment),
        tagLength: 128
      },
      key,
      utf8Encode(plaintext)
    ));
    const ciphertext = encrypted.slice(0, encrypted.length - GCM_TAG_BYTES);
    const tag = encrypted.slice(encrypted.length - GCM_TAG_BYTES);
    return [
      protectedSegment,
      "",
      base64UrlEncode(iv),
      base64UrlEncode(ciphertext),
      base64UrlEncode(tag)
    ].join(".");
  }

  async function decryptDirectJwe(compactJwe, keyMaterial) {
    const crypto = getCrypto();
    const parts = splitCompactJwe(compactJwe);
    if (parts.encryptedKeySegment !== "") {
      throw new Error("Direct JWE must not contain an encrypted key.");
    }
    const header = parseProtectedHeader(parts.protectedSegment);
    validateDirectHeader(header);
    const iv = base64UrlDecode(parts.ivSegment);
    const ciphertext = base64UrlDecode(parts.ciphertextSegment, { allowEmpty: true });
    const tag = base64UrlDecode(parts.tagSegment);
    const key = await importAesGcmKey(keyMaterial, ["decrypt"]);
    try {
      const plaintext = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: utf8Encode(parts.protectedSegment),
          tagLength: 128
        },
        key,
        concatBytes(ciphertext, tag)
      );
      return utf8Decode(new Uint8Array(plaintext));
    } catch (error) {
      throw new Error("Wrong direct key or corrupted payload.");
    }
  }

  function getCurrentRpId(locationLike) {
    const locationValue = locationLike || root.location;
    if (!locationValue || !locationValue.hostname) {
      return "";
    }
    try {
      return normalizeRpId(locationValue.hostname);
    } catch (error) {
      return "";
    }
  }

  function isWebAuthnApiAvailable() {
    return Boolean(
      root.navigator &&
      root.navigator.credentials &&
      typeof root.navigator.credentials.create === "function" &&
      typeof root.navigator.credentials.get === "function" &&
      typeof root.PublicKeyCredential === "function"
    );
  }

  function getWebAuthnEnvironment(locationLike) {
    const locationValue = locationLike || root.location;
    const origin = locationValue && locationValue.origin && locationValue.origin !== "null"
      ? locationValue.origin
      : "local file";
    return {
      origin,
      rpId: getCurrentRpId(locationValue),
      secureContext: Boolean(root.isSecureContext),
      apiAvailable: isWebAuthnApiAvailable()
    };
  }

  function assertWebAuthnAvailable(rpId) {
    if (!root.isSecureContext) {
      throw new Error("WebAuthn PRF requires a browser secure context.");
    }
    if (!isWebAuthnApiAvailable()) {
      throw new Error("WebAuthn APIs are not available in this browser.");
    }
    if (!rpId) {
      throw new Error("WebAuthn RP ID is unavailable for this page.");
    }
  }

  function describeWebAuthnDomError(error) {
    if (!error || !error.name) {
      return error && error.message ? error.message : String(error);
    }
    if (error.name === "NotAllowedError") {
      return "request was cancelled, timed out, or the credential is unavailable";
    }
    if (error.name === "SecurityError") {
      return "this origin or RP ID is not allowed";
    }
    if (error.name === "NotSupportedError") {
      return "the requested WebAuthn PRF extension is not supported";
    }
    if (error.name === "InvalidStateError") {
      return "the authenticator rejected this credential request";
    }
    return error.message || error.name;
  }

  function getPrfFirstResult(credential) {
    if (!credential || typeof credential.getClientExtensionResults !== "function") {
      return null;
    }
    const extensionResults = credential.getClientExtensionResults();
    const first = extensionResults &&
      extensionResults.prf &&
      extensionResults.prf.results &&
      extensionResults.prf.results.first;
    if (!first) {
      return null;
    }
    const bytes = toUint8Array(first);
    if (bytes.length !== AES_256_KEY_BYTES) {
      throw new Error("Authenticator returned an invalid WebAuthn PRF result.");
    }
    return bytes;
  }

  function getPrfEnabledResult(credential) {
    if (!credential || typeof credential.getClientExtensionResults !== "function") {
      return null;
    }
    const extensionResults = credential.getClientExtensionResults();
    return extensionResults && extensionResults.prf && typeof extensionResults.prf.enabled === "boolean"
      ? extensionResults.prf.enabled
      : null;
  }

  async function createWebAuthnPrfCredential(prfSalt, rpId, options) {
    const saltBytes = toUint8Array(prfSalt);
    const normalizedRpId = normalizeRpId(rpId);
    assertWebAuthnAvailable(normalizedRpId);
    const label = options && options.label ? String(options.label) : "code";
    const randomLabel = base64UrlEncode(randomBytes(8));
    try {
      const credential = await root.navigator.credentials.create({
        publicKey: {
          challenge: randomBytes(32),
          rp: {
            id: normalizedRpId,
            name: "Encrypted 2D Barcode"
          },
          user: {
            id: randomBytes(32),
            name: "encrypted-2d-barcode-" + randomLabel,
            displayName: "Encrypted 2D Barcode " + label
          },
          pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 }
          ],
          authenticatorSelection: {
            residentKey: "discouraged",
            requireResidentKey: false,
            userVerification: "preferred"
          },
          attestation: "none",
          timeout: WEBAUTHN_TIMEOUT_MS,
          extensions: {
            prf: {
              eval: {
                first: saltBytes
              }
            }
          }
        }
      });
      if (!credential || !credential.rawId) {
        throw new Error("Browser did not return a WebAuthn credential.");
      }
      return credential;
    } catch (error) {
      throw new Error("WebAuthn credential creation failed: " + describeWebAuthnDomError(error) + ".");
    }
  }

  async function requestWebAuthnPrfOutput(credentialIdBase64Url, prfSalt, rpId) {
    const normalizedRpId = normalizeRpId(rpId);
    assertWebAuthnAvailable(normalizedRpId);
    const credentialId = base64UrlDecode(credentialIdBase64Url);
    const saltBytes = toUint8Array(prfSalt);
    try {
      const assertion = await root.navigator.credentials.get({
        publicKey: {
          challenge: randomBytes(32),
          rpId: normalizedRpId,
          allowCredentials: [
            {
              type: "public-key",
              id: credentialId
            }
          ],
          userVerification: "preferred",
          timeout: WEBAUTHN_TIMEOUT_MS,
          extensions: {
            prf: {
              evalByCredential: {
                [credentialIdBase64Url]: {
                  first: saltBytes
                }
              }
            }
          }
        }
      });
      if (!assertion || !assertion.rawId) {
        throw new Error("Browser did not return a WebAuthn assertion.");
      }
      const returnedCredentialId = base64UrlEncode(toUint8Array(assertion.rawId));
      if (returnedCredentialId !== credentialIdBase64Url) {
        throw new Error("Browser returned a different WebAuthn credential.");
      }
      const prfOutput = getPrfFirstResult(assertion);
      if (!prfOutput) {
        throw new Error("Authenticator did not return a WebAuthn PRF result.");
      }
      return prfOutput;
    } catch (error) {
      if (error && error.message && error.message.startsWith("Authenticator did not")) {
        throw error;
      }
      if (error && error.message && error.message.startsWith("Browser returned")) {
        throw error;
      }
      throw new Error("WebAuthn credential request failed: " + describeWebAuthnDomError(error) + ".");
    }
  }

  // HKDF profile:
  // IKM  = WebAuthn prf.results.first
  // salt = UTF8(WEBAUTHN_HKDF_SALT_LABEL) || 0x00 || protected-header ps
  // info = UTF8(WEBAUTHN_HKDF_INFO_LABEL) || 0x00 || UTF8(rp) || 0x00 || cid
  // L    = 32 bytes for A256GCM
  async function deriveWebAuthnDirectKeyBytes(prfOutput, metadata) {
    const crypto = getCrypto();
    const prfBytes = toUint8Array(prfOutput);
    if (prfBytes.length !== AES_256_KEY_BYTES) {
      throw new Error("WebAuthn PRF output must be 256 bits.");
    }
    const credentialId = toUint8Array(metadata.credentialId);
    const prfSalt = toUint8Array(metadata.prfSalt);
    if (prfSalt.length !== WEBAUTHN_PRF_SALT_BYTES) {
      throw new Error("WebAuthn PRF salt must be 256 bits.");
    }
    const key = await crypto.subtle.importKey(
      "raw",
      prfBytes,
      "HKDF",
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: concatBytes(utf8Encode(WEBAUTHN_HKDF_SALT_LABEL), new Uint8Array([0]), prfSalt),
        info: concatBytes(
          utf8Encode(WEBAUTHN_HKDF_INFO_LABEL),
          new Uint8Array([0]),
          utf8Encode(normalizeRpId(metadata.rpId)),
          new Uint8Array([0]),
          credentialId
        )
      },
      key,
      256
    );
    return new Uint8Array(bits);
  }

  async function encryptWebAuthnJwe(plaintext, options) {
    const rpId = options && options.rpId ? normalizeRpId(options.rpId) : getCurrentRpId();
    assertWebAuthnAvailable(rpId);
    const prfSalt = randomBytes(WEBAUTHN_PRF_SALT_BYTES);
    const credential = await createWebAuthnPrfCredential(prfSalt, rpId, { label: "code" });
    const credentialIdBase64Url = base64UrlEncode(toUint8Array(credential.rawId));
    const prfEnabled = getPrfEnabledResult(credential);
    if (prfEnabled === false) {
      throw new Error("Authenticator did not enable WebAuthn PRF for this credential.");
    }
    let prfOutput = getPrfFirstResult(credential);
    if (!prfOutput) {
      prfOutput = await requestWebAuthnPrfOutput(credentialIdBase64Url, prfSalt, rpId);
    }
    const header = makeWebAuthnProtectedHeader(credentialIdBase64Url, rpId, prfSalt);
    const metadata = validateDirectHeader(header);
    const directKey = await deriveWebAuthnDirectKeyBytes(prfOutput, metadata);
    return encryptDirectJwe(plaintext, directKey, header, options);
  }

  async function decryptWebAuthnJwe(compactJwe, options) {
    const parts = splitCompactJwe(compactJwe);
    const header = parseProtectedHeader(parts.protectedSegment);
    const metadata = validateDirectHeader(header);
    const currentRpId = options && options.rpId ? normalizeRpId(options.rpId) : getCurrentRpId();
    if (currentRpId && currentRpId !== metadata.rpId) {
      throw new Error("This WebAuthn code was created for RP ID " + metadata.rpId + ", but this page is " + currentRpId + ".");
    }
    const prfOutput = await requestWebAuthnPrfOutput(
      metadata.credentialIdBase64Url,
      metadata.prfSalt,
      metadata.rpId
    );
    const directKey = await deriveWebAuthnDirectKeyBytes(prfOutput, metadata);
    try {
      return await decryptDirectJwe(compactJwe, directKey);
    } catch (error) {
      throw new Error("Wrong WebAuthn credential or corrupted payload.");
    }
  }

  async function probeWebAuthnPrf() {
    const env = getWebAuthnEnvironment();
    assertWebAuthnAvailable(env.rpId);
    const prfSalt = randomBytes(WEBAUTHN_PRF_SALT_BYTES);
    const credential = await createWebAuthnPrfCredential(prfSalt, env.rpId, { label: "probe" });
    const credentialIdBase64Url = base64UrlEncode(toUint8Array(credential.rawId));
    const prfEnabled = getPrfEnabledResult(credential);
    if (prfEnabled === false) {
      throw new Error("Authenticator did not enable WebAuthn PRF for the probe credential.");
    }
    let prfOutput = getPrfFirstResult(credential);
    let method = "registration";
    if (!prfOutput) {
      prfOutput = await requestWebAuthnPrfOutput(credentialIdBase64Url, prfSalt, env.rpId);
      method = "assertion";
    }
    return {
      ok: true,
      origin: env.origin,
      rpId: env.rpId,
      outputBytes: prfOutput.length,
      method
    };
  }

  // Recovery input can be a raw payload or a full URL scanned from an encrypted
  // QR. Only recognized fragments are extracted; ordinary URLs remain plain
  // strings so plain mode can encode URLs without surprise behavior.
  function extractPayloadFromInput(input) {
    const raw = String(input || "");
    const trimmed = raw.trim();
    if (!trimmed) {
      throw new Error("Enter a payload first.");
    }
    if (trimmed.startsWith(PLAIN_PREFIX) || trimmed.startsWith(ENCRYPTED_PREFIX)) {
      return trimmed;
    }
    let parsed;
    try {
      parsed = new URL(trimmed);
    } catch (error) {
      return raw;
    }
    const hash = parsed.hash ? parsed.hash.slice(1) : "";
    if (!hash) {
      return raw;
    }
    let decodedHash;
    try {
      decodedHash = decodeURIComponent(hash);
    } catch (error) {
      decodedHash = hash;
    }
    if (decodedHash.startsWith(PLAIN_PREFIX) || decodedHash.startsWith(ENCRYPTED_PREFIX)) {
      return decodedHash;
    }
    return raw;
  }

  // Lightweight router for payload kind. It validates enough metadata to decide
  // which recovery flow is needed, but does not decrypt anything here.
  function detectPayload(input) {
    const payload = extractPayloadFromInput(input);
    if (payload.startsWith(PLAIN_PREFIX)) {
      return {
        kind: "plain",
        payload,
        label: "Plain unencrypted payload"
      };
    }
    if (payload.startsWith(ENCRYPTED_PREFIX)) {
      const compactJwe = payload.slice(ENCRYPTED_PREFIX.length);
      const parts = splitCompactJwe(compactJwe);
      const header = parseProtectedHeader(parts.protectedSegment);
      if (header.alg === PASSWORD_ALG) {
        validatePassphraseHeader(header);
        return {
          kind: "passphrase",
          payload,
          compactJwe,
          label: "Passphrase encrypted payload"
        };
      }
      if (header.alg === DIRECT_ALG) {
        validateDirectHeader(header);
        return {
          kind: "webauthn",
          payload,
          compactJwe,
          label: "WebAuthn PRF encrypted payload"
        };
      }
      throw new Error("Unsupported encrypted payload.");
    }
    return {
      kind: "plain",
      payload,
      label: "Plain unencrypted payload"
    };
  }

  // Display-only checksum for humans comparing printed/scanned QR output. This
  // is not a security check and is not used for decryption.
  function shortChecksum(value) {
    let hash = 0x811c9dc5;
    for (let index = 0; index < value.length; index += 1) {
      hash ^= value.charCodeAt(index);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash.toString(16).padStart(8, "0").toUpperCase();
  }

  // QR generation itself is delegated to qrcode-generator. The Node require
  // path exists only for tests; production loads static/vendor/qrcode-generator.
  function getQrFactory() {
    if (typeof root.qrcode === "function") {
      return root.qrcode;
    }
    if (typeof require === "function") {
      return require("qrcode-generator");
    }
    throw new Error("QR code library is not loaded.");
  }

  // Byte mode keeps arbitrary user strings and JWE payloads in one predictable
  // QR encoding mode while the library handles standards details.
  function createQrCode(text, errorCorrectionLevel) {
    const qr = getQrFactory()(0, errorCorrectionLevel || QR_ERROR_CORRECTION);
    qr.addData(text, "Byte");
    qr.make();
    return qr;
  }

  // Calculate display sizing from the library-generated matrix. This keeps
  // rendering choices separate from QR encoding choices.
  function getQrRenderPlan(text) {
    const qr = createQrCode(text, QR_ERROR_CORRECTION);
    const moduleCount = qr.getModuleCount();
    return {
      qr,
      errorCorrectionLevel: QR_ERROR_CORRECTION,
      version: Math.round((moduleCount - 17) / 4),
      moduleCount,
      marginModules: QR_MARGIN_MODULES,
      modulePixels: QR_MODULE_PIXELS,
      pixelSize: (moduleCount + QR_MARGIN_MODULES * 2) * QR_MODULE_PIXELS
    };
  }

  // Draw the library-provided module matrix onto a canvas. This is rendering
  // code only; it does not implement QR encoding or error correction.
  function drawQrToCanvas(canvas, text) {
    const plan = getQrRenderPlan(text);
    canvas.width = plan.pixelSize;
    canvas.height = plan.pixelSize;
    canvas.dataset.qrVersion = String(plan.version);
    canvas.dataset.qrModuleCount = String(plan.moduleCount);
    canvas.dataset.qrModulePixels = String(plan.modulePixels);

    const ctx = canvas.getContext("2d");
    ctx.imageSmoothingEnabled = false;
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#000000";

    for (let row = 0; row < plan.moduleCount; row += 1) {
      for (let col = 0; col < plan.moduleCount; col += 1) {
        if (plan.qr.isDark(row, col)) {
          ctx.fillRect(
            (col + plan.marginModules) * plan.modulePixels,
            (row + plan.marginModules) * plan.modulePixels,
            plan.modulePixels,
            plan.modulePixels
          );
        }
      }
    }

    return plan;
  }

  // Canvas output needs manual wrapping because the recovered secret is not
  // inserted as normal DOM text.
  function wrapCanvasText(ctx, text, maxWidth) {
    const paragraphs = String(text).split(/\r?\n/);
    const lines = [];
    for (const paragraph of paragraphs) {
      const words = paragraph.length ? paragraph.split(/(\s+)/).filter(Boolean) : [""];
      let line = "";
      for (const word of words) {
        const test = line + word;
        if (ctx.measureText(test).width <= maxWidth || line === "") {
          line = test;
          continue;
        }
        lines.push(line.trimEnd());
        line = word.trimStart();
        while (ctx.measureText(line).width > maxWidth && line.length > 1) {
          let split = 1;
          while (split < line.length && ctx.measureText(line.slice(0, split + 1)).width <= maxWidth) {
            split += 1;
          }
          lines.push(line.slice(0, split));
          line = line.slice(split);
        }
      }
      lines.push(line);
    }
    return lines;
  }

  // Recovered secrets are drawn to canvas and auto-hidden. This is UI hygiene,
  // not a cryptographic guarantee; copying still requires explicit confirmation.
  function renderSecretToCanvas(canvas, text) {
    const width = 900;
    const contextForMeasure = canvas.getContext("2d");
    contextForMeasure.font = "20px ui-monospace, SFMono-Regular, Consolas, monospace";
    const lines = wrapCanvasText(contextForMeasure, text, width - 56);
    const lineHeight = 29;
    const height = Math.max(180, Math.min(1200, 52 + lines.length * lineHeight));
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#17202a";
    ctx.font = "20px ui-monospace, SFMono-Regular, Consolas, monospace";
    ctx.textBaseline = "top";
    const maxLines = Math.floor((height - 52) / lineHeight);
    for (let index = 0; index < Math.min(lines.length, maxLines); index += 1) {
      ctx.fillText(lines[index], 28, 26 + index * lineHeight);
    }
    if (lines.length > maxLines) {
      ctx.fillStyle = "#b42318";
      ctx.fillText("[Output truncated on canvas. Use Copy Anyway if needed.]", 28, height - 30);
    }
  }

  function setHidden(element, hidden) {
    element.classList.toggle("hidden", hidden);
  }

  // Fragment-only URLs open directly into recovery mode. The fragment is not
  // sent to the server during normal HTTP requests.
  function getFragmentPayload() {
    if (!root.location || !root.location.hash || root.location.hash.length <= 1) {
      return "";
    }
    const raw = root.location.hash.slice(1);
    try {
      return decodeURIComponent(raw);
    } catch (error) {
      return raw;
    }
  }

  function determineInitialView(locationLike) {
    const locationValue = locationLike || root.location;
    return locationValue && locationValue.hash && locationValue.hash.length > 1 ? "recover" : "create";
  }

  // Self-awareness for hosted encrypted QRs: strip query/hash from the current
  // page and reuse the same origin/path as the recovery URL.
  function getRecoveryBaseUrl(locationLike) {
    const locationValue = locationLike || root.location;
    if (!locationValue || !locationValue.href) {
      return "";
    }
    let url;
    try {
      url = new URL(locationValue.href);
    } catch (error) {
      return "";
    }
    if (url.protocol !== "https:" && url.protocol !== "http:") {
      return "";
    }
    url.hash = "";
    url.search = "";
    return url.toString();
  }

  function shouldEncodeQrAsUrl(locationLike) {
    return getRecoveryBaseUrl(locationLike) !== "";
  }

  // Plain QR mode returns the raw string. Encrypted QR mode uses a URL fragment
  // when hosted so scanning the QR opens this app directly in recovery mode.
  function buildQrContent(payload, locationLike) {
    if (!payload.startsWith(ENCRYPTED_PREFIX)) {
      return payload;
    }
    const baseUrl = getRecoveryBaseUrl(locationLike);
    if (!baseUrl) {
      return payload;
    }
    return baseUrl + "#" + encodeURIComponent(payload);
  }

  // Prefer the async Clipboard API on secure origins. The textarea fallback is
  // only for copying already-visible generated payload fields.
  async function copyText(text, fallbackTextArea) {
    if (root.navigator && root.navigator.clipboard && root.isSecureContext) {
      await root.navigator.clipboard.writeText(text);
      return;
    }
    if (fallbackTextArea) {
      fallbackTextArea.focus();
      fallbackTextArea.select();
      document.execCommand("copy");
      fallbackTextArea.setSelectionRange(0, 0);
      return;
    }
    throw new Error("Clipboard is unavailable in this context.");
  }

  /*
   * DOM glue below. The exported functions above are the audit target for data
   * format, crypto, and QR behavior; this section wires them into the page.
   */
  function initDom() {
    const $ = (id) => document.getElementById(id);
    const elements = {
      originLabel: $("origin-label"),
      secretInput: $("secret-input"),
      createPassphrase: $("create-passphrase"),
      createPassphraseConfirm: $("create-passphrase-confirm"),
      createPassphraseFields: $("passphrase-create-fields"),
      webauthnCreateFields: $("webauthn-create-fields"),
      webauthnAck: $("webauthn-ack"),
      webauthnOriginStatus: $("webauthn-origin-status"),
      webauthnRpStatus: $("webauthn-rp-status"),
      webauthnSecureStatus: $("webauthn-secure-status"),
      webauthnApiStatus: $("webauthn-api-status"),
      webauthnPrfStatus: $("webauthn-prf-status"),
      prfProbeButton: $("prf-probe-button"),
      plainWarning: $("plain-warning"),
      createButton: $("create-button"),
      clearCreateButton: $("clear-create-button"),
      createError: $("create-error"),
      outputArea: $("output-area"),
      payloadOutput: $("payload-output"),
      copyPayloadButton: $("copy-payload-button"),
      copyUrlButton: $("copy-url-button"),
      downloadCodeButton: $("download-code-button"),
      printButton: $("print-button"),
      qrCanvas: $("qr-canvas"),
      codeModeLabel: $("code-mode-label"),
      codeDate: $("code-date"),
      codeChecksum: $("code-checksum"),
      qrContentOutput: $("qr-content-output"),
      qrContentField: $("qr-content-field"),
      recoverPayload: $("recover-payload"),
      recoverPassphrase: $("recover-passphrase"),
      recoverPassphraseField: $("recover-passphrase-field"),
      recoverModeSummary: $("recover-mode-summary"),
      recoverButton: $("recover-button"),
      clearRecoverButton: $("clear-recover-button"),
      recoverError: $("recover-error"),
      protectedArea: $("protected-area"),
      protectedCanvas: $("protected-canvas"),
      hideSecretButton: $("hide-secret-button"),
      copySecretButton: $("copy-secret-button"),
      hideCountdown: $("hide-countdown"),
      fragmentBanner: $("fragment-banner")
    };

    elements.originLabel.textContent = root.location && root.location.origin !== "null"
      ? root.location.origin
      : "local file";

    let latestPayload = "";
    let latestQrContent = "";
    let recoveredSecret = "";
    let hideTimer = 0;
    let countdownTimer = 0;
    let hideAt = 0;

    function currentCreateMode() {
      const checked = document.querySelector("input[name='create-mode']:checked");
      return checked ? checked.value : "passphrase";
    }

    function clearError(element) {
      element.textContent = "";
    }

    function showError(element, error) {
      element.textContent = error && error.message ? error.message : String(error);
    }

    function yesNo(value) {
      return value ? "Yes" : "No";
    }

    function updateWebAuthnStatus(prfStatus) {
      const env = getWebAuthnEnvironment();
      elements.webauthnOriginStatus.textContent = env.origin;
      elements.webauthnRpStatus.textContent = env.rpId || "Unavailable";
      elements.webauthnSecureStatus.textContent = yesNo(env.secureContext);
      elements.webauthnApiStatus.textContent = yesNo(env.apiAvailable);
      if (prfStatus) {
        elements.webauthnPrfStatus.textContent = prfStatus;
      }
    }

    function updateModeUi() {
      const mode = currentCreateMode();
      setHidden(elements.createPassphraseFields, mode !== "passphrase");
      setHidden(elements.webauthnCreateFields, mode !== "webauthn");
      setHidden(elements.plainWarning, mode !== "plain");
    }

    function setAppView(view) {
      document.body.dataset.view = view === "recover" ? "recover" : "create";
    }

    function updateRecoverSummary() {
      clearError(elements.recoverError);
      const value = elements.recoverPayload.value;
      if (!value.trim()) {
        elements.recoverModeSummary.textContent = "Waiting for payload.";
        setHidden(elements.recoverPassphraseField, false);
        return;
      }
      try {
        const detected = detectPayload(value);
        elements.recoverModeSummary.textContent = detected.label;
        setHidden(elements.recoverPassphraseField, detected.kind !== "passphrase");
      } catch (error) {
        elements.recoverModeSummary.textContent = "Unsupported or malformed payload.";
      }
    }

    function renderOutput(payload, modeLabel) {
      latestPayload = payload;
      latestQrContent = buildQrContent(payload);
      if (payload.startsWith(ENCRYPTED_PREFIX) && shouldEncodeQrAsUrl() && latestQrContent === payload) {
        throw new Error("Hosted QR generation must include this page URL.");
      }
      elements.payloadOutput.value = payload;
      elements.qrContentOutput.value = latestQrContent;
      setHidden(elements.qrContentField, latestQrContent === payload);
      elements.codeModeLabel.textContent = modeLabel;
      elements.codeDate.textContent = new Date().toISOString().slice(0, 10);
      elements.codeChecksum.textContent = "Checksum " + shortChecksum(latestQrContent);
      drawQrToCanvas(elements.qrCanvas, latestQrContent);
      setHidden(elements.outputArea, false);
    }

    function hideSecret() {
      recoveredSecret = "";
      root.clearTimeout(hideTimer);
      root.clearInterval(countdownTimer);
      elements.hideCountdown.textContent = "";
      const ctx = elements.protectedCanvas.getContext("2d");
      ctx.clearRect(0, 0, elements.protectedCanvas.width, elements.protectedCanvas.height);
      setHidden(elements.protectedArea, true);
    }

    function startProtectedDisplay(text) {
      recoveredSecret = text;
      renderSecretToCanvas(elements.protectedCanvas, text);
      setHidden(elements.protectedArea, false);
      root.clearTimeout(hideTimer);
      root.clearInterval(countdownTimer);
      hideAt = Date.now() + 60000;
      countdownTimer = root.setInterval(() => {
        const remaining = Math.max(0, Math.ceil((hideAt - Date.now()) / 1000));
        elements.hideCountdown.textContent = remaining ? "Hides in " + remaining + "s" : "";
      }, 250);
      hideTimer = root.setTimeout(hideSecret, 60000);
    }

    async function createPayload() {
      clearError(elements.createError);
      hideSecret();
      try {
        const text = elements.secretInput.value;
        if (!text) {
          throw new Error("Enter a string first.");
        }
        const mode = currentCreateMode();
        if (mode === "plain") {
          renderOutput(encodePlainPayload(text), "Plain unencrypted code");
          return;
        }
        if (mode === "webauthn") {
          if (!elements.webauthnAck.checked) {
            throw new Error("Confirm the WebAuthn PRF recovery dependency first.");
          }
          const compactJwe = await encryptWebAuthnJwe(text);
          renderOutput(ENCRYPTED_PREFIX + compactJwe, "WebAuthn PRF encrypted code");
          updateWebAuthnStatus("Succeeded for generated code");
          return;
        }
        const passphrase = elements.createPassphrase.value;
        const confirm = elements.createPassphraseConfirm.value;
        if (passphrase !== confirm) {
          throw new Error("Passphrase confirmation does not match.");
        }
        const compactJwe = await encryptPassphraseJwe(text, passphrase);
        renderOutput(ENCRYPTED_PREFIX + compactJwe, "Passphrase encrypted code");
      } catch (error) {
        showError(elements.createError, error);
      }
    }

    async function recoverPayload() {
      clearError(elements.recoverError);
      hideSecret();
      try {
        const detected = detectPayload(elements.recoverPayload.value);
        if (detected.kind === "plain") {
          startProtectedDisplay(decodePlainPayload(detected.payload));
          return;
        }
        if (detected.kind === "webauthn") {
          startProtectedDisplay(await decryptWebAuthnJwe(detected.compactJwe));
          return;
        }
        startProtectedDisplay(await decryptPassphraseJwe(detected.compactJwe, elements.recoverPassphrase.value));
      } catch (error) {
        showError(elements.recoverError, error);
      }
    }

    document.querySelectorAll("input[name='create-mode']").forEach((input) => {
      input.addEventListener("change", updateModeUi);
    });
    elements.createButton.addEventListener("click", createPayload);
    elements.clearCreateButton.addEventListener("click", () => {
      elements.secretInput.value = "";
      elements.createPassphrase.value = "";
      elements.createPassphraseConfirm.value = "";
      elements.webauthnAck.checked = false;
      elements.payloadOutput.value = "";
      elements.qrContentOutput.value = "";
      latestPayload = "";
      latestQrContent = "";
      setHidden(elements.outputArea, true);
      clearError(elements.createError);
    });
    elements.prfProbeButton.addEventListener("click", async () => {
      clearError(elements.createError);
      updateWebAuthnStatus("Running");
      elements.prfProbeButton.disabled = true;
      try {
        const result = await probeWebAuthnPrf();
        updateWebAuthnStatus("Succeeded via " + result.method);
      } catch (error) {
        updateWebAuthnStatus("Failed");
        showError(elements.createError, error);
      } finally {
        elements.prfProbeButton.disabled = false;
      }
    });
    elements.copyPayloadButton.addEventListener("click", async () => {
      try {
        await copyText(latestPayload, elements.payloadOutput);
      } catch (error) {
        showError(elements.createError, error);
      }
    });
    elements.copyUrlButton.addEventListener("click", async () => {
      try {
        await copyText(latestQrContent, elements.payloadOutput);
      } catch (error) {
        showError(elements.createError, error);
      }
    });
    elements.downloadCodeButton.addEventListener("click", () => {
      const link = document.createElement("a");
      link.download = "encrypted-2d-barcode.png";
      link.href = elements.qrCanvas.toDataURL("image/png");
      link.click();
    });
    elements.printButton.addEventListener("click", () => root.print());
    elements.recoverPayload.addEventListener("input", updateRecoverSummary);
    elements.recoverButton.addEventListener("click", recoverPayload);
    elements.clearRecoverButton.addEventListener("click", () => {
      elements.recoverPayload.value = "";
      elements.recoverPassphrase.value = "";
      clearError(elements.recoverError);
      updateRecoverSummary();
      hideSecret();
    });
    elements.hideSecretButton.addEventListener("click", hideSecret);
    elements.copySecretButton.addEventListener("click", async () => {
      if (!recoveredSecret) {
        return;
      }
      if (!root.confirm("Copying places the recovered string on the system clipboard. Continue?")) {
        return;
      }
      try {
        await copyText(recoveredSecret);
      } catch (error) {
        showError(elements.recoverError, error);
      }
    });
    root.addEventListener("blur", hideSecret);
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        hideSecret();
      }
    });

    const fragmentPayload = getFragmentPayload();
    setAppView(determineInitialView(root.location));
    if (fragmentPayload) {
      elements.recoverPayload.value = fragmentPayload;
      updateRecoverSummary();
      setHidden(elements.fragmentBanner, false);
    } else {
      updateRecoverSummary();
    }
    updateWebAuthnStatus();
    updateModeUi();
  }

  const api = {
    ENCRYPTED_PREFIX,
    PLAIN_PREFIX,
    base64UrlEncode,
    base64UrlDecode,
    utf8Encode,
    utf8Decode,
    encodePlainPayload,
    decodePlainPayload,
    encryptPassphraseJwe,
    decryptPassphraseJwe,
    encryptDirectJwe,
    decryptDirectJwe,
    makeWebAuthnProtectedHeader,
    validateDirectHeader,
    deriveWebAuthnDirectKeyBytes,
    getCurrentRpId,
    getWebAuthnEnvironment,
    encryptWebAuthnJwe,
    decryptWebAuthnJwe,
    probeWebAuthnPrf,
    extractPayloadFromInput,
    detectPayload,
    parseProtectedHeader,
    validatePassphraseHeader,
    splitCompactJwe,
    determineInitialView,
    getRecoveryBaseUrl,
    shouldEncodeQrAsUrl,
    buildQrContent,
    shortChecksum,
    createQrCode,
    getQrRenderPlan,
    drawQrToCanvas
  };

  root.ERKApp = api;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  if (typeof document !== "undefined") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", initDom);
    } else {
      initDom();
    }
  }
})(typeof globalThis !== "undefined" ? globalThis : window);
