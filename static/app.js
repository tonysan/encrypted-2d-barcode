(function initCore(root) {
  "use strict";

  const config = root.ERKConfig;
  if (!config) {
    throw new Error("Config module is not loaded.");
  }

  const {
    ENCRYPTED_PREFIX,
    PLAIN_PREFIX,
    PASSWORD_ALG,
    WEBAUTHN_ALG,
    CONTENT_ALG,
    DEFAULT_P2C,
    MAX_P2C,
    GCM_TAG_BYTES,
    QR_ERROR_CORRECTION,
    QR_MARGIN_MODULES,
    QR_MODULE_PIXELS,
    WEBAUTHN_PROFILE,
    WEBAUTHN_PRF_SALT_BYTES,
    AES_256_KEY_BYTES,
    AES_GCM_IV_BYTES,
    WEBAUTHN_TIMEOUT_MS,
    WEBAUTHN_HKDF_SALT_LABEL,
    WEBAUTHN_HKDF_INFO_LABEL,
    PASSKEY_CREDENTIAL_STORAGE_KEY,
    WEBAUTHN_TRANSPORTS,
    WEBAUTHN_HINTS,
    PASSKEY_LABEL,
    PASSKEY_USER_ID,
    DOWNLOAD_FILENAME,
    MSG_EMPTY_PASSPHRASE,
    MSG_WRONG_PASSPHRASE,
    MSG_EMPTY_PAYLOAD,
    MSG_NO_CLIPBOARD,
    MSG_HOSTED_QR_URL_REQUIRED,
    MSG_EMPTY_SECRET,
    MSG_PASSPHRASE_MISMATCH,
    MSG_PASSKEY_ACK_REQUIRED,
    MSG_PLAIN_MODE_WARNING,
    MSG_WEBAUTHN_MODE_NOTICE,
    MSG_WEBAUTHN_SETUP_FAILED,
    MSG_WEBAUTHN_SETUP_CANCELLED,
    MSG_WEBAUTHN_SETUP_GENERIC,
    MSG_WEBAUTHN_RECOVERY_DIFFERENT_SITE,
    MSG_WEBAUTHN_RECOVERY_FAILED,
    MSG_WEBAUTHN_RECOVERY_GENERIC,
    MSG_COPY_SUCCESS,
    MSG_TRUNCATED_OUTPUT,
    MSG_WAITING_FOR_PAYLOAD,
    MSG_UNSUPPORTED_PAYLOAD_TYPE,
    MSG_PLAIN_UNENCRYPTED,
    MSG_PASSPHRASE_ENCRYPTED,
    MSG_WEBAUTHN_ENCRYPTED,
    MSG_PLAIN_MODE_LABEL,
    MSG_PASSPHRASE_MODE_LABEL,
    MSG_WEBAUTHN_MODE_LABEL,
    MSG_LOCAL_FILE,
    MSG_YES,
    MSG_NO,
    MSG_UNAVAILABLE,
    MSG_CHECKSUM_PREFIX,
    MSG_HIDE_COUNTDOWN_PREFIX,
    MSG_HIDE_COUNTDOWN_SUFFIX,
    MSG_PRF_CHECKING,
    MSG_PRF_SUCCEEDED,
    MSG_PRF_FAILED,
    MSG_CLEAR_BUTTON,
    MSG_CONFIRM_BUTTON,
    MSG_INVALID_BASE64URL,
    MSG_MALFORMED_HEADER,
    MSG_UNSUPPORTED_HEADER,
    MSG_UNSUPPORTED_ALG,
    MSG_UNSUPPORTED_ENC,
    MSG_UNSUPPORTED_P2C,
    MSG_UNSUPPORTED_P2C_OPTION,
    MSG_UNSUPPORTED_WEBAUTHN,
    MSG_MALFORMED_WEBAUTHN,
    MSG_MALFORMED_CREDENTIAL_ID,
    MSG_MALFORMED_PRF_SALT,
    MSG_EXPECTED_JWE,
    MSG_INVALID_RP_ID,
    MSG_NO_CRYPTO,
    MSG_EXPECTED_BINARY,
    MSG_NO_QR_LIB,
    MSG_UNSUPPORTED_PAYLOAD,
    MSG_NO_STORAGE,
    MSG_WEBAUTHN_SECURE_CONTEXT,
    MSG_WEBAUTHN_API_UNAVAILABLE,
    MSG_WEBAUTHN_RP_UNAVAILABLE,
    MSG_WEBAUTHN_CREDENTIAL_CREATION,
    MSG_WEBAUTHN_CREDENTIAL_REQUEST,
    MSG_WEBAUTHN_DIFFERENT_CREDENTIAL,
    MSG_WEBAUTHN_NO_PRF_RESULT,
    MSG_WEBAUTHN_INVALID_PRF_OUTPUT,
    MSG_WEBAUTHN_PRF_DISABLED,
    MSG_WEBAUTHN_WRONG_CREDENTIAL,
    MSG_WEBAUTHN_DIFFERENT_RP,
    MSG_WEBAUTHN_DIFFERENT_RP_PAGE,
    MSG_INVALID_WEBAUTHN_KEK_SIZE,
    MSG_INVALID_IV_SIZE,
    MSG_INVALID_PRF_OUTPUT_SIZE,
    MSG_INVALID_PRF_SALT_SIZE,
    MSG_WEBAUTHN_CREDENTIAL_CREATION_FAILED,
    MSG_WEBAUTHN_CREDENTIAL_REQUEST_FAILED,
    MSG_EXISTING_PASSKEY_REQUEST_FAILED,
    MSG_WEBAUTHN_REQUEST_CANCELLED,
    MSG_WEBAUTHN_ORIGIN_NOT_ALLOWED,
    MSG_WEBAUTHN_PRF_NOT_SUPPORTED,
    MSG_WEBAUTHN_AUTHENTICATOR_REJECTED
  } = config;

  /*
   * Audit map:
   * - QR standards logic is delegated to pinned qrcode-generator.
   * - Cryptographic primitives are delegated to Web Crypto.
   * - This file owns the app profile, format validation, and non-DOM helpers.
   * - The base64 helpers below are JOSE Compact Serialization glue. They adapt
   *   bytes to unpadded base64url because browsers expose standard base64 via
   *   btoa/atob, not a universal base64url API.
   */

  // Web Crypto is the security boundary. Node's webcrypto fallback lets tests
  // exercise the same API shape without adding a crypto dependency.
  function getCrypto() {
    if (root.crypto && root.crypto.subtle && root.crypto.getRandomValues) {
      return root.crypto;
    }
    if (typeof require === "function") {
      return require("node:crypto").webcrypto;
    }
    throw new Error(MSG_NO_CRYPTO);
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
    throw new Error(MSG_EXPECTED_BINARY);
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
      throw new Error(MSG_INVALID_BASE64URL);
    }
    if (!/^[A-Za-z0-9_-]+$/.test(value) || value.includes("=")) {
      throw new Error(MSG_INVALID_BASE64URL);
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
      throw new Error(MSG_EMPTY_PASSPHRASE);
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
      throw new Error(MSG_INVALID_RP_ID);
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
      alg: WEBAUTHN_ALG,
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
      throw new Error(MSG_MALFORMED_HEADER);
    }
    if (!header || typeof header !== "object" || Array.isArray(header)) {
      throw new Error(MSG_MALFORMED_HEADER);
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
        throw new Error(MSG_UNSUPPORTED_HEADER);
      }
    }
    if (header.alg !== PASSWORD_ALG) {
      throw new Error(MSG_UNSUPPORTED_ALG);
    }
    if (header.enc !== CONTENT_ALG) {
      throw new Error(MSG_UNSUPPORTED_ENC);
    }
    if (!Number.isInteger(header.p2c) || header.p2c < 1000 || header.p2c > MAX_P2C) {
      throw new Error(MSG_UNSUPPORTED_P2C);
    }
    base64UrlDecode(header.p2s);
  }

  // WebAuthn PRF uses a symmetric AES-KW recipient key derived locally from PRF
  // output. The protected header stores only non-secret recovery metadata.
  function validateWebAuthnHeader(header) {
    const allowed = new Set(["alg", "enc", "app", "cid", "rp", "ps"]);
    for (const key of Object.keys(header)) {
      if (!allowed.has(key)) {
        throw new Error(MSG_UNSUPPORTED_HEADER);
      }
    }
    if (header.alg !== WEBAUTHN_ALG) {
      throw new Error(MSG_UNSUPPORTED_ALG);
    }
    if (header.enc !== CONTENT_ALG) {
      throw new Error(MSG_UNSUPPORTED_ENC);
    }
    if (header.app !== WEBAUTHN_PROFILE) {
      throw new Error(MSG_UNSUPPORTED_WEBAUTHN);
    }
    if (typeof header.cid !== "string" || typeof header.ps !== "string" || typeof header.rp !== "string") {
      throw new Error(MSG_MALFORMED_WEBAUTHN);
    }
    const credentialId = base64UrlDecode(header.cid);
    if (credentialId.length === 0) {
      throw new Error(MSG_MALFORMED_CREDENTIAL_ID);
    }
    const prfSalt = base64UrlDecode(header.ps);
    if (prfSalt.length !== WEBAUTHN_PRF_SALT_BYTES) {
      throw new Error(MSG_MALFORMED_PRF_SALT);
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
      throw new Error(MSG_EXPECTED_JWE);
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
      throw new Error(MSG_UNSUPPORTED_P2C_OPTION);
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
      throw new Error(MSG_WRONG_PASSPHRASE);
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
      throw new Error(MSG_WRONG_PASSPHRASE);
    }
  }

  function looksLikeCryptoKey(value) {
    return Boolean(value && typeof value === "object" && value.type && value.algorithm && value.usages);
  }

  async function importAesKwKey(keyMaterial, usages) {
    if (looksLikeCryptoKey(keyMaterial)) {
      return keyMaterial;
    }
    const keyBytes = toUint8Array(keyMaterial);
    if (keyBytes.length !== AES_256_KEY_BYTES) {
      throw new Error(MSG_INVALID_WEBAUTHN_KEK_SIZE);
    }
    return getCrypto().subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-KW", length: 256 },
      false,
      usages
    );
  }

  async function encryptWebAuthnWrappedJwe(plaintext, kekMaterial, header) {
    const crypto = getCrypto();
    validateWebAuthnHeader(header);
    const iv = randomBytes(AES_GCM_IV_BYTES);
    const cekBytes = randomBytes(AES_256_KEY_BYTES);
    const cekForEncrypt = await crypto.subtle.importKey(
      "raw",
      cekBytes,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt"]
    );
    const kek = await importAesKwKey(kekMaterial, ["wrapKey"]);
    const protectedSegment = base64UrlEncode(utf8Encode(stringifyHeader(header)));
    const encryptedKey = new Uint8Array(await crypto.subtle.wrapKey("raw", cekForEncrypt, kek, "AES-KW"));
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

  async function decryptWebAuthnWrappedJwe(compactJwe, kekMaterial) {
    const crypto = getCrypto();
    const parts = splitCompactJwe(compactJwe);
    const header = parseProtectedHeader(parts.protectedSegment);
    validateWebAuthnHeader(header);
    const encryptedKey = base64UrlDecode(parts.encryptedKeySegment);
    const iv = base64UrlDecode(parts.ivSegment);
    const ciphertext = base64UrlDecode(parts.ciphertextSegment, { allowEmpty: true });
    const tag = base64UrlDecode(parts.tagSegment);
    const kek = await importAesKwKey(kekMaterial, ["unwrapKey"]);
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
      throw new Error(MSG_WEBAUTHN_WRONG_CREDENTIAL);
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
      throw new Error(MSG_WEBAUTHN_WRONG_CREDENTIAL);
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

  // Recovery input can be a raw payload or a full URL scanned from an encrypted
  // QR. Only recognized fragments are extracted; ordinary URLs remain plain
  // strings so plain mode can encode URLs without surprise behavior.
  function extractPayloadFromInput(input) {
    const raw = String(input || "");
    const trimmed = raw.trim();
    if (!trimmed) {
      throw new Error(MSG_EMPTY_PAYLOAD);
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
        label: MSG_PLAIN_UNENCRYPTED
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
          label: MSG_PASSPHRASE_ENCRYPTED
        };
      }
      if (header.alg === WEBAUTHN_ALG) {
        validateWebAuthnHeader(header);
        return {
          kind: "webauthn",
          payload,
          compactJwe,
          label: MSG_WEBAUTHN_ENCRYPTED
        };
      }
      throw new Error(MSG_UNSUPPORTED_PAYLOAD);
    }
    return {
      kind: "plain",
      payload,
      label: MSG_PLAIN_UNENCRYPTED
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
    throw new Error(MSG_NO_QR_LIB);
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

  const api = {
    ENCRYPTED_PREFIX,
    PLAIN_PREFIX,
    base64UrlEncode,
    base64UrlDecode,
    utf8Encode,
    utf8Decode,
    toUint8Array,
    randomBytes,
    concatBytes,
    getCrypto,
    encodePlainPayload,
    decodePlainPayload,
    encryptPassphraseJwe,
    decryptPassphraseJwe,
    encryptWebAuthnWrappedJwe,
    decryptWebAuthnWrappedJwe,
    makeWebAuthnProtectedHeader,
    validateWebAuthnHeader,
    getCurrentRpId,
    normalizeRpId,
    extractPayloadFromInput,
    detectPayload,
    parseProtectedHeader,
    validatePassphraseHeader,
    splitCompactJwe,
    determineInitialView,
    getFragmentPayload,
    getRecoveryBaseUrl,
    shouldEncodeQrAsUrl,
    buildQrContent,
    shortChecksum,
    createQrCode,
    getQrRenderPlan
  };

  root.ERKApp = Object.assign(root.ERKApp || {}, api);

  if (typeof module !== "undefined" && module.exports) {
    module.exports = root.ERKApp;
  }
})(typeof globalThis !== "undefined" ? globalThis : window);
