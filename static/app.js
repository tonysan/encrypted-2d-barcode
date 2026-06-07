(function initRuntime(root) {
  "use strict";

  const APP_VERSION = "0.1.0-dev";
  const ENCRYPTED_PREFIX = "ERK1.";
  const PLAIN_PREFIX = "ERP1.";
  const PASSWORD_ALG = "PBES2-HS512+A256KW";
  const DIRECT_ALG = "dir";
  const CONTENT_ALG = "A256GCM";
  const DEFAULT_P2C = 210000;
  const MAX_P2C = 5000000;
  const GCM_TAG_BYTES = 16;
  const QR_ECL = "M";
  const COMMON_PASSWORDS = new Set([
    "password",
    "password1",
    "password123",
    "1234567890123456",
    "qwertyqwertyqwerty",
    "letmeinletmein",
    "correcthorsebatterystaple"
  ]);

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

  function base64UrlEncode(bytes) {
    return bytesToBase64(bytes)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
  }

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

  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    getCrypto().getRandomValues(bytes);
    return bytes;
  }

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

  function encodePlainPayload(text) {
    return PLAIN_PREFIX + base64UrlEncode(utf8Encode(text));
  }

  function decodePlainPayload(payload) {
    if (!payload.startsWith(PLAIN_PREFIX)) {
      throw new Error("Not a plain payload.");
    }
    return utf8Decode(base64UrlDecode(payload.slice(PLAIN_PREFIX.length)));
  }

  function validatePassphraseForCreation(passphrase) {
    const value = String(passphrase || "");
    if (value.length < 16) {
      return "Use at least 16 characters.";
    }
    if (/^\d+$/.test(value)) {
      return "Use more than digits only.";
    }
    if (/^(.)\1+$/.test(value)) {
      return "Avoid repeated single-character passphrases.";
    }
    for (let size = 2; size <= 8; size += 1) {
      if (value.length % size === 0) {
        const part = value.slice(0, size);
        if (part.repeat(value.length / size) === value) {
          return "Avoid obvious repeated patterns.";
        }
      }
    }
    if (COMMON_PASSWORDS.has(value.trim().toLowerCase())) {
      return "Use a less common passphrase.";
    }
    return "";
  }

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

  function makeProtectedHeader(p2s, p2c) {
    return {
      alg: PASSWORD_ALG,
      enc: CONTENT_ALG,
      p2c,
      p2s: base64UrlEncode(p2s),
      typ: "ERK1"
    };
  }

  function stringifyHeader(header) {
    return JSON.stringify(header);
  }

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

  function validatePassphraseHeader(header) {
    const allowed = new Set(["alg", "enc", "p2c", "p2s", "typ"]);
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
    if (header.typ !== "ERK1") {
      throw new Error("Unsupported JWE type.");
    }
    if (!Number.isInteger(header.p2c) || header.p2c < 1000 || header.p2c > MAX_P2C) {
      throw new Error("Unsupported JWE PBES2 iteration count.");
    }
    base64UrlDecode(header.p2s);
  }

  function validateDirectHeader(header) {
    const allowed = new Set(["alg", "enc", "typ"]);
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
    if (header.typ !== "ERK1") {
      throw new Error("Unsupported JWE type.");
    }
  }

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

  async function encryptPassphraseJwe(plaintext, passphrase, options) {
    const crypto = getCrypto();
    const p2c = options && options.p2c ? options.p2c : DEFAULT_P2C;
    if (!Number.isInteger(p2c) || p2c < 1000 || p2c > MAX_P2C) {
      throw new Error("Unsupported PBES2 iteration count.");
    }
    const p2s = randomBytes(16);
    const iv = randomBytes(12);
    const cekBytes = randomBytes(32);
    const cekForEncrypt = await crypto.subtle.importKey(
      "raw",
      cekBytes,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt"]
    );
    const kek = await derivePbes2Key(passphrase, p2s, p2c);
    const header = makeProtectedHeader(p2s, p2c);
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

  async function decryptPassphraseJwe(compactJwe, passphrase) {
    const crypto = getCrypto();
    const parts = splitCompactJwe(compactJwe);
    const header = parseProtectedHeader(parts.protectedSegment);
    validatePassphraseHeader(header);
    const salt = base64UrlDecode(header.p2s);
    const kek = await derivePbes2Key(passphrase, salt, header.p2c);
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

  function detectPayload(input) {
    const payload = String(input || "").trim();
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
    throw new Error("Unsupported payload marker.");
  }

  function shortChecksum(value) {
    let hash = 0x811c9dc5;
    for (let index = 0; index < value.length; index += 1) {
      hash ^= value.charCodeAt(index);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash.toString(16).padStart(8, "0").toUpperCase();
  }

  const ECL_DATA = {
    L: {
      format: 1,
      ecc: [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
      blocks: [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25]
    },
    M: {
      format: 0,
      ecc: [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
      blocks: [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49]
    },
    Q: {
      format: 3,
      ecc: [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
      blocks: [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68]
    },
    H: {
      format: 2,
      ecc: [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
      blocks: [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81]
    }
  };

  function getNumRawDataModules(version) {
    let result = (16 * version + 128) * version + 64;
    if (version >= 2) {
      const numAlign = Math.floor(version / 7) + 2;
      result -= (25 * numAlign - 10) * numAlign - 55;
      if (version >= 7) {
        result -= 36;
      }
    }
    return result;
  }

  function getNumDataCodewords(version, ecl) {
    const data = ECL_DATA[ecl];
    return Math.floor(getNumRawDataModules(version) / 8) - data.ecc[version] * data.blocks[version];
  }

  class BitBuffer {
    constructor() {
      this.bits = [];
    }

    appendBits(value, length) {
      if (length < 0 || length > 31 || value >>> length !== 0) {
        throw new Error("Invalid bit buffer append.");
      }
      for (let i = length - 1; i >= 0; i -= 1) {
        this.bits.push((value >>> i) & 1);
      }
    }

    get length() {
      return this.bits.length;
    }

    toBytes() {
      const bytes = new Uint8Array(Math.ceil(this.bits.length / 8));
      for (let index = 0; index < this.bits.length; index += 1) {
        bytes[index >>> 3] |= this.bits[index] << (7 - (index & 7));
      }
      return bytes;
    }
  }

  function chooseQrVersion(dataLength, ecl) {
    for (let version = 1; version <= 40; version += 1) {
      const countBits = version <= 9 ? 8 : 16;
      const neededBits = 4 + countBits + dataLength * 8;
      if (neededBits <= getNumDataCodewords(version, ecl) * 8) {
        return version;
      }
    }
    throw new Error("Payload is too large for one QR code. Multi-chunk codes are deferred.");
  }

  function makeDataCodewords(dataBytes, version, ecl) {
    const capacity = getNumDataCodewords(version, ecl);
    const buffer = new BitBuffer();
    buffer.appendBits(0x4, 4);
    buffer.appendBits(dataBytes.length, version <= 9 ? 8 : 16);
    for (const byte of dataBytes) {
      buffer.appendBits(byte, 8);
    }
    const capacityBits = capacity * 8;
    buffer.appendBits(0, Math.min(4, capacityBits - buffer.length));
    while (buffer.length % 8 !== 0) {
      buffer.appendBits(0, 1);
    }
    const bytes = Array.from(buffer.toBytes());
    for (let pad = 0xec; bytes.length < capacity; pad ^= 0xec ^ 0x11) {
      bytes.push(pad);
    }
    return bytes;
  }

  function gfMultiply(x, y) {
    let result = 0;
    for (let index = 0; index < 8; index += 1) {
      result ^= (y & 1) ? x : 0;
      const carry = x & 0x80;
      x = (x << 1) & 0xff;
      if (carry) {
        x ^= 0x1d;
      }
      y >>>= 1;
    }
    return result;
  }

  function reedSolomonDivisor(degree) {
    const result = new Uint8Array(degree);
    result[degree - 1] = 1;
    let root = 1;
    for (let i = 0; i < degree; i += 1) {
      for (let j = 0; j < degree; j += 1) {
        result[j] = gfMultiply(result[j], root);
        if (j + 1 < degree) {
          result[j] ^= result[j + 1];
        }
      }
      root = gfMultiply(root, 2);
    }
    return result;
  }

  function reedSolomonRemainder(data, divisor) {
    const result = new Uint8Array(divisor.length);
    for (const byte of data) {
      const factor = byte ^ result[0];
      result.copyWithin(0, 1);
      result[result.length - 1] = 0;
      for (let index = 0; index < result.length; index += 1) {
        result[index] ^= gfMultiply(divisor[index], factor);
      }
    }
    return Array.from(result);
  }

  function addEccAndInterleave(dataCodewords, version, ecl) {
    const eclInfo = ECL_DATA[ecl];
    const numBlocks = eclInfo.blocks[version];
    const blockEccLen = eclInfo.ecc[version];
    const rawCodewords = Math.floor(getNumRawDataModules(version) / 8);
    const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
    const shortBlockLen = Math.floor(rawCodewords / numBlocks);
    const divisor = reedSolomonDivisor(blockEccLen);
    const blocks = [];
    let offset = 0;
    for (let blockIndex = 0; blockIndex < numBlocks; blockIndex += 1) {
      const datLen = shortBlockLen - blockEccLen + (blockIndex < numShortBlocks ? 0 : 1);
      const dat = dataCodewords.slice(offset, offset + datLen);
      offset += datLen;
      const ecc = reedSolomonRemainder(dat, divisor);
      if (blockIndex < numShortBlocks) {
        dat.push(0);
      }
      blocks.push(dat.concat(ecc));
    }
    const result = [];
    for (let byteIndex = 0; byteIndex < blocks[0].length; byteIndex += 1) {
      for (let blockIndex = 0; blockIndex < blocks.length; blockIndex += 1) {
        if (byteIndex !== shortBlockLen - blockEccLen || blockIndex >= numShortBlocks) {
          result.push(blocks[blockIndex][byteIndex]);
        }
      }
    }
    return result;
  }

  function getAlignmentPatternPositions(version) {
    if (version === 1) {
      return [];
    }
    const size = version * 4 + 17;
    const numAlign = Math.floor(version / 7) + 2;
    const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (numAlign * 2 - 2)) * 2;
    const result = [6];
    for (let position = size - 7; result.length < numAlign; position -= step) {
      result.splice(1, 0, position);
    }
    return result;
  }

  function makeMatrix(size) {
    const modules = [];
    const functions = [];
    for (let y = 0; y < size; y += 1) {
      modules.push(new Array(size).fill(false));
      functions.push(new Array(size).fill(false));
    }
    return { modules, functions };
  }

  function setFunctionModule(state, x, y, dark) {
    if (x < 0 || y < 0 || y >= state.modules.length || x >= state.modules.length) {
      return;
    }
    state.modules[y][x] = dark;
    state.functions[y][x] = true;
  }

  function drawFinderPattern(state, centerX, centerY) {
    for (let dy = -4; dy <= 4; dy += 1) {
      for (let dx = -4; dx <= 4; dx += 1) {
        const x = centerX + dx;
        const y = centerY + dy;
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        const dark = dist !== 2 && dist !== 4;
        setFunctionModule(state, x, y, dark);
      }
    }
  }

  function drawAlignmentPattern(state, centerX, centerY) {
    for (let dy = -2; dy <= 2; dy += 1) {
      for (let dx = -2; dx <= 2; dx += 1) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy));
        setFunctionModule(state, centerX + dx, centerY + dy, dist !== 1);
      }
    }
  }

  function drawFunctionPatterns(state, version) {
    const size = state.modules.length;
    drawFinderPattern(state, 3, 3);
    drawFinderPattern(state, size - 4, 3);
    drawFinderPattern(state, 3, size - 4);
    for (let index = 0; index < size; index += 1) {
      if (!state.functions[index][6]) {
        setFunctionModule(state, 6, index, index % 2 === 0);
      }
      if (!state.functions[6][index]) {
        setFunctionModule(state, index, 6, index % 2 === 0);
      }
    }
    const positions = getAlignmentPatternPositions(version);
    for (const y of positions) {
      for (const x of positions) {
        if (!state.functions[y][x]) {
          drawAlignmentPattern(state, x, y);
        }
      }
    }
    drawFormatBits(state, "M", 0);
    if (version >= 7) {
      drawVersionBits(state, version);
    }
  }

  function drawVersionBits(state, version) {
    const size = state.modules.length;
    let remainder = version;
    for (let i = 0; i < 12; i += 1) {
      remainder = (remainder << 1) ^ (((remainder >>> 11) & 1) * 0x1f25);
    }
    const bits = (version << 12) | remainder;
    for (let i = 0; i < 18; i += 1) {
      const bit = ((bits >>> i) & 1) !== 0;
      const a = size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      setFunctionModule(state, a, b, bit);
      setFunctionModule(state, b, a, bit);
    }
  }

  function drawFormatBits(state, ecl, mask) {
    const size = state.modules.length;
    const data = (ECL_DATA[ecl].format << 3) | mask;
    let remainder = data;
    for (let i = 0; i < 10; i += 1) {
      remainder = (remainder << 1) ^ (((remainder >>> 9) & 1) * 0x537);
    }
    const bits = ((data << 10) | remainder) ^ 0x5412;
    for (let i = 0; i <= 5; i += 1) {
      setFunctionModule(state, 8, i, ((bits >>> i) & 1) !== 0);
    }
    setFunctionModule(state, 8, 7, ((bits >>> 6) & 1) !== 0);
    setFunctionModule(state, 8, 8, ((bits >>> 7) & 1) !== 0);
    setFunctionModule(state, 7, 8, ((bits >>> 8) & 1) !== 0);
    for (let i = 9; i < 15; i += 1) {
      setFunctionModule(state, 14 - i, 8, ((bits >>> i) & 1) !== 0);
    }
    for (let i = 0; i < 8; i += 1) {
      setFunctionModule(state, size - 1 - i, 8, ((bits >>> i) & 1) !== 0);
    }
    for (let i = 8; i < 15; i += 1) {
      setFunctionModule(state, 8, size - 15 + i, ((bits >>> i) & 1) !== 0);
    }
    setFunctionModule(state, 8, size - 8, true);
  }

  function drawCodewords(state, data) {
    const size = state.modules.length;
    let bitIndex = 0;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) {
        right -= 1;
      }
      for (let vert = 0; vert < size; vert += 1) {
        for (let j = 0; j < 2; j += 1) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? size - 1 - vert : vert;
          if (!state.functions[y][x] && bitIndex < data.length * 8) {
            state.modules[y][x] = ((data[bitIndex >>> 3] >>> (7 - (bitIndex & 7))) & 1) !== 0;
            bitIndex += 1;
          }
        }
      }
    }
  }

  function maskBit(mask, x, y) {
    switch (mask) {
      case 0: return (x + y) % 2 === 0;
      case 1: return y % 2 === 0;
      case 2: return x % 3 === 0;
      case 3: return (x + y) % 3 === 0;
      case 4: return (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0;
      case 5: return ((x * y) % 2) + ((x * y) % 3) === 0;
      case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
      case 7: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
      default: throw new Error("Invalid QR mask.");
    }
  }

  function cloneQrState(state) {
    return {
      modules: state.modules.map((row) => row.slice()),
      functions: state.functions.map((row) => row.slice())
    };
  }

  function applyMask(state, mask) {
    const size = state.modules.length;
    for (let y = 0; y < size; y += 1) {
      for (let x = 0; x < size; x += 1) {
        if (!state.functions[y][x] && maskBit(mask, x, y)) {
          state.modules[y][x] = !state.modules[y][x];
        }
      }
    }
  }

  function getPenaltyScore(modules) {
    const size = modules.length;
    let result = 0;
    for (let y = 0; y < size; y += 1) {
      let color = modules[y][0];
      let run = 1;
      for (let x = 1; x < size; x += 1) {
        if (modules[y][x] === color) {
          run += 1;
        } else {
          if (run >= 5) {
            result += run - 2;
          }
          color = modules[y][x];
          run = 1;
        }
      }
      if (run >= 5) {
        result += run - 2;
      }
    }
    for (let x = 0; x < size; x += 1) {
      let color = modules[0][x];
      let run = 1;
      for (let y = 1; y < size; y += 1) {
        if (modules[y][x] === color) {
          run += 1;
        } else {
          if (run >= 5) {
            result += run - 2;
          }
          color = modules[y][x];
          run = 1;
        }
      }
      if (run >= 5) {
        result += run - 2;
      }
    }
    for (let y = 0; y < size - 1; y += 1) {
      for (let x = 0; x < size - 1; x += 1) {
        const color = modules[y][x];
        if (color === modules[y][x + 1] && color === modules[y + 1][x] && color === modules[y + 1][x + 1]) {
          result += 3;
        }
      }
    }
    const patternA = [true, false, true, true, true, false, true, false, false, false, false];
    const patternB = [false, false, false, false, true, false, true, true, true, false, true];
    function matches(line, index, pattern) {
      for (let i = 0; i < pattern.length; i += 1) {
        if (line[index + i] !== pattern[i]) {
          return false;
        }
      }
      return true;
    }
    for (let y = 0; y < size; y += 1) {
      for (let x = 0; x <= size - 11; x += 1) {
        if (matches(modules[y], x, patternA) || matches(modules[y], x, patternB)) {
          result += 40;
        }
      }
    }
    for (let x = 0; x < size; x += 1) {
      const column = modules.map((row) => row[x]);
      for (let y = 0; y <= size - 11; y += 1) {
        if (matches(column, y, patternA) || matches(column, y, patternB)) {
          result += 40;
        }
      }
    }
    let dark = 0;
    for (const row of modules) {
      for (const value of row) {
        if (value) {
          dark += 1;
        }
      }
    }
    const percent = (dark * 100) / (size * size);
    result += Math.floor(Math.abs(percent - 50) / 5) * 10;
    return result;
  }

  function makeQrMatrix(text, ecl) {
    const dataBytes = utf8Encode(text);
    const level = ecl || QR_ECL;
    const version = chooseQrVersion(dataBytes.length, level);
    const dataCodewords = makeDataCodewords(dataBytes, version, level);
    const allCodewords = addEccAndInterleave(dataCodewords, version, level);
    const size = version * 4 + 17;
    const base = makeMatrix(size);
    drawFunctionPatterns(base, version);
    drawCodewords(base, allCodewords);
    let best = null;
    let bestScore = Infinity;
    for (let mask = 0; mask < 8; mask += 1) {
      const candidate = cloneQrState(base);
      applyMask(candidate, mask);
      drawFormatBits(candidate, level, mask);
      const score = getPenaltyScore(candidate.modules);
      if (score < bestScore) {
        best = candidate.modules;
        bestScore = score;
      }
    }
    return {
      version,
      size,
      modules: best
    };
  }

  function drawQrToCanvas(canvas, text) {
    const qr = makeQrMatrix(text, QR_ECL);
    const quiet = 4;
    const scale = Math.floor(canvas.width / (qr.size + quiet * 2));
    if (scale < 1) {
      throw new Error("Canvas is too small for QR rendering.");
    }
    const drawSize = (qr.size + quiet * 2) * scale;
    const offset = Math.floor((canvas.width - drawSize) / 2);
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#000000";
    for (let y = 0; y < qr.size; y += 1) {
      for (let x = 0; x < qr.size; x += 1) {
        if (qr.modules[y][x]) {
          ctx.fillRect(offset + (x + quiet) * scale, offset + (y + quiet) * scale, scale, scale);
        }
      }
    }
    return qr;
  }

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

  function buildFragmentUrl(payload) {
    return root.location.href.split("#")[0] + "#" + encodeURIComponent(payload);
  }

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

  function canUseBarcodeDetector() {
    return typeof root.BarcodeDetector === "function";
  }

  async function detectBarcodeFromSource(source) {
    if (!canUseBarcodeDetector()) {
      throw new Error("Native barcode scanning is not available in this browser. Paste the payload manually.");
    }
    const detector = new root.BarcodeDetector({ formats: ["qr_code"] });
    const codes = await detector.detect(source);
    if (!codes.length) {
      throw new Error("No QR code found.");
    }
    return codes[0].rawValue;
  }

  function initDom() {
    const $ = (id) => document.getElementById(id);
    const elements = {
      appVersion: $("app-version"),
      originLabel: $("origin-label"),
      secretInput: $("secret-input"),
      createPassphrase: $("create-passphrase"),
      createPassphraseConfirm: $("create-passphrase-confirm"),
      createPassphraseFields: $("passphrase-create-fields"),
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
      payloadFallback: $("payload-fallback"),
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
      fragmentBanner: $("fragment-banner"),
      clearFragmentButton: $("clear-fragment-button"),
      startScanButton: $("start-scan-button"),
      stopScanButton: $("stop-scan-button"),
      scanVideo: $("scan-video"),
      imageScanInput: $("image-scan-input"),
      scanStatus: $("scan-status")
    };

    elements.appVersion.textContent = "v" + APP_VERSION;
    elements.originLabel.textContent = root.location && root.location.origin !== "null"
      ? root.location.origin
      : "local file";

    let latestPayload = "";
    let recoveredSecret = "";
    let hideTimer = 0;
    let countdownTimer = 0;
    let hideAt = 0;
    let scanStream = null;
    let scanLoopActive = false;

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

    function updateModeUi() {
      const mode = currentCreateMode();
      setHidden(elements.createPassphraseFields, mode !== "passphrase");
      setHidden(elements.plainWarning, mode !== "plain");
    }

    function updateRecoverSummary() {
      clearError(elements.recoverError);
      const value = elements.recoverPayload.value.trim();
      if (!value) {
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
      elements.payloadOutput.value = payload;
      elements.payloadFallback.textContent = payload;
      elements.codeModeLabel.textContent = modeLabel;
      elements.codeDate.textContent = new Date().toISOString().slice(0, 10);
      elements.codeChecksum.textContent = "Checksum " + shortChecksum(payload);
      drawQrToCanvas(elements.qrCanvas, payload);
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
          throw new Error("WebAuthn PRF creation is scaffolded for a later phase.");
        }
        const passphrase = elements.createPassphrase.value;
        const confirm = elements.createPassphraseConfirm.value;
        const passphraseError = validatePassphraseForCreation(passphrase);
        if (passphraseError) {
          throw new Error(passphraseError);
        }
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
          throw new Error("WebAuthn PRF recovery is scaffolded for a later phase.");
        }
        const passphrase = elements.recoverPassphrase.value;
        if (!passphrase) {
          throw new Error("Enter the passphrase.");
        }
        startProtectedDisplay(await decryptPassphraseJwe(detected.compactJwe, passphrase));
      } catch (error) {
        showError(elements.recoverError, error);
      }
    }

    async function startCameraScan() {
      clearError(elements.recoverError);
      elements.scanStatus.textContent = "";
      try {
        if (!canUseBarcodeDetector()) {
          throw new Error("Native barcode scanning is not available in this browser. Paste the payload manually.");
        }
        if (!root.navigator || !root.navigator.mediaDevices || !root.navigator.mediaDevices.getUserMedia) {
          throw new Error("Camera access is not available in this browser context.");
        }
        scanStream = await root.navigator.mediaDevices.getUserMedia({
          video: { facingMode: "environment" },
          audio: false
        });
        elements.scanVideo.srcObject = scanStream;
        await elements.scanVideo.play();
        setHidden(elements.scanVideo, false);
        elements.startScanButton.disabled = true;
        elements.stopScanButton.disabled = false;
        scanLoopActive = true;
        const detector = new root.BarcodeDetector({ formats: ["qr_code"] });
        const loop = async () => {
          if (!scanLoopActive) {
            return;
          }
          try {
            const codes = await detector.detect(elements.scanVideo);
            if (codes.length) {
              elements.recoverPayload.value = codes[0].rawValue;
              updateRecoverSummary();
              stopCameraScan();
              elements.scanStatus.textContent = "QR code scanned.";
              return;
            }
          } catch (error) {
            elements.scanStatus.textContent = error.message;
          }
          root.requestAnimationFrame(loop);
        };
        loop();
      } catch (error) {
        showError(elements.recoverError, error);
      }
    }

    function stopCameraScan() {
      scanLoopActive = false;
      if (scanStream) {
        for (const track of scanStream.getTracks()) {
          track.stop();
        }
      }
      scanStream = null;
      elements.scanVideo.srcObject = null;
      setHidden(elements.scanVideo, true);
      elements.startScanButton.disabled = false;
      elements.stopScanButton.disabled = true;
    }

    async function scanImageFile(file) {
      clearError(elements.recoverError);
      elements.scanStatus.textContent = "";
      try {
        if (!file) {
          return;
        }
        let source;
        if (root.createImageBitmap) {
          source = await root.createImageBitmap(file);
        } else {
          source = await new Promise((resolve, reject) => {
            const img = new Image();
            img.onload = () => resolve(img);
            img.onerror = reject;
            img.src = URL.createObjectURL(file);
          });
        }
        const value = await detectBarcodeFromSource(source);
        elements.recoverPayload.value = value;
        updateRecoverSummary();
        elements.scanStatus.textContent = "QR code scanned from image.";
      } catch (error) {
        showError(elements.recoverError, error);
      } finally {
        elements.imageScanInput.value = "";
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
      elements.payloadOutput.value = "";
      latestPayload = "";
      setHidden(elements.outputArea, true);
      clearError(elements.createError);
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
        await copyText(buildFragmentUrl(latestPayload), elements.payloadOutput);
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
    elements.startScanButton.addEventListener("click", startCameraScan);
    elements.stopScanButton.addEventListener("click", stopCameraScan);
    elements.imageScanInput.addEventListener("change", () => scanImageFile(elements.imageScanInput.files[0]));
    elements.clearFragmentButton.addEventListener("click", () => {
      if (root.history && root.location) {
        root.history.replaceState(null, "", root.location.href.split("#")[0]);
      }
      setHidden(elements.fragmentBanner, true);
    });
    root.addEventListener("blur", hideSecret);
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        hideSecret();
      }
    });

    const fragmentPayload = getFragmentPayload();
    if (fragmentPayload) {
      elements.recoverPayload.value = fragmentPayload;
      updateRecoverSummary();
      setHidden(elements.fragmentBanner, false);
    } else {
      updateRecoverSummary();
    }
    updateModeUi();
  }

  const api = {
    APP_VERSION,
    ENCRYPTED_PREFIX,
    PLAIN_PREFIX,
    base64UrlEncode,
    base64UrlDecode,
    utf8Encode,
    utf8Decode,
    encodePlainPayload,
    decodePlainPayload,
    validatePassphraseForCreation,
    encryptPassphraseJwe,
    decryptPassphraseJwe,
    detectPayload,
    parseProtectedHeader,
    validatePassphraseHeader,
    splitCompactJwe,
    shortChecksum,
    makeQrMatrix
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
