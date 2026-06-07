(function initRuntime(root) {
  "use strict";

  const APP_VERSION = getPackageVersion();
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
  function getPackageVersion() {
    if (root.ERK_PACKAGE && root.ERK_PACKAGE.version) {
      return root.ERK_PACKAGE.version;
    }
    if (typeof require === "function") {
      try {
        return require("../package.json").version;
      } catch (error) {
        return "0.0.0";
      }
    }
    return "0.0.0";
  }

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
    return String(text);
  }

  function decodePlainPayload(payload) {
    if (payload.startsWith(PLAIN_PREFIX)) {
      return utf8Decode(base64UrlDecode(payload.slice(PLAIN_PREFIX.length)));
    }
    return String(payload);
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

  function shortChecksum(value) {
    let hash = 0x811c9dc5;
    for (let index = 0; index < value.length; index += 1) {
      hash ^= value.charCodeAt(index);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash.toString(16).padStart(8, "0").toUpperCase();
  }

  function getQrFactory() {
    if (typeof root.qrcode === "function") {
      return root.qrcode;
    }
    if (typeof require === "function") {
      return require("qrcode-generator");
    }
    throw new Error("QR code library is not loaded.");
  }

  function createQrCode(text, errorCorrectionLevel) {
    const qr = getQrFactory()(0, errorCorrectionLevel || QR_ERROR_CORRECTION);
    qr.addData(text, "Byte");
    qr.make();
    return qr;
  }

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

  function determineInitialView(locationLike) {
    const locationValue = locationLike || root.location;
    return locationValue && locationValue.hash && locationValue.hash.length > 1 ? "recover" : "create";
  }

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

    function updateModeUi() {
      const mode = currentCreateMode();
      setHidden(elements.createPassphraseFields, mode !== "passphrase");
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
          throw new Error("WebAuthn PRF creation is scaffolded for a later phase.");
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
          throw new Error("WebAuthn PRF recovery is scaffolded for a later phase.");
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
      elements.payloadOutput.value = "";
      elements.qrContentOutput.value = "";
      latestPayload = "";
      latestQrContent = "";
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
    encryptPassphraseJwe,
    decryptPassphraseJwe,
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
