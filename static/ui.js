(function initUi(root) {
  "use strict";

  const config = root.ERKConfig;
  const app = root.ERKApp;
  if (!config || !app) {
    throw new Error("UI dependencies are not loaded.");
  }

  const {
    ENCRYPTED_PREFIX,
    PLAIN_PREFIX,
    PASSWORD_ALG,
    CONTENT_ALG,
    DEFAULT_P2C,
    MAX_P2C,
    GCM_TAG_BYTES,
    MAX_ENCRYPTED_PLAINTEXT_BYTES,
    MAX_PLAIN_QR_CONTENT_BYTES,
    MAX_QR_CONTENT_BYTES,
    MAX_RECOVERY_INPUT_BYTES,
    MAX_COMPACT_JWE_CHARS,
    MAX_JWE_SEGMENT_CHARS,
    MAX_PROTECTED_HEADER_BYTES,
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
    MSG_ENCRYPTED_PLAINTEXT_TOO_LARGE,
    MSG_PLAIN_QR_TOO_LARGE,
    MSG_QR_CONTENT_TOO_LARGE,
    MSG_RECOVERY_INPUT_TOO_LARGE,
    MSG_JWE_TOO_LARGE,
    MSG_UNSUPPORTED_ENCRYPTION_OPTION,
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
    MSG_INVALID_WEBAUTHN_KEK,
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

  // Draw the library-provided module matrix onto a canvas. This is rendering
  // code only; it does not implement QR encoding or error correction.
  function drawQrToCanvas(canvas, text) {
    const plan = app.getQrRenderPlan(text);
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
  // not a cryptographic guarantee; copying still places content on the system
  // clipboard.
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
      ctx.fillText(MSG_TRUNCATED_OUTPUT, 28, height - 30);
    }
  }

  function setHidden(element, hidden) {
    element.classList.toggle("hidden", hidden);
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
    throw new Error(MSG_NO_CLIPBOARD);
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
      passkeyLabelOutput: $("passkey-label-output"),
      passkeyOutputDetails: $("passkey-output-details"),
      createMessage: $("create-message"),
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
      copyStatus: $("copy-status")
    };

    elements.originLabel.textContent = root.location && root.location.origin !== "null"
      ? root.location.origin
      : MSG_LOCAL_FILE;

    let latestPayload = "";
    let latestQrContent = "";
    let recoveredSecret = "";
    let hideTimer = 0;
    let countdownTimer = 0;
    let hideAt = 0;
    const clearCreateConfirm = { timer: 0 };
    const clearRecoverConfirm = { timer: 0 };

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

    function setCreateMessage(kind, message) {
      elements.createMessage.className = "mode-message";
      if (!message) {
        elements.createMessage.textContent = "";
        setHidden(elements.createMessage, true);
        return;
      }
      elements.createMessage.classList.add(kind);
      elements.createMessage.textContent = message;
      setHidden(elements.createMessage, false);
    }

    function showCreateError(error) {
      clearError(elements.createError);
      setCreateMessage("error", error && error.message ? error.message : String(error));
    }

    function yesNo(value) {
      return value ? MSG_YES : MSG_NO;
    }

    function updateWebAuthnStatus(prfStatus) {
      const env = app.getWebAuthnEnvironment ? app.getWebAuthnEnvironment() : {
        origin: MSG_UNAVAILABLE,
        rpId: "",
        secureContext: false,
        apiAvailable: false
      };
      elements.webauthnOriginStatus.textContent = env.origin;
      elements.webauthnRpStatus.textContent = env.rpId || MSG_UNAVAILABLE;
      elements.webauthnSecureStatus.textContent = yesNo(env.secureContext);
      elements.webauthnApiStatus.textContent = yesNo(env.apiAvailable);
      elements.passkeyLabelOutput.textContent = PASSKEY_LABEL;
      if (prfStatus) {
        elements.webauthnPrfStatus.textContent = prfStatus;
      }
    }

    function selectCreateMode(mode) {
      const input = document.querySelector("input[name='create-mode'][value='" + mode + "']");
      if (input) {
        input.checked = true;
      }
      updateModeUi();
    }

    function describePasskeyFailure(error) {
      const detail = error && error.message ? error.message : String(error);
      if (isSizeLimitMessage(detail)) {
        return detail;
      }
      if (/secure context|HTTPS|not allowed|origin|RP ID|unavailable/i.test(detail)) {
        return MSG_WEBAUTHN_SETUP_FAILED;
      }
      if (/cancelled|timed out|credential|authenticator|PRF|WebAuthn|not supported/i.test(detail)) {
        return MSG_WEBAUTHN_SETUP_CANCELLED;
      }
      return MSG_WEBAUTHN_SETUP_GENERIC;
    }

    function describePasskeyRecoveryFailure(error) {
      const detail = error && error.message ? error.message : String(error);
      if (/created for RP ID|origin|RP ID|site/i.test(detail)) {
        return MSG_WEBAUTHN_RECOVERY_DIFFERENT_SITE;
      }
      if (/cancelled|timed out|credential|authenticator|PRF|WebAuthn|not supported|unavailable/i.test(detail)) {
        return MSG_WEBAUTHN_RECOVERY_FAILED;
      }
      return MSG_WEBAUTHN_RECOVERY_GENERIC;
    }

    function describeRecoverFailure(error) {
      const detail = error && error.message ? error.message : String(error);
      const allowedMessages = [
        MSG_EMPTY_PAYLOAD,
        MSG_EMPTY_PASSPHRASE,
        MSG_WRONG_PASSPHRASE,
        MSG_RECOVERY_INPUT_TOO_LARGE,
        MSG_JWE_TOO_LARGE,
        MSG_WEBAUTHN_RECOVERY_DIFFERENT_SITE,
        MSG_WEBAUTHN_RECOVERY_FAILED,
        MSG_WEBAUTHN_RECOVERY_GENERIC
      ];
      return allowedMessages.includes(detail) ? detail : MSG_UNSUPPORTED_PAYLOAD_TYPE;
    }

    function isSizeLimitMessage(message) {
      return [
        MSG_ENCRYPTED_PLAINTEXT_TOO_LARGE,
        MSG_PLAIN_QR_TOO_LARGE,
        MSG_QR_CONTENT_TOO_LARGE,
        MSG_RECOVERY_INPUT_TOO_LARGE,
        MSG_JWE_TOO_LARGE
      ].includes(message);
    }

    function updateModeUi() {
      const mode = currentCreateMode();
      setHidden(elements.createPassphraseFields, mode !== "passphrase");
      setHidden(elements.webauthnCreateFields, mode !== "webauthn");
      if (mode === "plain") {
        setCreateMessage("warning", MSG_PLAIN_MODE_WARNING);
      } else if (mode === "webauthn") {
        setCreateMessage("notice", MSG_WEBAUTHN_MODE_NOTICE);
      } else {
        setCreateMessage("", "");
      }
    }

    function setAppView(view) {
      document.body.dataset.view = view === "recover" ? "recover" : "create";
    }

    function updateRecoverSummary() {
      clearError(elements.recoverError);
      setHidden(elements.copyStatus, true);
      const value = elements.recoverPayload.value;
      if (!value.trim()) {
        elements.recoverModeSummary.textContent = MSG_WAITING_FOR_PAYLOAD;
        setHidden(elements.recoverPassphraseField, false);
        return;
      }
      try {
        const detected = app.detectPayload(value);
        elements.recoverModeSummary.textContent = detected.label;
        setHidden(elements.recoverPassphraseField, detected.kind !== "passphrase");
      } catch (error) {
        elements.recoverModeSummary.textContent = MSG_UNSUPPORTED_PAYLOAD_TYPE;
      }
    }

    function renderOutput(payload, modeLabel, modeKind) {
      latestPayload = payload;
      latestQrContent = app.buildQrContent(payload);
      if (payload.startsWith(ENCRYPTED_PREFIX) && app.shouldEncodeQrAsUrl() && latestQrContent === payload) {
        throw new Error(MSG_HOSTED_QR_URL_REQUIRED);
      }
      elements.payloadOutput.value = payload;
      elements.qrContentOutput.value = latestQrContent;
      setHidden(elements.qrContentField, latestQrContent === payload);
      elements.codeModeLabel.textContent = modeLabel;
      elements.codeDate.textContent = new Date().toISOString().slice(0, 10);
      elements.codeChecksum.textContent = MSG_CHECKSUM_PREFIX + app.shortChecksum(latestQrContent);
      setHidden(elements.passkeyOutputDetails, modeKind !== "webauthn");
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
      setHidden(elements.copyStatus, true);
      renderSecretToCanvas(elements.protectedCanvas, text);
      setHidden(elements.protectedArea, false);
      root.clearTimeout(hideTimer);
      root.clearInterval(countdownTimer);
      hideAt = Date.now() + 60000;
      countdownTimer = root.setInterval(() => {
        const remaining = Math.max(0, Math.ceil((hideAt - Date.now()) / 1000));
        elements.hideCountdown.textContent = remaining ? MSG_HIDE_COUNTDOWN_PREFIX + remaining + MSG_HIDE_COUNTDOWN_SUFFIX : "";
      }, 250);
      hideTimer = root.setTimeout(hideSecret, 60000);
    }

    async function createPayload() {
      clearError(elements.createError);
      updateModeUi();
      hideSecret();
      let mode = currentCreateMode();
      try {
        const text = elements.secretInput.value;
        if (!text) {
          throw new Error(MSG_EMPTY_SECRET);
        }
        mode = currentCreateMode();
        if (mode === "plain") {
          renderOutput(app.encodePlainPayload(text), MSG_PLAIN_MODE_LABEL, "plain");
          return;
        }
        if (mode === "webauthn") {
          if (!elements.webauthnAck.checked) {
            throw new Error(MSG_PASSKEY_ACK_REQUIRED);
          }
          updateWebAuthnStatus(MSG_PRF_CHECKING);
          const compactJwe = await app.encryptWebAuthnJwe(text);
          renderOutput(ENCRYPTED_PREFIX + compactJwe, MSG_WEBAUTHN_MODE_LABEL, "webauthn");
          updateWebAuthnStatus(MSG_PRF_SUCCEEDED);
          return;
        }
        const passphrase = elements.createPassphrase.value;
        const confirm = elements.createPassphraseConfirm.value;
        if (passphrase !== confirm) {
          throw new Error(MSG_PASSPHRASE_MISMATCH);
        }
        const compactJwe = await app.encryptPassphraseJwe(text, passphrase);
        renderOutput(ENCRYPTED_PREFIX + compactJwe, MSG_PASSPHRASE_MODE_LABEL, "passphrase");
      } catch (error) {
        if (mode === "webauthn") {
          if (error && error.message === MSG_PASSKEY_ACK_REQUIRED) {
            showCreateError(error);
            return;
          }
          if (error && isSizeLimitMessage(error.message)) {
            showCreateError(error);
            return;
          }
          selectCreateMode("passphrase");
          updateWebAuthnStatus(MSG_PRF_FAILED);
          showCreateError(new Error(describePasskeyFailure(error)));
          return;
        }
        showCreateError(error);
      }
    }

    async function recoverPayload() {
      clearError(elements.recoverError);
      setHidden(elements.copyStatus, true);
      hideSecret();
      try {
        const detected = app.detectPayload(elements.recoverPayload.value);
        if (detected.kind === "plain") {
          startProtectedDisplay(app.decodePlainPayload(detected.payload));
          return;
        }
        if (detected.kind === "webauthn") {
          try {
            startProtectedDisplay(await app.decryptWebAuthnJwe(detected.compactJwe));
          } catch (error) {
            throw new Error(describePasskeyRecoveryFailure(error));
          }
          return;
        }
        startProtectedDisplay(await app.decryptPassphraseJwe(detected.compactJwe, elements.recoverPassphrase.value));
      } catch (error) {
        showError(elements.recoverError, new Error(describeRecoverFailure(error)));
      }
    }

    function resetClearButton(button, state) {
      root.clearInterval(state.timer);
      state.timer = 0;
      button.dataset.confirmClear = "";
      button.disabled = false;
      button.textContent = MSG_CLEAR_BUTTON;
      button.classList.add("secondary");
      button.classList.remove("danger");
    }

    function requestClearConfirmation(button, state, clearAction) {
      if (button.dataset.confirmClear === "true") {
        resetClearButton(button, state);
        clearAction();
        return;
      }
      if (button.dataset.confirmClear === "pending") {
        return;
      }
      button.dataset.confirmClear = "pending";
      button.disabled = true;
      button.classList.remove("secondary");
      button.classList.add("danger");
      state.remaining = 3;
      button.textContent = MSG_CONFIRM_BUTTON + " (" + state.remaining + ")";
      root.clearInterval(state.timer);
      state.timer = root.setInterval(() => {
        state.remaining -= 1;
        if (state.remaining > 0) {
          button.textContent = MSG_CONFIRM_BUTTON + " (" + state.remaining + ")";
          return;
        }
        root.clearInterval(state.timer);
        state.timer = 0;
        button.dataset.confirmClear = "true";
        button.disabled = false;
        button.textContent = MSG_CONFIRM_BUTTON;
      }, 1000);
    }

    function clearCreateForm() {
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
      updateModeUi();
    }

    function clearRecoverForm() {
      elements.recoverPayload.value = "";
      elements.recoverPassphrase.value = "";
      clearError(elements.recoverError);
      setHidden(elements.copyStatus, true);
      updateRecoverSummary();
      hideSecret();
    }

    document.querySelectorAll("input[name='create-mode']").forEach((input) => {
      input.addEventListener("change", updateModeUi);
    });
    elements.createButton.addEventListener("click", createPayload);
    elements.clearCreateButton.addEventListener("click", () => {
      requestClearConfirmation(elements.clearCreateButton, clearCreateConfirm, clearCreateForm);
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
      link.download = DOWNLOAD_FILENAME;
      link.href = elements.qrCanvas.toDataURL("image/png");
      link.click();
    });
    elements.printButton.addEventListener("click", () => root.print());
    elements.recoverPayload.addEventListener("input", updateRecoverSummary);
    elements.recoverButton.addEventListener("click", recoverPayload);
    elements.clearRecoverButton.addEventListener("click", () => {
      requestClearConfirmation(elements.clearRecoverButton, clearRecoverConfirm, clearRecoverForm);
    });
    elements.hideSecretButton.addEventListener("click", hideSecret);
    elements.copySecretButton.addEventListener("click", async () => {
      if (!recoveredSecret) {
        return;
      }
      try {
        await copyText(recoveredSecret);
        hideSecret();
        elements.copyStatus.textContent = MSG_COPY_SUCCESS;
        setHidden(elements.copyStatus, false);
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

    const fragmentPayload = app.getFragmentPayload();
    setAppView(app.determineInitialView(root.location));
    if (fragmentPayload) {
      elements.recoverPayload.value = fragmentPayload;
      updateRecoverSummary();
    } else {
      updateRecoverSummary();
    }
    updateWebAuthnStatus();
    updateModeUi();
  }

  const api = {
    initDom,
    drawQrToCanvas,
    renderSecretToCanvas,
    setHidden,
    copyText
  };

  root.ERKUI = api;
  Object.assign(root.ERKApp, {
    drawQrToCanvas
  });

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : window);
