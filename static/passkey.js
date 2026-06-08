(function initPasskey(root) {
  "use strict";

  const config = root.ERKConfig;
  const app = root.ERKApp;
  if (!config || !app) {
    throw new Error("Passkey dependencies are not loaded.");
  }

  const {
    ENCRYPTED_PREFIX,
    PLAIN_PREFIX,
    PASSWORD_ALG,
    DIRECT_ALG,
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
    MSG_DIRECT_NO_ENCRYPTED_KEY,
    MSG_WRONG_DIRECT_KEY,
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
    MSG_INVALID_DIRECT_KEY_SIZE,
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

  const {
    base64UrlEncode,
    base64UrlDecode,
    utf8Encode,
    toUint8Array,
    randomBytes,
    concatBytes,
    getCrypto,
    makeWebAuthnProtectedHeader,
    validateDirectHeader,
    getCurrentRpId,
    normalizeRpId,
    encryptDirectJwe,
    decryptDirectJwe,
    splitCompactJwe,
    parseProtectedHeader
  } = app;

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
      : MSG_LOCAL_FILE;
    return {
      origin,
      rpId: getCurrentRpId(locationValue),
      secureContext: Boolean(root.isSecureContext),
      apiAvailable: isWebAuthnApiAvailable()
    };
  }

  function getPasskeyStorage() {
    try {
      if (!root.localStorage) {
        return null;
      }
      const testKey = PASSKEY_CREDENTIAL_STORAGE_KEY + ".test";
      root.localStorage.setItem(testKey, "1");
      root.localStorage.removeItem(testKey);
      return root.localStorage;
    } catch (error) {
      return null;
    }
  }

  function readRememberedPasskeyCredential(rpId) {
    const storage = getPasskeyStorage();
    if (!storage) {
      return null;
    }
    try {
      const parsed = JSON.parse(storage.getItem(PASSKEY_CREDENTIAL_STORAGE_KEY) || "null");
      if (!parsed || typeof parsed !== "object") {
        return null;
      }
      if (normalizeRpId(parsed.rpId) !== normalizeRpId(rpId)) {
        return null;
      }
      const credentialIdBase64Url = String(parsed.credentialIdBase64Url || "");
      if (base64UrlDecode(credentialIdBase64Url).length === 0) {
        return null;
      }
      return {
        rpId: normalizeRpId(parsed.rpId),
        credentialIdBase64Url
      };
    } catch (error) {
      return null;
    }
  }

  function rememberPasskeyCredential(rpId, credentialIdBase64Url) {
    const storage = getPasskeyStorage();
    if (!storage) {
      throw new Error(MSG_NO_STORAGE);
    }
    base64UrlDecode(credentialIdBase64Url);
    storage.setItem(PASSKEY_CREDENTIAL_STORAGE_KEY, JSON.stringify({
      version: 1,
      rpId: normalizeRpId(rpId),
      credentialIdBase64Url
    }));
  }

  function assertWebAuthnAvailable(rpId) {
    if (!root.isSecureContext) {
      throw new Error(MSG_WEBAUTHN_SECURE_CONTEXT);
    }
    if (!isWebAuthnApiAvailable()) {
      throw new Error(MSG_WEBAUTHN_API_UNAVAILABLE);
    }
    if (!rpId) {
      throw new Error(MSG_WEBAUTHN_RP_UNAVAILABLE);
    }
  }

  function describeWebAuthnDomError(error) {
    if (!error || !error.name) {
      return error && error.message ? error.message : String(error);
    }
    if (error.name === "NotAllowedError") {
      return MSG_WEBAUTHN_REQUEST_CANCELLED;
    }
    if (error.name === "SecurityError") {
      return MSG_WEBAUTHN_ORIGIN_NOT_ALLOWED;
    }
    if (error.name === "NotSupportedError") {
      return MSG_WEBAUTHN_PRF_NOT_SUPPORTED;
    }
    if (error.name === "InvalidStateError") {
      return MSG_WEBAUTHN_AUTHENTICATOR_REJECTED;
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
      throw new Error(MSG_WEBAUTHN_INVALID_PRF_OUTPUT);
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

  function makeWebAuthnCredentialDescriptor(credentialIdBase64Url) {
    return {
      type: "public-key",
      id: base64UrlDecode(credentialIdBase64Url),
      transports: WEBAUTHN_TRANSPORTS.slice()
    };
  }

  function makeDiscoverableWebAuthnPrfRequestOptions(prfSalt, rpId) {
    return {
      publicKey: {
        challenge: randomBytes(32),
        rpId: normalizeRpId(rpId),
        userVerification: "preferred",
        timeout: WEBAUTHN_TIMEOUT_MS,
        hints: WEBAUTHN_HINTS.slice(),
        extensions: {
          prf: {
            eval: {
              first: toUint8Array(prfSalt)
            }
          }
        }
      }
    };
  }

  function makeBoundWebAuthnPrfRequestOptions(credentialIdBase64Url, prfSalt, rpId) {
    return {
      publicKey: {
        challenge: randomBytes(32),
        rpId: normalizeRpId(rpId),
        allowCredentials: [
          makeWebAuthnCredentialDescriptor(credentialIdBase64Url)
        ],
        userVerification: "preferred",
        timeout: WEBAUTHN_TIMEOUT_MS,
        hints: WEBAUTHN_HINTS.slice(),
        extensions: {
          prf: {
            evalByCredential: {
              [credentialIdBase64Url]: {
                first: toUint8Array(prfSalt)
              }
            }
          }
        }
      }
    };
  }

  function makeWebAuthnPrfCreationOptions(prfSalt, rpId) {
    return {
      publicKey: {
        challenge: randomBytes(32),
        rp: {
          id: normalizeRpId(rpId),
          name: PASSKEY_LABEL
        },
        user: {
          id: utf8Encode(PASSKEY_USER_ID),
          name: PASSKEY_LABEL,
          displayName: PASSKEY_LABEL
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 }
        ],
        authenticatorSelection: {
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "preferred"
        },
        attestation: "none",
        timeout: WEBAUTHN_TIMEOUT_MS,
        hints: WEBAUTHN_HINTS.slice(),
        extensions: {
          credProps: true,
          prf: {
            eval: {
              first: toUint8Array(prfSalt)
            }
          }
        }
      }
    };
  }

  async function createWebAuthnPrfCredential(prfSalt, rpId) {
    const normalizedRpId = normalizeRpId(rpId);
    assertWebAuthnAvailable(normalizedRpId);
    try {
      const credential = await root.navigator.credentials.create(
        makeWebAuthnPrfCreationOptions(prfSalt, normalizedRpId)
      );
      if (!credential || !credential.rawId) {
        throw new Error(MSG_WEBAUTHN_CREDENTIAL_CREATION);
      }
      return credential;
    } catch (error) {
      throw new Error(MSG_WEBAUTHN_CREDENTIAL_CREATION_FAILED + describeWebAuthnDomError(error) + ".");
    }
  }

  async function requestWebAuthnPrfOutput(credentialIdBase64Url, prfSalt, rpId) {
    const normalizedRpId = normalizeRpId(rpId);
    assertWebAuthnAvailable(normalizedRpId);
    try {
      const assertion = await root.navigator.credentials.get(
        makeBoundWebAuthnPrfRequestOptions(credentialIdBase64Url, prfSalt, normalizedRpId)
      );
      if (!assertion || !assertion.rawId) {
        throw new Error(MSG_WEBAUTHN_CREDENTIAL_REQUEST);
      }
      const returnedCredentialId = base64UrlEncode(toUint8Array(assertion.rawId));
      if (returnedCredentialId !== credentialIdBase64Url) {
        throw new Error(MSG_WEBAUTHN_DIFFERENT_CREDENTIAL);
      }
      const prfOutput = getPrfFirstResult(assertion);
      if (!prfOutput) {
        throw new Error(MSG_WEBAUTHN_NO_PRF_RESULT);
      }
      return prfOutput;
    } catch (error) {
      if (error && error.message && error.message.startsWith(MSG_WEBAUTHN_NO_PRF_RESULT)) {
        throw error;
      }
      if (error && error.message && error.message.startsWith(MSG_WEBAUTHN_DIFFERENT_CREDENTIAL)) {
        throw error;
      }
      throw new Error(MSG_WEBAUTHN_CREDENTIAL_REQUEST_FAILED + describeWebAuthnDomError(error) + ".");
    }
  }

  async function requestDiscoverableWebAuthnPrfOutput(prfSalt, rpId) {
    const normalizedRpId = normalizeRpId(rpId);
    assertWebAuthnAvailable(normalizedRpId);
    try {
      const assertion = await root.navigator.credentials.get(
        makeDiscoverableWebAuthnPrfRequestOptions(prfSalt, normalizedRpId)
      );
      if (!assertion || !assertion.rawId) {
        throw new Error(MSG_WEBAUTHN_CREDENTIAL_REQUEST);
      }
      const credentialIdBase64Url = base64UrlEncode(toUint8Array(assertion.rawId));
      const prfOutput = getPrfFirstResult(assertion);
      if (!prfOutput) {
        throw new Error(MSG_WEBAUTHN_NO_PRF_RESULT);
      }
      return {
        credentialIdBase64Url,
        prfOutput
      };
    } catch (error) {
      if (error && error.message && error.message.startsWith(MSG_WEBAUTHN_NO_PRF_RESULT)) {
        throw error;
      }
      throw new Error(MSG_EXISTING_PASSKEY_REQUEST_FAILED + describeWebAuthnDomError(error) + ".");
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
      throw new Error(MSG_INVALID_PRF_OUTPUT_SIZE);
    }
    const credentialId = toUint8Array(metadata.credentialId);
    const prfSalt = toUint8Array(metadata.prfSalt);
    if (prfSalt.length !== WEBAUTHN_PRF_SALT_BYTES) {
      throw new Error(MSG_INVALID_PRF_SALT_SIZE);
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
    const remembered = readRememberedPasskeyCredential(rpId);
    let credentialIdBase64Url;
    let prfOutput;
    try {
      const selected = await requestDiscoverableWebAuthnPrfOutput(prfSalt, rpId);
      credentialIdBase64Url = selected.credentialIdBase64Url;
      prfOutput = selected.prfOutput;
      rememberPasskeyCredential(rpId, credentialIdBase64Url);
    } catch (discoverableError) {
      if (remembered) {
        credentialIdBase64Url = remembered.credentialIdBase64Url;
        prfOutput = await requestWebAuthnPrfOutput(credentialIdBase64Url, prfSalt, rpId);
      } else {
        if (!getPasskeyStorage()) {
          throw new Error(MSG_NO_STORAGE);
        }
        const credential = await createWebAuthnPrfCredential(prfSalt, rpId);
        credentialIdBase64Url = base64UrlEncode(toUint8Array(credential.rawId));
        const prfEnabled = getPrfEnabledResult(credential);
        if (prfEnabled === false) {
          throw new Error(MSG_WEBAUTHN_PRF_DISABLED);
        }
        prfOutput = getPrfFirstResult(credential);
        if (!prfOutput) {
          prfOutput = await requestWebAuthnPrfOutput(credentialIdBase64Url, prfSalt, rpId);
        }
        rememberPasskeyCredential(rpId, credentialIdBase64Url);
      }
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
      throw new Error(MSG_WEBAUTHN_DIFFERENT_RP + metadata.rpId + MSG_WEBAUTHN_DIFFERENT_RP_PAGE + currentRpId + ".");
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
      throw new Error(MSG_WEBAUTHN_WRONG_CREDENTIAL);
    }
  }

  const api = {
    makeWebAuthnCredentialDescriptor,
    makeWebAuthnPrfCreationOptions,
    makeDiscoverableWebAuthnPrfRequestOptions,
    makeBoundWebAuthnPrfRequestOptions,
    deriveWebAuthnDirectKeyBytes,
    getWebAuthnEnvironment,
    encryptWebAuthnJwe,
    decryptWebAuthnJwe
  };

  root.ERKPasskey = api;
  Object.assign(root.ERKApp, api);

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : window);
