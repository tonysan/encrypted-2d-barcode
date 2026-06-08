(function initConfig(root) {
  "use strict";

  // Configs
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
  const PASSKEY_CREDENTIAL_STORAGE_KEY = "erk1.passkeyCredential.v1";
  const WEBAUTHN_TRANSPORTS = ["hybrid", "internal", "usb", "nfc", "ble"];
  const WEBAUTHN_HINTS = ["hybrid", "client-device", "security-key"];
  const PASSKEY_LABEL = "Encrypted 2D Barcode";
  const PASSKEY_USER_ID = "encrypted-2d-barcode-passkey-v1";
  const DOWNLOAD_FILENAME = "encrypted-2d-barcode.png";

  // User-facing messages
  const MSG_EMPTY_PASSPHRASE = "Enter a passphrase.";
  const MSG_WRONG_PASSPHRASE = "That passphrase did not unlock this code.";
  const MSG_EMPTY_PAYLOAD = "Paste a code or link first.";
  const MSG_NO_CLIPBOARD = "Copy is not available in this browser or page.";
  const MSG_HOSTED_QR_URL_REQUIRED = "Open this app from a web address before generating an encrypted code.";
  const MSG_EMPTY_SECRET = "Enter content first.";
  const MSG_PASSPHRASE_MISMATCH = "The passphrases do not match.";
  const MSG_PASSKEY_ACK_REQUIRED = "Confirm that the same passkey is needed to decrypt later.";
  const MSG_PLAIN_MODE_WARNING = "Generate code with no redirect or tracking. Plain mode is not encrypted. Anyone who scans the code can read it.";
  const MSG_WEBAUTHN_MODE_NOTICE = "Passkey mode can use this device, a phone, or a security key. The same passkey can protect many codes.";
  const MSG_WEBAUTHN_SETUP_FAILED = "Passkey is not available. Switched back to passphrase mode.";
  const MSG_WEBAUTHN_SETUP_CANCELLED = "Passkey was cancelled, or not supported. Switched back to passphrase mode.";
  const MSG_WEBAUTHN_SETUP_GENERIC = "Passkey did not work. Switched back to passphrase mode.";
  const MSG_WEBAUTHN_RECOVERY_DIFFERENT_SITE = "This code was made for a different site. Open it from the original site and try again.";
  const MSG_WEBAUTHN_RECOVERY_FAILED = "The passkey did not unlock this code. Use the same passkey on the original site.";
  const MSG_WEBAUTHN_RECOVERY_GENERIC = "The passkey did not unlock this code.";
  const MSG_COPY_SUCCESS = "Copied to clipboard.";
  const MSG_TRUNCATED_OUTPUT = "[Preview shortened. Use Copy if needed.]";
  const MSG_WAITING_FOR_PAYLOAD = "Waiting for code.";
  const MSG_UNSUPPORTED_PAYLOAD_TYPE = "This does not look like a supported code.";
  const MSG_PLAIN_UNENCRYPTED = "Plain text, not encrypted";
  const MSG_PASSPHRASE_ENCRYPTED = "Passphrase-protected code";
  const MSG_WEBAUTHN_ENCRYPTED = "Passkey-protected code";
  const MSG_PLAIN_MODE_LABEL = "Plain code";
  const MSG_PASSPHRASE_MODE_LABEL = "Passphrase-protected code";
  const MSG_WEBAUTHN_MODE_LABEL = "Passkey-protected code";
  const MSG_LOCAL_FILE = "local file";
  const MSG_YES = "Yes";
  const MSG_NO = "No";
  const MSG_UNAVAILABLE = "Unavailable";
  const MSG_CHECKSUM_PREFIX = "Checksum ";
  const MSG_HIDE_COUNTDOWN_PREFIX = "Hides in ";
  const MSG_HIDE_COUNTDOWN_SUFFIX = "s";
  const MSG_PRF_CHECKING = "Checking passkey";
  const MSG_PRF_SUCCEEDED = "Passkey ready for this code";
  const MSG_PRF_FAILED = "Passphrase mode selected";
  const MSG_CLEAR_BUTTON = "Clear";
  const MSG_CONFIRM_BUTTON = "Confirm";

  // Internal error messages
  const MSG_INVALID_BASE64URL = "Invalid base64url value.";
  const MSG_MALFORMED_HEADER = "Malformed JWE protected header.";
  const MSG_UNSUPPORTED_HEADER = "Unsupported JWE protected header.";
  const MSG_UNSUPPORTED_ALG = "Unsupported JWE algorithm.";
  const MSG_UNSUPPORTED_ENC = "Unsupported JWE encryption method.";
  const MSG_UNSUPPORTED_P2C = "Unsupported JWE PBES2 iteration count.";
  const MSG_UNSUPPORTED_P2C_OPTION = "Unsupported PBES2 iteration count.";
  const MSG_UNSUPPORTED_WEBAUTHN = "Unsupported WebAuthn PRF profile.";
  const MSG_MALFORMED_WEBAUTHN = "Malformed WebAuthn PRF header.";
  const MSG_MALFORMED_CREDENTIAL_ID = "Malformed WebAuthn credential ID.";
  const MSG_MALFORMED_PRF_SALT = "Malformed WebAuthn PRF salt.";
  const MSG_EXPECTED_JWE = "Expected JWE Compact Serialization.";
  const MSG_DIRECT_NO_ENCRYPTED_KEY = "Direct JWE must not contain an encrypted key.";
  const MSG_WRONG_DIRECT_KEY = "Wrong direct key or corrupted payload.";
  const MSG_INVALID_RP_ID = "Invalid WebAuthn RP ID.";
  const MSG_NO_CRYPTO = "Web Crypto is not available.";
  const MSG_EXPECTED_BINARY = "Expected binary data.";
  const MSG_NO_QR_LIB = "QR code library is not loaded.";
  const MSG_UNSUPPORTED_PAYLOAD = "Unsupported encrypted payload.";
  const MSG_NO_STORAGE = "Passkey mode needs browser storage for non-secret passkey metadata.";
  const MSG_WEBAUTHN_SECURE_CONTEXT = "WebAuthn PRF requires a browser secure context.";
  const MSG_WEBAUTHN_API_UNAVAILABLE = "WebAuthn APIs are not available in this browser.";
  const MSG_WEBAUTHN_RP_UNAVAILABLE = "WebAuthn RP ID is unavailable for this page.";
  const MSG_WEBAUTHN_CREDENTIAL_CREATION = "Browser did not return a WebAuthn credential.";
  const MSG_WEBAUTHN_CREDENTIAL_REQUEST = "Browser did not return a WebAuthn assertion.";
  const MSG_WEBAUTHN_DIFFERENT_CREDENTIAL = "Browser returned a different WebAuthn credential.";
  const MSG_WEBAUTHN_NO_PRF_RESULT = "Authenticator did not return a WebAuthn PRF result.";
  const MSG_WEBAUTHN_INVALID_PRF_OUTPUT = "Authenticator returned an invalid WebAuthn PRF result.";
  const MSG_WEBAUTHN_PRF_DISABLED = "Authenticator did not enable WebAuthn PRF for this credential.";
  const MSG_WEBAUTHN_WRONG_CREDENTIAL = "Wrong WebAuthn credential or corrupted payload.";
  const MSG_WEBAUTHN_DIFFERENT_RP = "This WebAuthn code was created for RP ID ";
  const MSG_WEBAUTHN_DIFFERENT_RP_PAGE = ", but this page is ";
  const MSG_INVALID_DIRECT_KEY_SIZE = "Direct JWE key must be 256 bits.";
  const MSG_INVALID_IV_SIZE = "AES-GCM IV must be 96 bits.";
  const MSG_INVALID_PRF_OUTPUT_SIZE = "WebAuthn PRF output must be 256 bits.";
  const MSG_INVALID_PRF_SALT_SIZE = "WebAuthn PRF salt must be 256 bits.";
  const MSG_WEBAUTHN_CREDENTIAL_CREATION_FAILED = "WebAuthn credential creation failed: ";
  const MSG_WEBAUTHN_CREDENTIAL_REQUEST_FAILED = "WebAuthn credential request failed: ";
  const MSG_EXISTING_PASSKEY_REQUEST_FAILED = "Existing passkey request failed: ";
  const MSG_WEBAUTHN_REQUEST_CANCELLED = "request was cancelled, timed out, or the credential is unavailable";
  const MSG_WEBAUTHN_ORIGIN_NOT_ALLOWED = "this origin or RP ID is not allowed";
  const MSG_WEBAUTHN_PRF_NOT_SUPPORTED = "the requested WebAuthn PRF extension is not supported";
  const MSG_WEBAUTHN_AUTHENTICATOR_REJECTED = "the authenticator rejected this credential request";

  const config = {
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
  };

  root.ERKConfig = config;

  function initDomWhenReady() {
    if (!root.ERKUI || typeof root.ERKUI.initDom !== "function") {
      throw new Error("UI module is not loaded.");
    }
    root.ERKUI.initDom();
  }

  if (typeof module !== "undefined" && module.exports) {
    require("./app.js");
    require("./passkey.js");
    require("./ui.js");
    module.exports = root.ERKApp;
  }

  if (typeof document !== "undefined") {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", initDomWhenReady);
    } else {
      initDomWhenReady();
    }
  }
})(typeof globalThis !== "undefined" ? globalThis : window);
