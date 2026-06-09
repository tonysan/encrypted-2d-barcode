const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const app = require("../static/init.js");

const rootDir = path.resolve(__dirname, "..");

async function rejectsWith(fn, pattern) {
  let rejected = false;
  try {
    await fn();
  } catch (error) {
    rejected = true;
    assert.match(error.message, pattern);
  }
  assert.equal(rejected, true, "Expected rejection");
}

function readRootFile(fileName) {
  return fs.readFileSync(path.join(rootDir, fileName), "utf8");
}

async function testMarkdownInventory() {
  for (const fileName of ["README.md", "SECURITY.md", "AGENT.md", "LICENSE"]) {
    assert.equal(fs.existsSync(path.join(rootDir, fileName)), true, `${fileName} should exist`);
  }
  for (const fileName of ["SELF_HOSTING.md", "THREAT_MODEL.md", "IMPLEMENTATION_PLAN.md"]) {
    assert.equal(fs.existsSync(path.join(rootDir, fileName)), false, `${fileName} should stay merged`);
  }

  const readme = readRootFile("README.md");
  const readmeSections = readme
    .split(/\r?\n/)
    .filter((line) => line.startsWith("## "))
    .map((line) => line.slice(3));
  assert.deepEqual(readmeSections, [
    "TLDR",
    "Quick How To Use",
    "How To Self Host",
    "Full Tech Details"
  ]);
  assert.match(readme, /not trying to become the canonical hosted QR service/);
  assert.match(readRootFile("SECURITY.md"), /README\.md/);
  assert.match(readRootFile("AGENT.md"), /Phase 2 preserved the current passkey credential-selection behavior/);
}

async function testBase64Url() {
  const input = app.utf8Encode("hello world + / =");
  const encoded = app.base64UrlEncode(input);
  assert.equal(encoded.includes("+"), false);
  assert.equal(encoded.includes("/"), false);
  assert.equal(encoded.includes("="), false);
  assert.equal(app.utf8Decode(app.base64UrlDecode(encoded)), "hello world + / =");
}

async function testPlainPayload() {
  const payload = app.encodePlainPayload("line one\nline two");
  assert.equal(payload, "line one\nline two");
  assert.equal(app.decodePlainPayload(payload), "line one\nline two");
  assert.equal(app.detectPayload(payload).kind, "plain");
}

async function testLegacyPlainPayload() {
  const payload = app.PLAIN_PREFIX + app.base64UrlEncode(app.utf8Encode("legacy plain"));
  assert.equal(app.decodePlainPayload(payload), "legacy plain");
  assert.equal(app.detectPayload(payload).kind, "plain");
}

async function testUrlPayloadExtraction() {
  const payload = app.PLAIN_PREFIX + app.base64UrlEncode(app.utf8Encode("from url"));
  const url = `https://codes.example/recover/#${encodeURIComponent(payload)}`;
  assert.equal(app.extractPayloadFromInput(url), payload);
  assert.equal(app.detectPayload(url).kind, "plain");
}

async function testRawUrlCanBePlainPayload() {
  const payload = "https://example.com/raw/plain/string";
  assert.equal(app.extractPayloadFromInput(payload), payload);
  assert.equal(app.decodePlainPayload(app.detectPayload(payload).payload), payload);
}

async function testPlainQrContentUsesPayloadOnly() {
  const payload = app.encodePlainPayload("hosted qr");
  const qrContent = app.buildQrContent(payload, {
    protocol: "https:",
    origin: "https://codes.example",
    href: "https://codes.example/app/index.html?ignored=true#old"
  });
  assert.equal(qrContent, payload);
}

async function testQrContentUsesDeployedDomainUrl() {
  const payload = app.ENCRYPTED_PREFIX + "sample";
  const qrContent = app.buildQrContent(payload, {
    href: "https://encrypt.tonysan.fun/"
  });
  assert.equal(qrContent, `https://encrypt.tonysan.fun/#${encodeURIComponent(payload)}`);
}

async function testQrContentUsesLocalHttpUrl() {
  const payload = app.ENCRYPTED_PREFIX + "sample";
  const qrContent = app.buildQrContent(payload, {
    href: "http://127.0.0.1:8788/"
  });
  assert.equal(qrContent, `http://127.0.0.1:8788/#${encodeURIComponent(payload)}`);
}

async function testQrContentUsesHostedUrlWithoutOriginProperty() {
  const payload = app.ENCRYPTED_PREFIX + "sample";
  const qrContent = app.buildQrContent(payload, {
    href: "https://codes.example/app/#old"
  });
  assert.equal(qrContent, `https://codes.example/app/#${encodeURIComponent(payload)}`);
}

async function testQrContentUsesPayloadForLocalFile() {
  const payload = app.encodePlainPayload("local qr");
  const qrContent = app.buildQrContent(payload, {
    protocol: "file:",
    origin: "null",
    href: "file:///C:/app/index.html"
  });
  assert.equal(qrContent, payload);
}

async function testInitialViewFromFragment() {
  assert.equal(app.determineInitialView({ hash: "" }), "create");
  assert.equal(app.determineInitialView({ hash: "#ERK1.payload" }), "recover");
  assert.equal(app.determineInitialView({ hash: "#anything" }), "recover");
}

async function testPassphraseJweRoundtrip() {
  const compact = await app.encryptPassphraseJwe("secret string", "this is a long passphrase", { p2c: 1500 });
  assert.equal(compact.split(".").length, 5);
  assert.equal(Object.hasOwn(app.parseProtectedHeader(compact.split(".")[0]), "typ"), false);
  const detected = app.detectPayload(app.ENCRYPTED_PREFIX + compact);
  assert.equal(detected.kind, "passphrase");
  assert.equal(await app.decryptPassphraseJwe(compact, "this is a long passphrase"), "secret string");

  const shortPassphraseCompact = await app.encryptPassphraseJwe("short passphrase secret", "x", { p2c: 1500 });
  assert.equal(await app.decryptPassphraseJwe(shortPassphraseCompact, "x"), "short passphrase secret");
}

function fixedWebAuthnHeader() {
  const credentialId = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  const prfSalt = new Uint8Array(32);
  for (let index = 0; index < prfSalt.length; index += 1) {
    prfSalt[index] = index;
  }
  return app.makeWebAuthnProtectedHeader(credentialId, "encrypt.tonysan.fun", prfSalt);
}

function zeroKey() {
  return new Uint8Array(32);
}

function oversizedAscii(limit) {
  return "a".repeat(limit + 1);
}

async function testWebAuthnWrappedJweShape() {
  const header = fixedWebAuthnHeader();
  const compact = await app.encryptWebAuthnWrappedJwe("passkey secret", zeroKey(), header);
  const parts = compact.split(".");
  assert.equal(parts.length, 5);
  assert.equal(app.base64UrlDecode(parts[1]).length, 40);
  const parsed = app.parseProtectedHeader(parts[0]);
  assert.equal(parsed.alg, "A256KW");
  assert.equal(parsed.enc, "A256GCM");
  assert.equal(parsed.app, "erk-webauthn-prf-v1");
  assert.equal(parsed.cid, header.cid);
  assert.equal(parsed.rp, "encrypt.tonysan.fun");
  assert.equal(parsed.ps, header.ps);
}

async function testDefensiveSizeLimits() {
  await rejectsWith(
    () => app.encryptPassphraseJwe(oversizedAscii(app.MAX_ENCRYPTED_PLAINTEXT_BYTES), "passphrase", { p2c: 1500 }),
    /too large.*Multi-code splitting/
  );
  await rejectsWith(
    () => app.encryptWebAuthnWrappedJwe(oversizedAscii(app.MAX_ENCRYPTED_PLAINTEXT_BYTES), zeroKey(), fixedWebAuthnHeader()),
    /too large.*Multi-code splitting/
  );
  assert.throws(
    () => app.encodePlainPayload(oversizedAscii(app.MAX_PLAIN_QR_CONTENT_BYTES)),
    /too large.*Multi-code splitting/
  );
  assert.throws(
    () => app.extractPayloadFromInput(oversizedAscii(app.MAX_RECOVERY_INPUT_BYTES)),
    /too large.*Multi-code splitting/
  );
  assert.throws(
    () => app.splitCompactJwe(oversizedAscii(app.MAX_COMPACT_JWE_CHARS)),
    /too large.*Multi-code splitting/
  );
  assert.throws(
    () => app.splitCompactJwe([
      oversizedAscii(app.MAX_JWE_SEGMENT_CHARS),
      "AA",
      "AA",
      "AA",
      "AA"
    ].join(".")),
    /too large.*Multi-code splitting/
  );
  const oversizedHeader = app.base64UrlEncode(app.utf8Encode(JSON.stringify({
    alg: "A256KW",
    enc: "A256GCM",
    app: "erk-webauthn-prf-v1",
    extra: oversizedAscii(app.MAX_PROTECTED_HEADER_BYTES)
  })));
  assert.throws(
    () => app.parseProtectedHeader(oversizedHeader),
    /too large.*Multi-code splitting/
  );
  assert.throws(
    () => app.buildQrContent(app.ENCRYPTED_PREFIX + oversizedAscii(app.MAX_QR_CONTENT_BYTES), {
      href: "https://encrypt.tonysan.fun/"
    }),
    /too large.*Multi-code splitting/
  );
}

async function testInboundP2cLimit() {
  const compact = await app.encryptPassphraseJwe("secret string", "this is a long passphrase", { p2c: 1500 });
  const parts = compact.split(".");
  const header = app.parseProtectedHeader(parts[0]);
  header.p2c = app.MAX_P2C + 1;
  parts[0] = app.base64UrlEncode(app.utf8Encode(JSON.stringify(header)));
  await rejectsWith(
    () => app.decryptPassphraseJwe(parts.join("."), "this is a long passphrase"),
    /iteration count/
  );
}

async function testUnsupportedFixedIvOption() {
  await rejectsWith(
    () => app.encryptPassphraseJwe("secret string", "this is a long passphrase", {
      p2c: 1500,
      iv: new Uint8Array(12)
    }),
    /Unsupported encryption option/
  );
}

async function testWebAuthnCryptoKeyValidation() {
  const crypto = app.getCrypto();
  const wrapKey = await crypto.subtle.importKey(
    "raw",
    zeroKey(),
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey"]
  );
  const compact = await app.encryptWebAuthnWrappedJwe("passkey secret", wrapKey, fixedWebAuthnHeader());
  assert.equal(await app.decryptWebAuthnWrappedJwe(compact, zeroKey()), "passkey secret");

  const unwrapOnlyKey = await crypto.subtle.importKey(
    "raw",
    zeroKey(),
    { name: "AES-KW", length: 256 },
    false,
    ["unwrapKey"]
  );
  await rejectsWith(
    () => app.encryptWebAuthnWrappedJwe("passkey secret", unwrapOnlyKey, fixedWebAuthnHeader()),
    /AES-KW secret key/
  );

  await rejectsWith(
    () => app.decryptWebAuthnWrappedJwe(compact, wrapKey),
    /AES-KW secret key/
  );

  const gcmKey = await crypto.subtle.importKey(
    "raw",
    zeroKey(),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  await rejectsWith(
    () => app.encryptWebAuthnWrappedJwe("passkey secret", gcmKey, fixedWebAuthnHeader()),
    /AES-KW secret key/
  );

  const shortKwKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(16),
    { name: "AES-KW", length: 128 },
    false,
    ["wrapKey"]
  );
  await rejectsWith(
    () => app.encryptWebAuthnWrappedJwe("passkey secret", shortKwKey, fixedWebAuthnHeader()),
    /AES-KW secret key/
  );
}

async function testWebAuthnHeaderValidation() {
  const header = fixedWebAuthnHeader();
  const metadata = app.validateWebAuthnHeader(header);
  assert.equal(metadata.credentialId.length, 8);
  assert.equal(metadata.prfSalt.length, 32);
  assert.equal(metadata.rpId, "encrypt.tonysan.fun");

  assert.throws(
    () => app.validateWebAuthnHeader({ ...header, kid: "https://example.com/key" }),
    /Unsupported JWE protected header/
  );
  assert.throws(
    () => app.validateWebAuthnHeader({ ...header, alg: "dir" }),
    /Unsupported JWE algorithm/
  );
}

async function testWebAuthnCredentialDescriptorAllowsMobile() {
  const header = fixedWebAuthnHeader();
  const descriptor = app.makeWebAuthnCredentialDescriptor(header.cid);
  assert.equal(descriptor.type, "public-key");
  assert.equal(descriptor.id.length, 8);
  assert.equal(descriptor.transports.includes("hybrid"), true);
  assert.equal(descriptor.transports.includes("internal"), true);
}

async function testPasskeyCreationUsesStableLabel() {
  const metadata = app.validateWebAuthnHeader(fixedWebAuthnHeader());
  const options = app.makeWebAuthnPrfCreationOptions(metadata.prfSalt, metadata.rpId);
  assert.equal(options.publicKey.rp.name, "Encrypted 2D Barcode");
  assert.equal(options.publicKey.user.name, "Encrypted 2D Barcode");
  assert.equal(options.publicKey.user.displayName, "Encrypted 2D Barcode");
  assert.equal(app.utf8Decode(options.publicKey.user.id), "encrypted-2d-barcode-passkey-v1");
  assert.equal(options.publicKey.authenticatorSelection.residentKey, "required");
  assert.equal(options.publicKey.authenticatorSelection.userVerification, "required");
  assert.equal(options.publicKey.hints.includes("hybrid"), true);
}

async function testDiscoverablePasskeyRequestReadsExistingCredential() {
  const metadata = app.validateWebAuthnHeader(fixedWebAuthnHeader());
  const options = app.makeDiscoverableWebAuthnPrfRequestOptions(metadata.prfSalt, metadata.rpId);
  assert.equal(options.publicKey.rpId, "encrypt.tonysan.fun");
  assert.equal(options.publicKey.challenge.length, 32);
  assert.equal(options.publicKey.userVerification, "required");
  assert.equal(Object.hasOwn(options.publicKey, "allowCredentials"), false);
  assert.equal(options.publicKey.hints.includes("hybrid"), true);
  assert.equal(options.publicKey.extensions.prf.eval.first.length, 32);
  assert.equal(Object.hasOwn(options.publicKey.extensions.prf, "evalByCredential"), false);
}

async function testBoundPasskeyRequestUsesStoredCredentialId() {
  const header = fixedWebAuthnHeader();
  const metadata = app.validateWebAuthnHeader(header);
  const options = app.makeBoundWebAuthnPrfRequestOptions(header.cid, metadata.prfSalt, metadata.rpId);
  assert.equal(options.publicKey.rpId, "encrypt.tonysan.fun");
  assert.equal(options.publicKey.allowCredentials.length, 1);
  assert.equal(options.publicKey.userVerification, "required");
  assert.equal(options.publicKey.allowCredentials[0].transports.includes("hybrid"), true);
  assert.equal(options.publicKey.extensions.prf.evalByCredential[header.cid].first.length, 32);
  assert.equal(Object.hasOwn(options.publicKey.extensions.prf, "eval"), false);
}

async function testWebAuthnWrappedJweRoundtrip() {
  const compact = await app.encryptWebAuthnWrappedJwe("passkey secret", zeroKey(), fixedWebAuthnHeader());
  assert.equal(await app.decryptWebAuthnWrappedJwe(compact, zeroKey()), "passkey secret");
}

async function testWrongWebAuthnKek() {
  const compact = await app.encryptWebAuthnWrappedJwe("passkey secret", zeroKey(), fixedWebAuthnHeader());
  const wrongKey = new Uint8Array(32);
  wrongKey.fill(1);
  await rejectsWith(
    () => app.decryptWebAuthnWrappedJwe(compact, wrongKey),
    /Wrong WebAuthn credential|corrupted/
  );
}

async function testCorruptedWebAuthnCiphertext() {
  const compact = await app.encryptWebAuthnWrappedJwe("passkey secret", zeroKey(), fixedWebAuthnHeader());
  const parts = compact.split(".");
  parts[3] = (parts[3][0] === "A" ? "B" : "A") + parts[3].slice(1);
  await rejectsWith(
    () => app.decryptWebAuthnWrappedJwe(parts.join("."), zeroKey()),
    /Wrong WebAuthn credential|corrupted/
  );
}

async function testLegacyDirectWebAuthnPayloadRejection() {
  const header = { ...fixedWebAuthnHeader(), alg: "dir" };
  const protectedSegment = app.base64UrlEncode(app.utf8Encode(JSON.stringify(header)));
  const legacyCompact = [
    protectedSegment,
    "",
    app.base64UrlEncode(new Uint8Array(12)),
    app.base64UrlEncode(app.utf8Encode("ciphertext")),
    app.base64UrlEncode(new Uint8Array(16))
  ].join(".");
  assert.throws(
    () => app.detectPayload(app.ENCRYPTED_PREFIX + legacyCompact),
    /Unsupported encrypted payload/
  );
}

async function testWebAuthnPayloadDetection() {
  const compact = await app.encryptWebAuthnWrappedJwe("passkey secret", zeroKey(), fixedWebAuthnHeader());
  const detected = app.detectPayload(app.ENCRYPTED_PREFIX + compact);
  assert.equal(detected.kind, "webauthn");
  assert.equal(detected.label, "Passkey-protected code");
}

async function testWebAuthnHkdfProfile() {
  const header = fixedWebAuthnHeader();
  const metadata = app.validateWebAuthnHeader(header);
  const prfOutput = new Uint8Array(32);
  prfOutput.fill(0x42);
  const first = await app.deriveWebAuthnKekBytes(prfOutput, metadata);
  const second = await app.deriveWebAuthnKekBytes(prfOutput, metadata);
  assert.equal(first.length, 32);
  assert.deepEqual(first, second);
  assert.equal(Buffer.from(first).toString("hex"), "9bd9cf8717a8bf0252e4607ace6d85f9df11ae6ed7e963d6f09cd93bf711be14");

  const changedHeader = app.makeWebAuthnProtectedHeader(
    metadata.credentialId,
    "example.com",
    metadata.prfSalt
  );
  const changed = await app.deriveWebAuthnKekBytes(
    prfOutput,
    app.validateWebAuthnHeader(changedHeader)
  );
  assert.notDeepEqual(first, changed);
}

async function testEmptyPassphraseRejection() {
  await rejectsWith(
    () => app.encryptPassphraseJwe("secret string", "", { p2c: 1500 }),
    /Enter a passphrase/
  );

  const compact = await app.encryptPassphraseJwe("secret string", "x", { p2c: 1500 });
  await rejectsWith(
    () => app.decryptPassphraseJwe(compact, ""),
    /Enter a passphrase/
  );
}

async function testWrongPassphrase() {
  const compact = await app.encryptPassphraseJwe("secret string", "this is a long passphrase", { p2c: 1500 });
  await rejectsWith(
    () => app.decryptPassphraseJwe(compact, "this is the wrong pass"),
    /passphrase did not unlock/
  );
}

async function testCorruptedPayload() {
  const compact = await app.encryptPassphraseJwe("secret string", "this is a long passphrase", { p2c: 1500 });
  const parts = compact.split(".");
  parts[3] = (parts[3][0] === "A" ? "B" : "A") + parts[3].slice(1);
  await rejectsWith(
    () => app.decryptPassphraseJwe(parts.join("."), "this is a long passphrase"),
    /passphrase did not unlock/
  );
}

async function testUnsupportedHeaderRejection() {
  const compact = await app.encryptPassphraseJwe("secret string", "this is a long passphrase", { p2c: 1500 });
  const parts = compact.split(".");
  const header = app.parseProtectedHeader(parts[0]);
  header.alg = "PBES2-HS256+A128KW";
  parts[0] = app.base64UrlEncode(app.utf8Encode(JSON.stringify(header)));
  await rejectsWith(
    () => app.decryptPassphraseJwe(parts.join("."), "this is a long passphrase"),
    /Unsupported JWE algorithm/
  );
}

async function testTypHeaderRejection() {
  const compact = await app.encryptPassphraseJwe("secret string", "this is a long passphrase", { p2c: 1500 });
  const parts = compact.split(".");
  const header = app.parseProtectedHeader(parts[0]);
  header.typ = "ERK1";
  parts[0] = app.base64UrlEncode(app.utf8Encode(JSON.stringify(header)));
  await rejectsWith(
    () => app.decryptPassphraseJwe(parts.join("."), "this is a long passphrase"),
    /Unsupported JWE protected header/
  );
}

async function testRemoteHeaderRejection() {
  const compact = await app.encryptPassphraseJwe("secret string", "this is a long passphrase", { p2c: 1500 });
  const parts = compact.split(".");
  const header = app.parseProtectedHeader(parts[0]);
  header.jku = "https://example.com/jwks.json";
  parts[0] = app.base64UrlEncode(app.utf8Encode(JSON.stringify(header)));
  await rejectsWith(
    () => app.decryptPassphraseJwe(parts.join("."), "this is a long passphrase"),
    /Unsupported JWE protected header/
  );
}

async function testQrLibraryMatrix() {
  const qrContent = app.buildQrContent(app.encodePlainPayload("qr smoke test"), {
    href: "https://encrypt.tonysan.fun/"
  });
  const qr = app.createQrCode(qrContent);
  const moduleCount = qr.getModuleCount();
  assert.equal(Number.isInteger(moduleCount), true);
  assert.equal(moduleCount >= 21, true);
  assert.equal(typeof qr.isDark(0, 0), "boolean");
}

async function testPassphraseQrRenderPlan() {
  const compact = await app.encryptPassphraseJwe(
    "secret string",
    "this is a long passphrase",
    { p2c: 1500 }
  );
  const payload = app.ENCRYPTED_PREFIX + compact;
  const qrContent = app.buildQrContent(payload, {
    href: "https://encrypt.tonysan.fun/"
  });
  const plan = app.getQrRenderPlan(qrContent);
  assert.equal(plan.errorCorrectionLevel, "M");
  assert.equal(plan.marginModules, 4);
  assert.equal(plan.modulePixels >= 10, true);
  assert.equal(plan.pixelSize, (plan.moduleCount + plan.marginModules * 2) * plan.modulePixels);
}

async function run() {
  const tests = [
    testMarkdownInventory,
    testBase64Url,
    testPlainPayload,
    testLegacyPlainPayload,
    testUrlPayloadExtraction,
    testRawUrlCanBePlainPayload,
    testPlainQrContentUsesPayloadOnly,
    testQrContentUsesDeployedDomainUrl,
    testQrContentUsesLocalHttpUrl,
    testQrContentUsesHostedUrlWithoutOriginProperty,
    testQrContentUsesPayloadForLocalFile,
    testInitialViewFromFragment,
    testPassphraseJweRoundtrip,
    testDefensiveSizeLimits,
    testInboundP2cLimit,
    testUnsupportedFixedIvOption,
    testWebAuthnWrappedJweShape,
    testWebAuthnHeaderValidation,
    testWebAuthnCredentialDescriptorAllowsMobile,
    testPasskeyCreationUsesStableLabel,
    testDiscoverablePasskeyRequestReadsExistingCredential,
    testBoundPasskeyRequestUsesStoredCredentialId,
    testWebAuthnWrappedJweRoundtrip,
    testWebAuthnCryptoKeyValidation,
    testWrongWebAuthnKek,
    testCorruptedWebAuthnCiphertext,
    testLegacyDirectWebAuthnPayloadRejection,
    testWebAuthnPayloadDetection,
    testWebAuthnHkdfProfile,
    testEmptyPassphraseRejection,
    testWrongPassphrase,
    testCorruptedPayload,
    testUnsupportedHeaderRejection,
    testTypHeaderRejection,
    testRemoteHeaderRejection,
    testQrLibraryMatrix,
    testPassphraseQrRenderPlan
  ];
  for (const test of tests) {
    await test();
    console.log("ok", test.name);
  }
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
