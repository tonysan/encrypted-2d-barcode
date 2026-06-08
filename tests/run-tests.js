const assert = require("node:assert/strict");
const app = require("../static/app.js");

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

function fixedDirectHeader() {
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

function fixedIv() {
  const iv = new Uint8Array(12);
  for (let index = 0; index < iv.length; index += 1) {
    iv[index] = 0xa0 + index;
  }
  return iv;
}

async function testDirectJweShape() {
  const header = fixedDirectHeader();
  const compact = await app.encryptDirectJwe("direct secret", zeroKey(), header, { iv: fixedIv() });
  const parts = compact.split(".");
  assert.equal(parts.length, 5);
  assert.equal(parts[1], "");
  const parsed = app.parseProtectedHeader(parts[0]);
  assert.equal(parsed.alg, "dir");
  assert.equal(parsed.enc, "A256GCM");
  assert.equal(parsed.app, "erk-webauthn-prf-v1");
  assert.equal(parsed.cid, header.cid);
  assert.equal(parsed.rp, "encrypt.tonysan.fun");
  assert.equal(parsed.ps, header.ps);
}

async function testDirectHeaderValidation() {
  const header = fixedDirectHeader();
  const metadata = app.validateDirectHeader(header);
  assert.equal(metadata.credentialId.length, 8);
  assert.equal(metadata.prfSalt.length, 32);
  assert.equal(metadata.rpId, "encrypt.tonysan.fun");

  assert.throws(
    () => app.validateDirectHeader({ ...header, kid: "https://example.com/key" }),
    /Unsupported JWE protected header/
  );
  assert.throws(
    () => app.validateDirectHeader({ alg: "dir", enc: "A256GCM" }),
    /Unsupported WebAuthn PRF profile/
  );
}

async function testWebAuthnCredentialDescriptorAllowsMobile() {
  const header = fixedDirectHeader();
  const descriptor = app.makeWebAuthnCredentialDescriptor(header.cid);
  assert.equal(descriptor.type, "public-key");
  assert.equal(descriptor.id.length, 8);
  assert.equal(descriptor.transports.includes("hybrid"), true);
  assert.equal(descriptor.transports.includes("internal"), true);
}

async function testPasskeyCreationUsesStableLabel() {
  const metadata = app.validateDirectHeader(fixedDirectHeader());
  const options = app.makeWebAuthnPrfCreationOptions(metadata.prfSalt, metadata.rpId);
  assert.equal(options.publicKey.rp.name, "Encrypted 2D Barcode");
  assert.equal(options.publicKey.user.name, "Encrypted 2D Barcode");
  assert.equal(options.publicKey.user.displayName, "Encrypted 2D Barcode");
  assert.equal(app.utf8Decode(options.publicKey.user.id), "encrypted-2d-barcode-passkey-v1");
  assert.equal(options.publicKey.authenticatorSelection.residentKey, "required");
  assert.equal(options.publicKey.hints.includes("hybrid"), true);
}

async function testDiscoverablePasskeyRequestReadsExistingCredential() {
  const metadata = app.validateDirectHeader(fixedDirectHeader());
  const options = app.makeDiscoverableWebAuthnPrfRequestOptions(metadata.prfSalt, metadata.rpId);
  assert.equal(options.publicKey.rpId, "encrypt.tonysan.fun");
  assert.equal(options.publicKey.challenge.length, 32);
  assert.equal(Object.hasOwn(options.publicKey, "allowCredentials"), false);
  assert.equal(options.publicKey.hints.includes("hybrid"), true);
  assert.equal(options.publicKey.extensions.prf.eval.first.length, 32);
  assert.equal(Object.hasOwn(options.publicKey.extensions.prf, "evalByCredential"), false);
}

async function testBoundPasskeyRequestUsesStoredCredentialId() {
  const header = fixedDirectHeader();
  const metadata = app.validateDirectHeader(header);
  const options = app.makeBoundWebAuthnPrfRequestOptions(header.cid, metadata.prfSalt, metadata.rpId);
  assert.equal(options.publicKey.rpId, "encrypt.tonysan.fun");
  assert.equal(options.publicKey.allowCredentials.length, 1);
  assert.equal(options.publicKey.allowCredentials[0].transports.includes("hybrid"), true);
  assert.equal(options.publicKey.extensions.prf.evalByCredential[header.cid].first.length, 32);
  assert.equal(Object.hasOwn(options.publicKey.extensions.prf, "eval"), false);
}

async function testDirectJweRoundtrip() {
  const compact = await app.encryptDirectJwe("direct secret", zeroKey(), fixedDirectHeader(), { iv: fixedIv() });
  assert.equal(await app.decryptDirectJwe(compact, zeroKey()), "direct secret");
}

async function testWrongDirectKey() {
  const compact = await app.encryptDirectJwe("direct secret", zeroKey(), fixedDirectHeader(), { iv: fixedIv() });
  const wrongKey = new Uint8Array(32);
  wrongKey.fill(1);
  await rejectsWith(
    () => app.decryptDirectJwe(compact, wrongKey),
    /Wrong direct key|corrupted/
  );
}

async function testCorruptedDirectCiphertext() {
  const compact = await app.encryptDirectJwe("direct secret", zeroKey(), fixedDirectHeader(), { iv: fixedIv() });
  const parts = compact.split(".");
  parts[3] = (parts[3][0] === "A" ? "B" : "A") + parts[3].slice(1);
  await rejectsWith(
    () => app.decryptDirectJwe(parts.join("."), zeroKey()),
    /Wrong direct key|corrupted/
  );
}

async function testDirectEncryptedKeySegmentRejection() {
  const compact = await app.encryptDirectJwe("direct secret", zeroKey(), fixedDirectHeader(), { iv: fixedIv() });
  const parts = compact.split(".");
  parts[1] = "AA";
  await rejectsWith(
    () => app.decryptDirectJwe(parts.join("."), zeroKey()),
    /Direct JWE must not contain an encrypted key/
  );
}

async function testWebAuthnPayloadDetection() {
  const compact = await app.encryptDirectJwe("direct secret", zeroKey(), fixedDirectHeader(), { iv: fixedIv() });
  const detected = app.detectPayload(app.ENCRYPTED_PREFIX + compact);
  assert.equal(detected.kind, "webauthn");
  assert.equal(detected.label, "Passkey-protected code");
}

async function testWebAuthnHkdfProfile() {
  const header = fixedDirectHeader();
  const metadata = app.validateDirectHeader(header);
  const prfOutput = new Uint8Array(32);
  prfOutput.fill(0x42);
  const first = await app.deriveWebAuthnDirectKeyBytes(prfOutput, metadata);
  const second = await app.deriveWebAuthnDirectKeyBytes(prfOutput, metadata);
  assert.equal(first.length, 32);
  assert.deepEqual(first, second);

  const changedHeader = app.makeWebAuthnProtectedHeader(
    metadata.credentialId,
    "example.com",
    metadata.prfSalt
  );
  const changed = await app.deriveWebAuthnDirectKeyBytes(
    prfOutput,
    app.validateDirectHeader(changedHeader)
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
    testDirectJweShape,
    testDirectHeaderValidation,
    testWebAuthnCredentialDescriptorAllowsMobile,
    testPasskeyCreationUsesStableLabel,
    testDiscoverablePasskeyRequestReadsExistingCredential,
    testBoundPasskeyRequestUsesStoredCredentialId,
    testDirectJweRoundtrip,
    testWrongDirectKey,
    testCorruptedDirectCiphertext,
    testDirectEncryptedKeySegmentRejection,
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
