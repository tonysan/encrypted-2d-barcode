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
  assert.equal(payload.startsWith(app.PLAIN_PREFIX), true);
  assert.equal(app.decodePlainPayload(payload), "line one\nline two");
  assert.equal(app.detectPayload(payload).kind, "plain");
}

async function testUrlPayloadExtraction() {
  const payload = app.encodePlainPayload("from url");
  const url = `https://codes.example/recover/#${encodeURIComponent(payload)}`;
  assert.equal(app.extractPayloadFromInput(url), payload);
  assert.equal(app.detectPayload(url).kind, "plain");
}

async function testQrContentUsesHostedUrl() {
  const payload = app.encodePlainPayload("hosted qr");
  const qrContent = app.buildQrContent(payload, {
    protocol: "https:",
    origin: "https://codes.example",
    href: "https://codes.example/app/index.html?ignored=true#old"
  });
  assert.equal(qrContent, `https://codes.example/app/index.html#${encodeURIComponent(payload)}`);
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
  const payload = app.encodePlainPayload("hosted qr");
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
  const detected = app.detectPayload(app.ENCRYPTED_PREFIX + compact);
  assert.equal(detected.kind, "passphrase");
  assert.equal(await app.decryptPassphraseJwe(compact, "this is a long passphrase"), "secret string");
}

async function testWrongPassphrase() {
  const compact = await app.encryptPassphraseJwe("secret string", "this is a long passphrase", { p2c: 1500 });
  await rejectsWith(
    () => app.decryptPassphraseJwe(compact, "this is the wrong pass"),
    /Wrong passphrase|corrupted/
  );
}

async function testCorruptedPayload() {
  const compact = await app.encryptPassphraseJwe("secret string", "this is a long passphrase", { p2c: 1500 });
  const parts = compact.split(".");
  parts[3] = (parts[3][0] === "A" ? "B" : "A") + parts[3].slice(1);
  await rejectsWith(
    () => app.decryptPassphraseJwe(parts.join("."), "this is a long passphrase"),
    /Wrong passphrase|corrupted/
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

async function testPassphrasePolicy() {
  assert.match(app.validatePassphraseForCreation("short"), /16/);
  assert.match(app.validatePassphraseForCreation("1111111111111111"), /digits/);
  assert.equal(app.validatePassphraseForCreation("five random words would be better"), "");
}

async function run() {
  const tests = [
    testBase64Url,
    testPlainPayload,
    testUrlPayloadExtraction,
    testQrContentUsesHostedUrl,
    testQrContentUsesDeployedDomainUrl,
    testQrContentUsesLocalHttpUrl,
    testQrContentUsesHostedUrlWithoutOriginProperty,
    testQrContentUsesPayloadForLocalFile,
    testInitialViewFromFragment,
    testPassphraseJweRoundtrip,
    testWrongPassphrase,
    testCorruptedPayload,
    testUnsupportedHeaderRejection,
    testRemoteHeaderRejection,
    testQrLibraryMatrix,
    testPassphraseQrRenderPlan,
    testPassphrasePolicy
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
