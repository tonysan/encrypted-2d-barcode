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

async function testQrMatrix() {
  const matrix = app.makeQrMatrix(app.encodePlainPayload("qr smoke test"), "M");
  assert.equal(Number.isInteger(matrix.version), true);
  assert.equal(matrix.size, matrix.modules.length);
  assert.equal(matrix.modules.every((row) => row.length === matrix.size), true);
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
    testPassphraseJweRoundtrip,
    testWrongPassphrase,
    testCorruptedPayload,
    testUnsupportedHeaderRejection,
    testRemoteHeaderRejection,
    testQrMatrix,
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
