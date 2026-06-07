const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const staticDir = path.join(root, "static");
const staticVendorDir = path.join(staticDir, "vendor");
const qrVendorSource = path.join(root, "node_modules", "qrcode-generator", "qrcode.js");
const qrVendorTarget = path.join(staticVendorDir, "qrcode-generator.js");
const requiredFiles = [
  "index.html",
  "app.js",
  "style.css",
  "LICENSE",
  "_headers",
  path.join("vendor", "qrcode-generator.js")
];

if (!fs.existsSync(qrVendorSource)) {
  console.error("Missing qrcode-generator dependency. Run npm install before building.");
  process.exit(1);
}

fs.mkdirSync(staticVendorDir, { recursive: true });
fs.copyFileSync(qrVendorSource, qrVendorTarget);

const testResult = spawnSync(process.execPath, [path.join(root, "tests", "run-tests.js")], {
  cwd: root,
  stdio: "inherit"
});

if (testResult.status !== 0) {
  process.exit(testResult.status || 1);
}

for (const file of requiredFiles) {
  const fullPath = path.join(staticDir, file);
  if (!fs.existsSync(fullPath)) {
    console.error(`Missing static deployment file: static/${file}`);
    process.exit(1);
  }
}

const html = fs.readFileSync(path.join(staticDir, "index.html"), "utf8");
if (
  !/href="\.\/style\.css(?:\?v=[^"]+)"/.test(html) ||
  !/src="\.\/vendor\/qrcode-generator\.js(?:\?v=[^"]+)"/.test(html) ||
  !/src="\.\/app\.js(?:\?v=[^"]+)"/.test(html)
) {
  console.error("static/index.html must reference local style, QR vendor, and app files");
  process.exit(1);
}

console.log("static deployment directory verified");
