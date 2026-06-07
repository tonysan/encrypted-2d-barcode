const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const staticDir = path.join(root, "static");
const staticVendorDir = path.join(staticDir, "vendor");

function prepareStatic() {
  const qrVendorSource = path.join(root, "node_modules", "qrcode-generator", "qrcode.js");
  const qrVendorTarget = path.join(staticVendorDir, "qrcode-generator.js");

  if (!fs.existsSync(qrVendorSource)) {
    throw new Error("Missing qrcode-generator dependency. Run npm install first.");
  }

  fs.mkdirSync(staticVendorDir, { recursive: true });
  fs.copyFileSync(qrVendorSource, qrVendorTarget);
}

if (require.main === module) {
  try {
    prepareStatic();
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}

module.exports = {
  prepareStatic,
  root,
  staticDir
};
