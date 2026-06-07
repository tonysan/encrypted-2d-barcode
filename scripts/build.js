const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const root = path.resolve(__dirname, "..");
const staticDir = path.join(root, "static");
const requiredFiles = [
  "index.html",
  "app.js",
  "style.css",
  "LICENSE",
  "_headers"
];

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
if (!html.includes('href="./style.css"') || !html.includes('src="./app.js"')) {
  console.error("static/index.html must reference ./style.css and ./app.js");
  process.exit(1);
}

console.log("static deployment directory verified");
