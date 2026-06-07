const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { prepareStatic, staticDir } = require("./prepare-static");

const host = process.env.HOST || "127.0.0.1";
const port = Number.parseInt(process.env.PORT || "8788", 10);

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml; charset=utf-8",
  ".txt": "text/plain; charset=utf-8"
};

function send(res, statusCode, body, contentType) {
  res.writeHead(statusCode, {
    "Cache-Control": "no-store",
    "Content-Type": contentType || "text/plain; charset=utf-8",
    "X-Content-Type-Options": "nosniff"
  });
  res.end(body);
}

function resolveRequestPath(reqUrl) {
  const url = new URL(reqUrl, `http://${host}:${port}`);
  const pathname = decodeURIComponent(url.pathname);
  const relativePath = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const fullPath = path.resolve(staticDir, relativePath);
  if (!fullPath.startsWith(staticDir + path.sep) && fullPath !== staticDir) {
    return null;
  }
  return fullPath;
}

try {
  prepareStatic();
} catch (error) {
  console.error(error.message);
  process.exit(1);
}

const server = http.createServer((req, res) => {
  if (req.method !== "GET" && req.method !== "HEAD") {
    send(res, 405, "Method not allowed");
    return;
  }

  let fullPath;
  try {
    fullPath = resolveRequestPath(req.url || "/");
  } catch (error) {
    send(res, 400, "Bad request");
    return;
  }
  if (!fullPath) {
    send(res, 403, "Forbidden");
    return;
  }

  fs.readFile(fullPath, (error, data) => {
    if (error) {
      send(res, error.code === "ENOENT" ? 404 : 500, error.code === "ENOENT" ? "Not found" : "Server error");
      return;
    }
    const contentType = contentTypes[path.extname(fullPath).toLowerCase()] || "application/octet-stream";
    res.writeHead(200, {
      "Cache-Control": "no-store",
      "Content-Type": contentType,
      "X-Content-Type-Options": "nosniff"
    });
    if (req.method === "HEAD") {
      res.end();
      return;
    }
    res.end(data);
  });
});

server.listen(port, host, () => {
  console.log(`Serving static app at http://${host}:${port}/`);
});
