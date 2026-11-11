import http from "node:http";
import { readFile } from "node:fs/promises";
// Development-only server: read the latest build for each request. No upload endpoint.
const server = http.createServer(async (req, res) => {
  if (req.url !== "/") {
    res.writeHead(404);
    res.end();
    return;
  }
  try {
    const html = await readFile(new URL("./dist/index.html", import.meta.url));
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    });
    res.end(html);
  } catch {
    res.writeHead(500);
    res.end("Build the app first with npm run build.");
  }
});
server.listen(4173, "127.0.0.1", () =>
  console.log("Local: http://127.0.0.1:4173"),
);
