import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { build } from "esbuild";
import { marked } from "marked";
import { format } from "prettier";

// Normalize source line endings so Windows and Linux produce the same HTML.
const readText = async (path) =>
  (await readFile(path, "utf8")).replace(/\r\n/g, "\n");

// Bundle dependencies locally, retaining readable names and module boundaries.
const options = {
  bundle: true,
  write: false,
  format: "iife",
  platform: "browser",
  target: "es2022",
  alias: { crypto: "./src/crypto-browser.js" },
  minify: false,
  legalComments: "inline",
};
const worker = await build({ ...options, entryPoints: ["src/worker.js"] });
const app = await build({ ...options, entryPoints: ["src/app.js"] });
const escapeScript = (text) => text.replace(/<\/script/gi, "<\\/script");
const escapeHtml = (text) =>
  text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
const css = await readText("src/style.css");
const readme = marked.parse(await readText("README.md"));
const notices = escapeHtml(
  (await readText("LICENSE")) +
    "\n\n" +
    (await readText("THIRD-PARTY-NOTICES.txt")),
);
// Format the HTML shell first. Keep the worker as readable inert text, not a JSON string.
let html = await format(await readText("src/index.html"), {
  parser: "html",
  printWidth: 100,
});
html = html
  .replace("__NOTICES__", () => notices)
  .replace("__README__", () => readme)
  .replace("__CSS__", () => css)
  .replace("__WORKER_SOURCE__", () => escapeScript(worker.outputFiles[0].text))
  .replace("__APP__", () => escapeScript(app.outputFiles[0].text));

// Hash the exact executable script bytes, including the formatted shell whitespace.
const script = html.match(/<script id="app-code">([\s\S]*?)<\/script>/)[1];
const hash = createHash("sha256").update(script).digest("base64");
const csp = `default-src 'none'; script-src 'sha256-${hash}' 'wasm-unsafe-eval'; style-src 'unsafe-inline'; img-src data: blob:; worker-src blob:; connect-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'`;
html = html.replace("__CSP__", csp);
await mkdir("dist", { recursive: true });
await writeFile("dist/index.html", html);
console.log(
  `Built readable offline HTML (${(Buffer.byteLength(html) / 1024 / 1024).toFixed(2)} MiB)`,
);
