// Public synthetic data only; used for browser import/export smoke tests.
import { writeFile } from "node:fs/promises";
import { pbkdf2Sync, createCipheriv } from "node:crypto";
import Papa from "papaparse";
import {
  exportEnte,
  exportAegis,
  aegisDb,
  normalize,
  uri,
} from "../src/core.js";
import { exportKdbx } from "../src/kdbx.js";
const password = "demo-test-password-2026";
const tokens = [
  normalize({
    name: "demo@example.com",
    issuer: "Demo",
    secret: "JBSWY3DPEHPK3PXP",
  }),
  normalize({
    name: "<script>not executable</script>",
    issuer: "Public fixture",
    secret: "JBSWY3DPEHPK3PXP",
    algorithm: "SHA256",
    digits: 8,
    period: 60,
  }),
];
for (const [name, fn] of [
  ["ente", exportEnte],
  ["aegis", exportAegis],
])
  await writeFile(
    new URL(`./fixtures/demo-${name}.json`, import.meta.url),
    JSON.stringify(await fn(tokens, password)),
  );
await writeFile(
  new URL("./fixtures/demo.kdbx", import.meta.url),
  new Uint8Array(await exportKdbx(tokens, password)),
);
await writeFile(
  new URL("./fixtures/demo.txt", import.meta.url),
  tokens.map(uri).join("\n"),
);
const rows = tokens.map((t) => {
  const salt = "demo-literal-salt",
    iv = Buffer.alloc(16, 7),
    key = pbkdf2Sync(password, salt, 100000, 32, "sha1"),
    c = createCipheriv("aes-256-cbc", key, iv);
  return {
    name: t.name,
    encrypted_seed: Buffer.concat([c.update(t.secret), c.final()]).toString(
      "base64",
    ),
    salt,
    iv: iv.toString("hex"),
  };
});
await writeFile(
  new URL("./fixtures/demo-authy.csv", import.meta.url),
  Papa.unparse(rows),
);
const extended = ["totp", "hotp", "steam", "motp"].map((type) =>
  normalize(
    {
      type,
      name: `${type} fixture`,
      secret: "JBSWY3DPEHPK3PXP",
      counter: 42,
      pin: "0123",
    },
    true,
  ),
);
await writeFile(
  new URL("./fixtures/demo-extended.json", import.meta.url),
  JSON.stringify(await exportAegis(extended, password)),
);
await writeFile(
  new URL("./fixtures/demo-extended-plain.json", import.meta.url),
  JSON.stringify({
    version: 1,
    header: { slots: null, params: null },
    db: aegisDb(extended),
  }),
);
console.log("Created public demo fixtures. Password: " + password);
