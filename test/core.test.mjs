import test from "node:test";
import assert from "node:assert/strict";
import {
  pbkdf2Sync,
  createCipheriv,
  scryptSync,
  createDecipheriv,
} from "node:crypto";
import QRCode from "qrcode";
import jsQR from "jsqr";
import sodium from "libsodium-wrappers-sumo";
import { readFile } from "node:fs/promises";
import kdbx from "kdbxweb";
import { exportKdbx, importKdbx, inspectKdbx } from "../src/kdbx.js";
import {
  base32,
  normalize,
  parseText,
  inspect,
  uri,
  decryptAuthy,
  exportEnte,
  importEnte,
  exportAegis,
  importAegis,
  totp,
  b64,
  unb64,
  unhex,
  bytes,
} from "../src/core.js";
const token = normalize({
    name: "àlice + test@example.com",
    issuer: "Example & Co",
    secret: "JBSWY3DPEHPK3PXP",
  }),
  password = "correct horse battery staple";
test("KDBX export fields consumed by Passbolt, round trip and wrong password", async () => {
  const input = { ...token, algorithm: "SHA512", period: 60, digits: 8 };
  const data = await exportKdbx([input], password);
  assert.equal(inspectKdbx(data).locked, true);
  const result = await importKdbx(data, password);
  for (const key of [
    "secret",
    "name",
    "issuer",
    "algorithm",
    "period",
    "digits",
  ])
    assert.equal(result.tokens[0][key], input[key]);
  const db = await kdbx.Kdbx.load(
    data,
    new kdbx.Credentials(kdbx.ProtectedValue.fromString(password)),
  );
  const entry = db.getDefaultGroup().entries[0];
  assert.equal(
    entry.fields.get("TimeOtp-Secret-Base32").getText(),
    token.secret,
  );
  assert.equal(entry.fields.get("TimeOtp-Algorithm"), "HMAC-SHA-512");
  entry.fields.delete("otp");
  const bare = await importKdbx(await db.save(), password);
  assert.equal(bare.tokens[0].algorithm, "SHA512");
  await assert.rejects(importKdbx(data, "wrong"));
  const corrupt = data.slice(0);
  new Uint8Array(corrupt)[corrupt.byteLength - 10] ^= 1;
  await assert.rejects(importKdbx(corrupt, password));
});
test("Official Passbolt repository KDBX fixture imports", async () => {
  const data = await readFile(
    new URL("./fixtures/passbolt-totp.kdbx", import.meta.url),
  );
  const result = await importKdbx(
    data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength),
    "passbolt",
  );
  assert.ok(result.tokens.length >= 2);
  assert.equal(result.tokens[0].secret, "TJSNMLGTCYOEMXZG");
  assert.ok(result.skipped >= 0);
});
function authy(plain) {
  const salt = "literal-salt-not-base64==",
    iv = Buffer.alloc(16, 7),
    key = pbkdf2Sync(password, salt, 100000, 32, "sha1"),
    cipher = createCipheriv("aes-256-cbc", key, iv);
  return {
    name: "Account, with commas",
    salt,
    iv: iv.toString("hex"),
    encrypted_seed: Buffer.concat([
      cipher.update(plain),
      cipher.final(),
    ]).toString("base64"),
  };
}
test("RFC 6238 published SHA1, SHA256, SHA512 vectors", async () => {
  for (const [algorithm, length, expected] of [
    ["SHA1", 20, "94287082"],
    ["SHA256", 32, "46119246"],
    ["SHA512", 64, "90693936"],
  ]) {
    const secret = base32(bytes("1234567890".repeat(7).slice(0, length)));
    assert.equal(
      await totp(normalize({ secret, algorithm, digits: 8 }), 59000),
      expected,
    );
  }
});
test("URI round trip preserves issuer, unicode, parameters and extra metadata", () => {
  const t = {
    ...token,
    algorithm: "SHA256",
    digits: 8,
    period: 60,
    extra: { note: "special note" },
  };
  const parsed = parseText(uri(t))[0];
  for (const k of ["name", "issuer", "algorithm", "digits", "period", "secret"])
    assert.equal(parsed[k], t[k]);
  assert.equal(parsed.extra.note, "special note");
  assert.equal(parseText(uri(token) + "," + uri(t)).length, 2);
});
test("CSV RFC quoting, semicolon, multiline, apostrophes and BOM", () => {
  const row = authy(bytes(token.secret));
  const csv =
    '\ufeffname,encrypted_seed,salt,iv\r\n"O\'Brien,\naccount",' +
    row.encrypted_seed +
    "," +
    row.salt +
    "," +
    row.iv;
  assert.equal(inspect(csv).rows[0].name, "O'Brien,\naccount");
  assert.equal(
    inspect("name;encrypted_seed;salt;iv\nhello;abc;salt;iv").rows.length,
    1,
  );
  assert.throws(() =>
    inspect("name,encrypted_seed,salt,iv\nhello,abc,salt,iv,extra"),
  );
});
test("Authy interoperates with Node AES CBC / PBKDF2 fixture", async () => {
  assert.equal(
    (await decryptAuthy(authy(bytes(token.secret)), password)).secret,
    token.secret,
  );
  assert.equal(
    (await decryptAuthy(authy(bytes("0123456789abcdef")), password)).secret,
    base32(unhex("0123456789abcdef")),
  );
  assert.equal(
    (await decryptAuthy(authy(new Uint8Array([0, 255, 1, 128])), password))
      .secret,
    base32(new Uint8Array([0, 255, 1, 128])),
  );
  await assert.rejects(decryptAuthy(authy(bytes(token.secret)), "wrong"));
});
test("Ambiguous hex/Base32 seed is flagged; explicit hex override works", async () => {
  const row = authy(bytes("DEADBEEF"));
  assert.equal((await decryptAuthy(row, password)).ambiguous, true);
  assert.equal(
    (await decryptAuthy(row, password, "hex")).secret,
    base32(unhex("DEADBEEF")),
  );
});
test("Ente round trip; independent sodium KDF; rejects wrong password and corruption", async () => {
  const data = await exportEnte([token], password);
  assert.equal((await importEnte(data, password))[0].secret, token.secret);
  await sodium.ready;
  const key = sodium.crypto_pwhash(
    32,
    password,
    unb64(data.kdfParams.salt),
    data.kdfParams.opsLimit,
    data.kdfParams.memLimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
  const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(
    unb64(data.encryptionNonce),
    key,
  );
  const out = sodium.crypto_secretstream_xchacha20poly1305_pull(
    state,
    unb64(data.encryptedData),
  );
  assert.equal(new TextDecoder().decode(out.message), uri(token));
  await assert.rejects(importEnte(data, "wrong"));
  const cipher = unb64(data.encryptedData);
  cipher[10] ^= 1;
  await assert.rejects(
    importEnte({ ...data, encryptedData: b64(cipher) }, password),
  );
});
test("External-style Ente backup generated solely with sodium imports", async () => {
  await sodium.ready;
  const salt = sodium.randombytes_buf(16),
    kdfParams = { salt: b64(salt), memLimit: 16777216, opsLimit: 2 };
  const key = sodium.crypto_pwhash(
    32,
    password,
    salt,
    2,
    16777216,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
  const s = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  const encryptedData = b64(
    sodium.crypto_secretstream_xchacha20poly1305_push(
      s.state,
      bytes(uri(token)),
      null,
      3,
    ),
  );
  assert.equal(
    (
      await importEnte(
        {
          version: 1,
          kdfParams,
          encryptionNonce: b64(s.header),
          encryptedData,
        },
        password,
      )
    )[0].secret,
    token.secret,
  );
});
test("Aegis round trip and independent Node scrypt/GCM decrypt; corruption rejection", async () => {
  const data = await exportAegis([token], password);
  assert.equal((await importAegis(data, password))[0].secret, token.secret);
  const slot = data.header.slots[0],
    key = scryptSync(password, unhex(slot.salt), 32, {
      N: slot.n,
      r: slot.r,
      p: slot.p,
      maxmem: 128 * 1024 * 1024,
    });
  function decrypt(k, body, p) {
    const c = createDecipheriv("aes-256-gcm", k, unhex(p.nonce));
    c.setAuthTag(unhex(p.tag));
    return Buffer.concat([c.update(body), c.final()]);
  }
  const master = decrypt(key, unhex(slot.key), slot.key_params);
  const db = JSON.parse(decrypt(master, unb64(data.db), data.header.params));
  assert.equal(db.entries[0].info.secret, token.secret);
  await assert.rejects(importAegis(data, "wrong"));
  const altered = structuredClone(data);
  altered.header.params.tag = "00".repeat(16);
  await assert.rejects(importAegis(altered, password));
});
test("QR generated by qrcode is decoded by independent jsQR", () => {
  const data = uri(token),
    qr = QRCode.create(data, { errorCorrectionLevel: "M" }),
    scale = 6,
    pad = 4,
    size = (qr.modules.size + pad * 2) * scale,
    rgba = new Uint8ClampedArray(size * size * 4);
  for (let y = 0; y < size; y++)
    for (let x = 0; x < size; x++) {
      const mx = Math.floor(x / scale) - pad,
        my = Math.floor(y / scale) - pad,
        black =
          mx >= 0 &&
          my >= 0 &&
          mx < qr.modules.size &&
          my < qr.modules.size &&
          qr.modules.get(my, mx);
      const off = (y * size + x) * 4;
      rgba[off] = rgba[off + 1] = rgba[off + 2] = black ? 0 : 255;
      rgba[off + 3] = 255;
    }
  assert.equal(jsQR(rgba, size, size).data, data);
});
test("Reject unsupported types, versions, malformed secrets and excessive KDF", async () => {
  assert.throws(() =>
    parseText("otpauth://hotp/test?secret=JBSWY3DPEHPK3PXP&counter=0"),
  );
  assert.throws(() => normalize({ secret: "bad!" }));
  assert.throws(() => inspect('{"version":999,"db":{}}'));
  await assert.rejects(
    importEnte(
      { version: 1, kdfParams: { memLimit: 2 ** 40, opsLimit: 3, salt: "" } },
      password,
    ),
  );
});
import { createHash, createHmac } from "node:crypto";
import {
  readAegis,
  aegisDb,
  parseUri,
  assertExportable,
  fromBase32,
} from "../src/core.js";
const hotpToken = normalize(
  {
    type: "hotp",
    name: "RFC HOTP",
    secret: base32(bytes("12345678901234567890")),
    counter: 0,
  },
  true,
);
const steamToken = normalize(
  { type: "steam", name: "Steam fixture", secret: token.secret },
  true,
);
const motpToken = normalize(
  {
    type: "motp",
    name: "mOTP fixture",
    secret: base32(unhex("0123456789abcdef")),
    pin: "0123",
  },
  true,
);

test("HOTP RFC 4226 counters 0–9; preview never mutates the counter", async () => {
  const expected = [
    "755224",
    "287082",
    "359152",
    "969429",
    "338314",
    "254676",
    "287922",
    "162583",
    "399871",
    "520489",
  ];
  for (let counter = 0; counter < expected.length; counter++)
    assert.equal(await totp({ ...hotpToken, counter }, 0), expected[counter]);
  assert.equal(await totp(hotpToken, 999999999), expected[0]);
  assert.equal(hotpToken.counter, 0);
  for (const counter of [
    undefined,
    null,
    "",
    -1,
    0.5,
    Number.MAX_SAFE_INTEGER + 1,
    "9007199254740993",
  ])
    assert.throws(() => normalize({ ...hotpToken, counter }, true));
});
test("Steam encoding and mOTP MD5 agree with independent Node crypto", async () => {
  const time = 59000,
    buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(1n);
  const mac = createHmac("sha1", fromBase32(steamToken.secret))
    .update(buf)
    .digest();
  let value = mac.readUInt32BE(mac.at(-1) & 15) & 0x7fffffff,
    expected = "";
  for (let i = 0; i < 5; i++) {
    expected += "23456789BCDFGHJKMNPQRTVWXY"[value % 26];
    value = Math.floor(value / 26);
  }
  assert.equal(await totp(steamToken, time), expected);
  assert.equal(
    await totp(motpToken, time),
    createHash("md5")
      .update("5" + "0123456789abcdef" + "0123")
      .digest("hex")
      .slice(0, 6),
  );
  assert.throws(() => normalize({ ...motpToken, pin: "123" }, true));
  assert.throws(() => normalize({ ...steamToken, period: 60 }, true));
});
test("Compatibility is opt-in across URI, plaintext and encrypted formats", async () => {
  for (const t of [hotpToken, steamToken, motpToken])
    assert.throws(() => normalize(t), /compatibility/);
  for (const t of [hotpToken, steamToken]) {
    assert.throws(() => parseUri(uri(t)));
    assert.equal(parseUri(uri(t), true).type, t.type);
  }
  assert.equal(
    parseUri(
      "otpauth://totp/Steam?secret=" + token.secret + "&encoder=steam&digits=5",
      true,
    ).type,
    "steam",
  );
  const mixed = [token, hotpToken, steamToken, motpToken],
    db = aegisDb(mixed);
  assert.throws(() => inspect(JSON.stringify({ version: 1, header: {}, db })));
  assert.equal(
    inspect(JSON.stringify({ version: 1, header: {}, db }), true).tokens.length,
    4,
  );
  const data = await exportAegis(mixed, password);
  await assert.rejects(importAegis(data, password));
  const restored = await importAegis(data, password, true);
  for (let i = 0; i < mixed.length; i++)
    for (const k of [
      "type",
      "secret",
      "algorithm",
      "digits",
      "period",
      "counter",
      "pin",
    ])
      assert.equal(restored[i][k], mixed[i][k]);
  const ente = await exportEnte([hotpToken, steamToken], password);
  await assert.rejects(importEnte(ente, password));
  const read = await importEnte(ente, password, true);
  assert.equal(read[0].counter, 0);
  assert.equal(read[1].type, "steam");
});
test("No silent conversion or omission in incompatible exports", async () => {
  assert.throws(() => uri(motpToken));
  assert.throws(() => assertExportable([motpToken], "plain"));
  await assert.rejects(exportEnte([token, motpToken], password));
  for (const t of [hotpToken, steamToken, motpToken])
    await assert.rejects(exportKdbx([token, t], password));
  const edited = { ...hotpToken, counter: 123456789 };
  const restored = readAegis(aegisDb([edited]), true)[0];
  assert.equal(restored.counter, 123456789);
  assert.equal(parseUri(uri(edited), true).counter, 123456789);
  assert.throws(() =>
    readAegis(
      {
        version: 3,
        entries: [{ type: "yandex", info: { secret: token.secret } }],
      },
      true,
    ),
  );
});
test("KDBX compatibility reads explicit HOTP/Steam URIs and native Base32 HOTP fields", async () => {
  const db = kdbx.Kdbx.create(
    new kdbx.Credentials(kdbx.ProtectedValue.fromString(password)),
    "Extended fixture",
  );
  db.setVersion(3);
  for (const t of [hotpToken, steamToken]) {
    const e = db.createEntry(db.getDefaultGroup());
    e.fields.set("Title", t.name);
    e.fields.set("otp", kdbx.ProtectedValue.fromString(uri(t)));
  }
  const native = db.createEntry(db.getDefaultGroup());
  native.fields.set("Title", "Native HOTP");
  native.fields.set(
    "HmacOtp-Secret-Base32",
    kdbx.ProtectedValue.fromString(hotpToken.secret),
  );
  native.fields.set("HmacOtp-Counter", "42");
  const data = await db.save();
  await assert.rejects(importKdbx(data, password));
  const result = await importKdbx(data, password, true);
  assert.deepEqual(
    result.tokens.map((t) => t.type),
    ["hotp", "steam", "hotp"],
  );
  assert.equal(result.tokens[2].counter, 42);
});
