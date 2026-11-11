/*! TOTP Bridge format and crypto layer. All operations run locally.
 * Normalize every imported token before it reaches the UI or an export adapter.
 * Authy is unauthenticated CBC; Ente/Aegis authenticate ciphertext before parsing.
 */
import Papa from "papaparse";
import sodium from "libsodium-wrappers-sumo";
import { argon2id, scrypt, md5 } from "hash-wasm";

const enc = new TextEncoder(),
  dec = new TextDecoder("utf-8", { fatal: true });
export const bytes = (s) => enc.encode(s);
export const hex = (b) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
export function unhex(s) {
  if (typeof s !== "string" || !/^(?:[0-9a-f]{2})+$/i.test(s))
    throw Error("Invalid hexadecimal field");
  return Uint8Array.from(s.match(/../g), (x) => parseInt(x, 16));
}
export const b64 = (b) => {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
};
export const unb64 = (s) => Uint8Array.from(atob(s), (x) => x.charCodeAt(0));
const random = (n) => crypto.getRandomValues(new Uint8Array(n));
const join = (a, b) => {
  const c = new Uint8Array(a.length + b.length);
  c.set(a);
  c.set(b, a.length);
  return c;
};
function integer(n, min, max, label) {
  if (!Number.isSafeInteger(n) || n < min || n > max)
    throw Error(`${label}: unsupported value (${min}–${max})`);
  return n;
}
export function base32(data) {
  const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let value = 0,
    bits = 0,
    out = "";
  for (const b of data) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += abc[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) out += abc[(value << (5 - bits)) & 31];
  return out;
}
export function fromBase32(s) {
  const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let v = 0,
    b = 0,
    out = [];
  for (const c of s) {
    const n = abc.indexOf(c);
    if (n < 0) throw Error("Invalid Base32 secret");
    v = (v << 5) | n;
    b += 5;
    if (b >= 8) {
      out.push((v >>> (b - 8)) & 255);
      b -= 8;
    }
  }
  if (b && v & ((1 << b) - 1)) throw Error("Invalid Base32 padding");
  return new Uint8Array(out);
}
/*! Extended types require explicit opt-in at the import boundary. Counter values are
 * restricted to exact JS integers because Aegis serializes them as JSON numbers. */
export function normalize(t, compatibility = false) {
  const type = String(t.type || "totp").toLowerCase();
  if (!["totp", "hotp", "steam", "motp"].includes(type))
    throw Error(`Unsupported OTP type: ${type}`);
  if (type !== "totp" && !compatibility)
    throw Error(
      `${type.toUpperCase()} requires Activate compatibility with other formats. Enable it before importing.`,
    );
  const secret = String(t.secret || "")
    .toUpperCase()
    .replace(/\s/g, "")
    .replace(/=+$/, "");
  if (!/^[A-Z2-7]+$/.test(secret) || secret.length < 2)
    throw Error("Missing or invalid Base32 secret");
  if (base32(fromBase32(secret)) !== secret)
    throw Error("Invalid Base32 length");
  const fixed =
    type === "steam"
      ? { algorithm: "SHA1", digits: 5, period: 30 }
      : type === "motp"
        ? { algorithm: "MD5", digits: 6, period: 10 }
        : null;
  const algorithm = String(t.algorithm || fixed?.algorithm || "SHA1")
    .toUpperCase()
    .replaceAll("-", "");
  const digits = Number(t.digits ?? fixed?.digits ?? 6);
  const period = Number(t.period ?? fixed?.period ?? 30);
  if (
    fixed &&
    (algorithm !== fixed.algorithm ||
      digits !== fixed.digits ||
      period !== fixed.period)
  )
    throw Error(
      `${type.toUpperCase()} requires ${fixed.algorithm}, ${fixed.digits} characters, ${fixed.period}s`,
    );
  if (!fixed && !["SHA1", "SHA256", "SHA512"].includes(algorithm))
    throw Error("Unsupported OTP algorithm");
  const result = {
    ...t,
    type,
    name: String(t.name || "Account"),
    issuer: String(t.issuer || ""),
    secret,
    algorithm,
    digits: fixed ? digits : integer(digits, 6, 8, "Digits"),
    period: integer(period, 1, 86400, "Period"),
  };
  if (type === "hotp") {
    if (
      t.counter === undefined ||
      t.counter === null ||
      String(t.counter).trim() === ""
    )
      throw Error("HOTP requires an explicit counter");
    if (!/^\d+$/.test(String(t.counter))) throw Error("Invalid HOTP counter");
    result.counter = integer(
      Number(t.counter),
      0,
      Number.MAX_SAFE_INTEGER,
      "HOTP counter",
    );
  }
  if (type === "motp") {
    if (typeof t.pin !== "string" || !/^\d{4}$/.test(t.pin))
      throw Error("mOTP requires a four-digit PIN, including leading zeros");
    result.pin = t.pin;
  }
  return result;
}
/*! Destination policy is shared by the UI and exporters: reject whole selections,
 * never silently discard tokens or relabel another algorithm as TOTP. */
export function assertExportable(tokens, format) {
  const supported = {
    aegis: ["totp", "hotp", "steam", "motp"],
    ente: ["totp", "hotp", "steam"],
    plain: ["totp", "hotp", "steam"],
    kdbx: ["totp"],
  }[format];
  if (!supported) throw Error("Unknown export format");
  const rejected = tokens.filter((t) => !supported.includes(t.type || "totp"));
  if (rejected.length)
    throw Error(
      `${format.toUpperCase()} cannot preserve ${[...new Set(rejected.map((t) => t.type.toUpperCase()))].join(", ")} (${rejected.length} selected). Choose Aegis or deselect these entries. Nothing exported.`,
    );
}
export function uri(raw) {
  const t = normalize(raw, true);
  assertExportable([t], "plain");
  const p = new URLSearchParams(t.extra || {});
  for (const key of [
    "secret",
    "issuer",
    "algorithm",
    "digits",
    "period",
    "counter",
    "pin",
    "encoder",
  ])
    p.delete(key);
  for (const [key, value] of Object.entries({
    secret: t.secret,
    issuer: t.issuer,
    algorithm: t.algorithm,
    digits: t.digits,
    ...(t.type === "hotp" ? { counter: t.counter } : { period: t.period }),
  }))
    if (value !== "" && value != null) p.set(key, value);
  return `otpauth://${t.type}/${encodeURIComponent(t.issuer ? t.issuer + ":" + t.name : t.name)}?${p}`;
}
export function parseUri(s, compatibility = false) {
  const u = new URL(s);
  if (
    u.protocol !== "otpauth:" ||
    !["totp", "hotp", "steam"].includes(u.hostname)
  )
    throw Error(
      "Supported URI types: TOTP, HOTP and Steam. Use Aegis for mOTP.",
    );
  const p = u.searchParams,
    label = decodeURIComponent(u.pathname.slice(1));
  if (p.has("encoder") && p.get("encoder") !== "steam")
    throw Error("Unsupported OTP encoder");
  if (
    p.get("encoder") === "steam" &&
    u.hostname !== "totp" &&
    u.hostname !== "steam"
  )
    throw Error("Steam encoder cannot be used with HOTP");
  const type = p.get("encoder") === "steam" ? "steam" : u.hostname;
  let issuer = p.get("issuer") || "",
    name = label;
  if (label.includes(":")) {
    const i = label.indexOf(":");
    if (!issuer) issuer = label.slice(0, i);
    if (label.slice(0, i) === issuer) name = label.slice(i + 1);
  }
  return normalize(
    {
      type,
      name,
      issuer,
      secret: p.get("secret"),
      algorithm: p.get("algorithm") || undefined,
      digits: p.get("digits") || undefined,
      period: p.get("period") || undefined,
      counter: p.get("counter"),
      extra: Object.fromEntries(p),
    },
    compatibility,
  );
}
export function parseText(s, compatibility = false) {
  const lines = s
    .trim()
    .split(/\r?\n|,(?=\s*otpauth:\/\/)/)
    .map((x) => x.trim())
    .filter(Boolean);
  if (!lines.length) throw Error("Empty file");
  return lines.map((x, i) => {
    try {
      return parseUri(x, compatibility);
    } catch (e) {
      throw Error(`Entry ${i + 1}: ${e.message}`);
    }
  });
}
export function inspect(text, compatibility = false) {
  text = text.replace(/^\uFEFF/, "").trim();
  if (!text) throw Error("Empty file");
  if (text.startsWith("otpauth://"))
    return { format: "Plaintext", tokens: parseText(text, compatibility) };
  if (text.startsWith("{")) {
    const data = JSON.parse(text);
    if (data.version !== 1) throw Error("Unsupported backup version");
    if (data.kdfParams && data.encryptedData)
      return { format: "Ente encrypted", data, locked: true };
    if (data.header && data.db)
      return typeof data.db === "string"
        ? { format: "Aegis encrypted", data, locked: true }
        : {
            format: "Aegis plaintext",
            tokens: readAegis(data.db, compatibility),
          };
    throw Error("Unrecognized JSON format");
  }
  const parseCsv = (source) =>
    Papa.parse(source, {
      header: true,
      skipEmptyLines: "greedy",
      transformHeader: (h) => h.trim().toLowerCase(),
    });
  const hasAuthyColumns = (parsed) =>
    ["name", "encrypted_seed", "salt", "iv"].every((h) =>
      parsed.meta.fields?.includes(h),
    );
  let result = parseCsv(text);
  if (!hasAuthyColumns(result)) {
    // Some exports encode each CSV record as one quoted CSV cell. Decode
    // that outer layer with a real parser, preserving escaped quotes and
    // embedded newlines; never strip quotes from ordinary CSV fields.
    const outer = Papa.parse(text, {
      delimiter: ",",
      skipEmptyLines: "greedy",
    });
    if (
      !outer.errors.length &&
      outer.data.length &&
      outer.data.every((row) => row.length === 1)
    ) {
      const nested = parseCsv(outer.data.map((row) => row[0]).join("\n"));
      if (hasAuthyColumns(nested)) result = nested;
    }
    // Retain support for the legacy extra quote pair around the whole file.
    if (!hasAuthyColumns(result) && text.startsWith('"') && text.endsWith('"'))
      result = parseCsv(text.slice(1, -1));
  }
  if (
    !["name", "encrypted_seed", "salt", "iv"].every((h) =>
      result.meta.fields?.includes(h),
    )
  )
    throw Error("Authy CSV requires name, encrypted_seed, salt, iv columns");
  if (result.errors.length)
    throw Error(`Invalid CSV: ${result.errors[0].message}`);
  if (!result.data.length || result.data.length > 5000)
    throw Error("CSV must contain between 1 and 5000 accounts");
  return { format: "Authy CSV", rows: result.data, locked: true };
}
/*! Authy GDPR: UTF-8 password and literal UTF-8 salt -> PBKDF2-HMAC-SHA1
 * (100,000 iterations, 32-byte key) -> AES-256-CBC (hex IV, Base64 ciphertext).
 * Web Crypto removes PKCS#7 padding. Decode Base32/hex/raw seed conservatively.
 * Successful CBC padding is not proof of a correct secret: compare live codes.
 */
export async function decryptAuthy(row, password, encoding = "auto") {
  const material = await crypto.subtle.importKey(
    "raw",
    bytes(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: bytes(row.salt),
      iterations: 100000,
      hash: "SHA-1",
    },
    material,
    { name: "AES-CBC", length: 256 },
    false,
    ["decrypt"],
  );
  let raw;
  try {
    raw = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-CBC", iv: unhex(row.iv.trim()) },
        key,
        unb64(row.encrypted_seed.trim()),
      ),
    );
  } catch {
    throw Error("Wrong password or damaged Authy data");
  }
  if (!raw.length) throw Error("Empty seed");
  let text = "";
  try {
    text = dec.decode(raw).trim();
  } catch {}
  const candidate = text.toUpperCase().replace(/=+$/, "");
  let secret,
    ambiguous = false;
  if (encoding === "hex") {
    secret = base32(unhex(text));
  } else if (encoding === "raw") {
    secret = base32(raw);
  } else if (/^[A-Z2-7]+$/.test(candidate)) {
    secret = candidate;
    ambiguous = /^(?:[0-9a-f]{2})+$/i.test(text);
  } else if (/^(?:[0-9a-f]{2})+$/i.test(text)) {
    secret = base32(unhex(text));
  } else {
    secret = base32(raw);
  }
  raw.fill(0);
  return normalize({
    name: row.name,
    secret,
    ambiguous,
    source: "Authy",
    note: "Authy defaults: SHA1 / 6 digits / 30 s; verify against the original.",
  });
}
async function enteKey(p, password) {
  const memory = integer(p.memLimit, 8192, 1073741824, "Argon2 memory (bytes)");
  integer(p.opsLimit, 1, 20, "Argon2 iterations");
  const salt = unb64(p.salt);
  if (salt.length !== 16) throw Error("Invalid Ente salt");
  return argon2id({
    password: bytes(password),
    salt,
    parallelism: 1,
    iterations: p.opsLimit,
    memorySize: Math.floor(memory / 1024),
    hashLength: 32,
    outputType: "binary",
  });
}
/*! Ente v1: Argon2id derives a 32-byte key, then sodium secretstream encrypts
 * newline-separated otpauth URIs. A FINAL tag is required when reading a backup.
 */
export async function exportEnte(tokens, password) {
  assertExportable(tokens, "ente");
  await sodium.ready;
  const kdfParams = { memLimit: 67108864, opsLimit: 3, salt: b64(random(16)) };
  const key = await enteKey(kdfParams, password);
  try {
    const state = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
    const ciphertext = sodium.crypto_secretstream_xchacha20poly1305_push(
      state.state,
      bytes(tokens.map(uri).join("\n")),
      null,
      sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL,
    );
    return {
      version: 1,
      kdfParams,
      encryptedData: b64(ciphertext),
      encryptionNonce: b64(state.header),
    };
  } finally {
    key.fill(0);
  }
}
export async function importEnte(data, password, compatibility = false) {
  if (data.version !== 1) throw Error("Unsupported Ente version");
  await sodium.ready;
  const key = await enteKey(data.kdfParams, password);
  try {
    const header = unb64(data.encryptionNonce);
    if (header.length !== 24) throw Error("Invalid Ente header");
    const state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(
      header,
      key,
    );
    const out = sodium.crypto_secretstream_xchacha20poly1305_pull(
      state,
      unb64(data.encryptedData),
    );
    if (
      !out ||
      out.tag !== sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
    )
      throw Error("Wrong password, incomplete or damaged backup");
    try {
      return parseText(dec.decode(out.message), compatibility);
    } finally {
      out.message.fill(0);
    }
  } finally {
    key.fill(0);
  }
}
async function gcmEncrypt(key, plain) {
  const nonce = random(12),
    k = await crypto.subtle.importKey("raw", key, "AES-GCM", false, [
      "encrypt",
    ]);
  const out = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, k, plain),
  );
  return {
    body: out.slice(0, -16),
    params: { nonce: hex(nonce), tag: hex(out.slice(-16)) },
  };
}
async function gcmDecrypt(key, cipher, params) {
  const nonce = unhex(params.nonce),
    tag = unhex(params.tag);
  if (nonce.length !== 12 || tag.length !== 16)
    throw Error("Invalid AES-GCM parameters");
  const k = await crypto.subtle.importKey("raw", key, "AES-GCM", false, [
    "decrypt",
  ]);
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      k,
      join(cipher, tag),
    ),
  );
}
async function aegisKey(slot, password) {
  integer(slot.n, 2, 1048576, "scrypt N");
  if ((slot.n & (slot.n - 1)) !== 0) throw Error("Invalid scrypt N");
  integer(slot.r, 1, 32, "scrypt r");
  integer(slot.p, 1, 16, "scrypt p");
  if (128 * slot.n * slot.r > 1073741824 || slot.n * slot.r * slot.p > 16777216)
    throw Error("Excessive scrypt cost");
  return scrypt({
    password: bytes(password),
    salt: unhex(slot.salt),
    costFactor: slot.n,
    blockSize: slot.r,
    parallelism: slot.p,
    hashLength: 32,
    outputType: "binary",
  });
}
export function readAegis(db, compatibility = false) {
  if (![1, 2, 3].includes(db.version) || !Array.isArray(db.entries))
    throw Error("Unsupported Aegis database");
  return db.entries.map((e, i) => {
    try {
      return normalize(
        {
          name: e.name,
          issuer: e.issuer,
          type: e.type,
          secret: e.info.secret,
          algorithm: e.info.algo,
          digits: e.info.digits,
          period: e.info.period,
          counter: e.info.counter,
          pin: e.info.pin,
          note: e.note,
          aegisEntry: e,
          aegisGroups: db.groups || [],
        },
        compatibility,
      );
    } catch (err) {
      throw Error(`Aegis entry ${i + 1}: ${err.message}. No entries imported.`);
    }
  });
}
export function aegisDb(tokens) {
  tokens = tokens.map((t) => normalize(t, true));
  const groups = new Map();
  for (const t of tokens)
    for (const g of t.aegisGroups || []) groups.set(g.uuid, g);
  return {
    version: 3,
    groups: [...groups.values()],
    entries: tokens.map((t) => ({
      ...t.aegisEntry,
      type: t.type,
      uuid: t.aegisEntry?.uuid || crypto.randomUUID(),
      name: t.name,
      issuer: t.issuer,
      note: t.note || "",
      icon: t.aegisEntry?.icon || null,
      favorite: t.aegisEntry?.favorite || false,
      groups: t.aegisEntry?.groups || [],
      info: {
        secret: t.secret,
        algo: t.algorithm,
        digits: t.digits,
        ...(t.type === "hotp" ? { counter: t.counter } : { period: t.period }),
        ...(t.type === "motp" ? { pin: t.pin } : {}),
      },
    })),
  };
}
/*! Aegis: scrypt derives the password wrapping key. AES-GCM wraps a random
 * master key and encrypts the JSON vault separately, with independent nonces.
 * The master key, not the password key, encrypts the token database.
 */
export async function exportAegis(tokens, password) {
  const master = random(32),
    slot = {
      type: 1,
      uuid: crypto.randomUUID(),
      n: 32768,
      r: 8,
      p: 1,
      salt: hex(random(32)),
    };
  const key = await aegisKey(slot, password);
  try {
    const wrapped = await gcmEncrypt(key, master),
      db = await gcmEncrypt(master, bytes(JSON.stringify(aegisDb(tokens))));
    return {
      version: 1,
      header: {
        slots: [
          { ...slot, key: hex(wrapped.body), key_params: wrapped.params },
        ],
        params: db.params,
      },
      db: b64(db.body),
    };
  } finally {
    master.fill(0);
    key.fill(0);
  }
}
export async function importAegis(data, password, compatibility = false) {
  if (data.version !== 1) throw Error("Unsupported Aegis version");
  if (typeof data.db !== "string") return readAegis(data.db, compatibility);
  const slots = data.header.slots.filter((s) => s.type === 1);
  if (!slots.length || slots.length > 10)
    throw Error("Backup has no supported password slots (or too many slots)");
  let master;
  for (const slot of slots) {
    const key = await aegisKey(slot, password);
    try {
      master = await gcmDecrypt(key, unhex(slot.key), slot.key_params);
      break;
    } catch {
    } finally {
      key.fill(0);
    }
  }
  if (!master) throw Error("Wrong password or damaged Aegis backup");
  try {
    const raw = await gcmDecrypt(master, unb64(data.db), data.header.params);
    try {
      return readAegis(JSON.parse(dec.decode(raw)), compatibility);
    } finally {
      raw.fill(0);
    }
  } finally {
    master.fill(0);
  }
}
/*! RFC 6238: floor(unixSeconds/period) as an 8-byte big-endian counter,
 * HMAC with the decoded secret, dynamic truncation, modulo 10^digits.
 * Passing the next period boundary yields the next code without changing the clock.
 */
export async function totp(t, time = Date.now()) {
  t = normalize(t, true);
  // mOTP uses hexadecimal secret bytes and the literal four-digit PIN, not HMAC.
  if (t.type === "motp")
    return (
      await md5(
        String(Math.floor(time / 1000 / t.period)) +
          hex(fromBase32(t.secret)) +
          t.pin,
      )
    ).slice(0, 6);
  const counter = BigInt(
    t.type === "hotp" ? t.counter : Math.floor(time / 1000 / t.period),
  );
  const buf = new ArrayBuffer(8);
  new DataView(buf).setBigUint64(0, counter);
  const k = await crypto.subtle.importKey(
    "raw",
    fromBase32(t.secret),
    { name: "HMAC", hash: t.algorithm.replace("SHA", "SHA-") },
    false,
    ["sign"],
  );
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", k, buf)),
    i = h[h.length - 1] & 15;
  const n =
    ((h[i] & 127) << 24) | (h[i + 1] << 16) | (h[i + 2] << 8) | h[i + 3];
  if (t.type === "steam") {
    const alphabet = "23456789BCDFGHJKMNPQRTVWXY";
    let value = n,
      result = "";
    for (let i = 0; i < 5; i++) {
      result += alphabet[value % alphabet.length];
      value = Math.floor(value / alphabet.length);
    }
    return result;
  }
  return String(n % 10 ** t.digits).padStart(t.digits, "0");
}
