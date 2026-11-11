/*! Passbolt/KeePass adapter. kdbxweb handles the container and encryption.
 * Accept both TimeOtp-* fields and protected otp URIs; export both for portability.
 * Only current TOTP entries are migrated, never login passwords or entry history.
 */
import kdbx from "kdbxweb";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";
import { argon2id, argon2d } from "hash-wasm";
import { normalize, parseUri, uri, assertExportable } from "./core.js";
// Workers have no native DOM. Provide the maintained XML implementation.
globalThis.DOMParser ??= DOMParser;
globalThis.XMLSerializer ??= XMLSerializer;
const credentials = (password) =>
  new kdbx.Credentials(
    password ? kdbx.ProtectedValue.fromString(password) : null,
  );
const field = (entry, key) => {
  const v = entry.fields.get(key);
  return typeof v === "string" ? v : v?.getText() || "";
};
function limit(n, min, max, label) {
  if (!Number.isSafeInteger(n) || n < min || n > max)
    throw Error(`KDBX: ${label} unsupported`);
  return n;
}
kdbx.CryptoEngine.setArgon2Impl(
  async (
    password,
    salt,
    memory,
    iterations,
    length,
    parallelism,
    type,
    version,
  ) => {
    if (version !== 0x13 || ![0, 2].includes(type))
      throw Error("KDBX: unsupported Argon2 version");
    limit(memory, 8, 1048576, "memory");
    limit(iterations, 1, 20, "iterations");
    limit(parallelism, 1, 16, "parallelism");
    return (type === 2 ? argon2id : argon2d)({
      password: new Uint8Array(password),
      salt: new Uint8Array(salt),
      memorySize: memory,
      iterations,
      parallelism,
      hashLength: length,
      outputType: "binary",
    });
  },
);
export function inspectKdbx(data) {
  const header = kdbx.KdbxHeader.read(new kdbx.BinaryStream(data), {});
  const rounds =
    header.versionMajor === 3
      ? header.keyEncryptionRounds
      : header.kdfParameters?.get("R")?.value;
  if (rounds !== undefined) limit(rounds, 1, 100000000, "AES-KDF iterations");
  return { format: "Passbolt / KeePass KDBX", data, locked: true };
}
export async function importKdbx(data, password, compatibility = false) {
  inspectKdbx(data);
  let db;
  try {
    db = await kdbx.Kdbx.load(data, credentials(password));
  } catch (e) {
    throw Error(
      `KDBX: wrong password, required keyfile, damaged file or unsupported parameters (${e.code || e.message}).`,
    );
  }
  const tokens = [];
  let skipped = 0;
  function visit(group) {
    if (db.meta.recycleBinUuid?.equals(group.uuid)) return;
    for (const entry of group.entries) {
      const otp = field(entry, "otp"),
        secret = field(entry, "TimeOtp-Secret-Base32"),
        hotpSecret = field(entry, "HmacOtp-Secret-Base32");
      const otherHotp = [
        "HmacOtp-Secret",
        "HmacOtp-Secret-Hex",
        "HmacOtp-Secret-Base64",
      ].some((key) => entry.fields.has(key));
      if (otherHotp)
        throw Error(
          "KDBX HOTP: only HmacOtp-Secret-Base32 is supported. Re-export as an otpauth URI or Aegis.",
        );
      if (hotpSecret && (otp || secret))
        throw Error(
          "KDBX entry has multiple OTP definitions. Separate them before importing.",
        );
      if (!otp && !secret && !hotpSecret) {
        skipped++;
        continue;
      }
      try {
        const token = otp
          ? parseUri(
              otp.startsWith("otpauth://") ? otp : decodeURIComponent(otp),
              compatibility,
            )
          : hotpSecret
            ? normalize(
                {
                  type: "hotp",
                  secret: hotpSecret,
                  counter: field(entry, "HmacOtp-Counter"),
                  name: field(entry, "UserName") || field(entry, "Title"),
                  issuer: field(entry, "Title"),
                },
                compatibility,
              )
            : normalize({
                secret,
                algorithm: (
                  field(entry, "TimeOtp-Algorithm") || "HMAC-SHA-1"
                ).replace(/^HMAC-/i, ""),
                digits: field(entry, "TimeOtp-Length") || 6,
                period: field(entry, "TimeOtp-Period") || 30,
                name: field(entry, "UserName") || field(entry, "Title"),
                issuer: field(entry, "Title"),
              });
        tokens.push({ ...token, source: "KDBX" });
      } catch (e) {
        throw Error(
          `KDBX entry ${field(entry, "Title") || tokens.length + 1}: ${e.message}. No entries imported.`,
        );
      }
    }
    for (const child of group.groups) visit(child);
  }
  for (const group of db.groups) visit(group);
  if (!tokens.length)
    throw Error(
      `No supported OTP in KDBX (${skipped} entries without supported OTP fields).`,
    );
  return { tokens, skipped };
}
export async function exportKdbx(tokens, password) {
  assertExportable(tokens, "kdbx");
  if (password.length < 12)
    throw Error("Use at least 12 characters for the KDBX backup");
  const db = kdbx.Kdbx.create(credentials(password), "TOTP Bridge");
  db.setVersion(3);
  db.header.keyEncryptionRounds = 600000;
  for (const raw of tokens) {
    const t = normalize(raw),
      entry = db.createEntry(db.getDefaultGroup());
    entry.fields.set("Title", t.issuer || t.name);
    entry.fields.set("UserName", t.name);
    entry.fields.set(
      "TimeOtp-Secret-Base32",
      kdbx.ProtectedValue.fromString(t.secret),
    );
    entry.fields.set(
      "TimeOtp-Algorithm",
      `HMAC-${t.algorithm.replace("SHA", "SHA-")}`,
    );
    entry.fields.set("TimeOtp-Length", String(t.digits));
    entry.fields.set("TimeOtp-Period", String(t.period));
    entry.fields.set("otp", kdbx.ProtectedValue.fromString(uri(t)));
  }
  return db.save();
}
