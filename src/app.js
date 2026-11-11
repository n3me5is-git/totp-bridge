/*! TOTP Bridge UI: secrets are kept in memory only. No storage or network calls.
 * Expensive KDF/decryption work is delegated to the embedded worker.
 * generation invalidates in-flight work after reset; passwords are cleared after use.
 */
import QRCode from "qrcode";
import {
  normalize,
  uri,
  totp,
  assertExportable,
  hex,
  fromBase32,
} from "./core.js";
const $ = (id) => document.getElementById(id);
let worker,
  jobs = new Map(),
  jobId = 0,
  entries = [],
  backup = null,
  selected = new Set(),
  busy = false,
  generation = 0,
  active = null,
  hideTimer,
  tickTimer;
let pendingKey = null,
  otpActive = null,
  otpTimer,
  otpHideTimer,
  otpEpoch = 0;
/*! Quick OTP view exposes current/next codes for 30 seconds, never the setup key.
 * Both values use one time snapshot to avoid mixing periods at rollover.
 */
function hideOtp() {
  otpEpoch++;
  clearInterval(otpTimer);
  clearTimeout(otpHideTimer);
  otpActive = null;
  $("otpDialog").close();
  $("otpCurrent").textContent = "";
  $("otpNext").textContent = "";
  $("otpCountdown").textContent = "";
  $("otpTitle").textContent = "";
}
function cancelReveal() {
  pendingKey = null;
  $("revealDialog").close();
}
function askReveal(i) {
  hideKey();
  hideOtp();
  pendingKey = i;
  $("revealDialog").showModal();
}
async function showOtp(i) {
  hideKey();
  hideOtp();
  cancelReveal();
  otpActive = i;
  const epoch = otpEpoch;
  const token = entries[i].token,
    expires = Date.now() + 30000;
  $("otpTitle").textContent = token.issuer
    ? `${token.issuer} · ${token.name}`
    : token.name;
  $("hotpAdvance").hidden = token.type !== "hotp";
  $("hotpAdvance").disabled = token.counter === Number.MAX_SAFE_INTEGER;
  $("otpNextLabel").textContent =
    token.type === "hotp"
      ? "Next counter preview — not consumed automatically"
      : "Next code — wait until the next period before using it";
  $("otpUsage").textContent =
    token.type === "hotp"
      ? "Viewing does not advance the counter. After using a code, advance once and export the updated backup before closing."
      : "Codes hide after 30 seconds or when you switch tabs. The setup key is not displayed.";
  $("otpDialog").showModal();
  const tick = async () => {
    try {
      const now = Date.now(),
        boundary =
          (Math.floor(now / 1000 / token.period) + 1) * token.period * 1000;
      const [current, next] = await Promise.all([
        totp(token, now),
        token.type === "hotp"
          ? token.counter < Number.MAX_SAFE_INTEGER
            ? totp({ ...token, counter: token.counter + 1 })
            : Promise.resolve("Counter limit reached")
          : totp(token, boundary),
      ]);
      if (otpActive !== i || otpEpoch !== epoch) return;
      $("otpCurrent").textContent = current;
      $("otpNext").textContent = next;
      $("otpCountdown").textContent =
        `${token.type === "hotp" ? `Counter ${token.counter} · ` : `Next code valid in ${Math.ceil((boundary - now) / 1000)}s · `}Hidden in ${Math.max(0, Math.ceil((expires - now) / 1000))}s`;
    } catch {
      hideOtp();
      status("Unable to generate OTP codes.", true);
    }
  };
  await tick();
  if (otpActive !== i || otpEpoch !== epoch) return;
  otpTimer = setInterval(tick, 1000);
  otpHideTimer = setTimeout(hideOtp, Math.max(0, expires - Date.now()));
}
$("revealCancel").onclick = cancelReveal;
$("revealConfirm").onclick = () => {
  const i = pendingKey;
  cancelReveal();
  if (i !== null) showKey(i).catch((e) => status(e.message, true));
};
$("revealDialog").addEventListener("cancel", (e) => {
  e.preventDefault();
  cancelReveal();
});
$("hotpAdvance").onclick = () => {
  const i = otpActive;
  if (i === null) return;
  try {
    const t = entries[i].token;
    entries[i].token = normalize({ ...t, counter: t.counter + 1 }, true);
    render();
    status(
      "HOTP counter advanced in memory. Export an updated backup before closing.",
    );
    showOtp(i).catch((e) => status(e.message, true));
  } catch (e) {
    status(e.message, true);
  }
};
$("otpClose").onclick = hideOtp;
$("otpDialog").addEventListener("cancel", (e) => {
  e.preventDefault();
  hideOtp();
});
const workerUrl = URL.createObjectURL(
  new Blob([$("crypto-worker").textContent], { type: "text/javascript" }),
);
function startWorker() {
  worker = new Worker(workerUrl);
  worker.onmessage = ({ data }) => {
    const job = jobs.get(data.id);
    if (job) {
      jobs.delete(data.id);
      data.error ? job.reject(Error(data.error)) : job.resolve(data.result);
    }
  };
  worker.onerror = () => {
    for (const job of jobs.values())
      job.reject(
        Error(
          "Cryptographic engine unavailable or insufficient memory. Try a current browser.",
        ),
      );
    jobs.clear();
  };
}
startWorker();
function call(op, ...args) {
  return new Promise((resolve, reject) => {
    const id = ++jobId;
    jobs.set(id, { resolve, reject });
    worker.postMessage({ id, op, args });
  });
}
function status(message, error = false) {
  $("status").textContent = message;
  $("status").classList.toggle("error", error);
}
function setBusy(value) {
  busy = value;
  document.body.classList.toggle("busy", value);
  for (const el of document.querySelectorAll(
    "#unlockForm button,#download,#file,#demo,#compatibility",
  ))
    el.disabled = value;
  if ($("exportDialog").open) $("format").onchange();
  render();
}
function hideKey() {
  clearTimeout(hideTimer);
  clearInterval(tickTimer);
  active = null;
  $("keyDialog").close();
  $("secret").value = "";
  $("motpPin").value = "";
  $("code").textContent = "";
  $("keyTitle").textContent = "";
  $("keyNote").textContent = "";
  const c = $("qr");
  c.getContext("2d").clearRect(0, 0, c.width, c.height);
}
function closeExport() {
  $("exportDialog").close();
  $("newPassword").value = "";
  $("confirmPassword").value = "";
  $("plainConfirm").checked = false;
}
/*! Reset terminates the worker and drops UI references. JS does not promise secure erasure. */
function reset() {
  generation++;
  worker.terminate();
  for (const job of jobs.values()) job.reject(Error("Session cleared"));
  jobs.clear();
  startWorker();
  entries = [];
  backup = null;
  selected.clear();
  hideKey();
  hideOtp();
  cancelReveal();
  closeExport();
  $("password").value = "";
  $("file").value = "";
  $("search").value = "";
  $("fileInfo").hidden = true;
  $("unlockForm").hidden = true;
  $("encoding").value = "auto";
  setBusy(false);
  status("Session cleared. Ready to import.");
}
function el(tag, className, text) {
  const e = document.createElement(tag);
  if (className) e.className = className;
  if (text != null) e.textContent = text;
  return e;
}
function render() {
  const ready = entries.filter((e) => e.token);
  $("count").textContent = entries.length;
  $("empty").hidden = entries.length > 0 || !!backup;
  $("listTools").hidden = entries.length === 0;
  $("verify").hidden = ready.length === 0;
  $("exportOpen").disabled = busy || selected.size === 0;
  $("selectAll").checked = ready.length > 0 && selected.size === ready.length;
  $("selectAll").indeterminate =
    selected.size > 0 && selected.size < ready.length;
  const query = $("search").value.toLowerCase(),
    list = $("list");
  list.replaceChildren();
  for (const [i, e] of entries.entries()) {
    const t = e.token;
    if (!`${e.name} ${t?.issuer || ""}`.toLowerCase().includes(query)) continue;
    const row = el("div", "row" + (e.error ? " error" : ""));
    const check = el("input");
    check.type = "checkbox";
    check.checked = selected.has(i);
    check.disabled = !t || busy;
    check.setAttribute("aria-label", `Select ${e.name}`);
    check.onchange = () => {
      check.checked ? selected.add(i) : selected.delete(i);
      render();
    };
    row.append(
      check,
      el("div", "avatar", (t?.issuer || e.name || "?")[0].toUpperCase()),
    );
    const text = el("div", "rowmain");
    text.append(
      el("div", "rowname", t?.issuer ? `${t.issuer} · ${t.name}` : e.name),
      el(
        "div",
        "rowmeta",
        e.error ||
          (t
            ? `${t.type.toUpperCase()} · ${t.algorithm} · ${t.digits} ${["steam", "motp"].includes(t.type) ? "characters" : "digits"} · ${t.type === "hotp" ? `counter ${t.counter}` : `${t.period}s`}${t.ambiguous ? " · Ambiguous encoding: verify" : ""}`
            : "Encrypted · waiting for password"),
      ),
    );
    row.append(text);
    const button = el("button", "secondary", t ? "Show key ↗" : "Locked");
    button.disabled = !t || busy;
    button.onclick = () => askReveal(i);
    const otpButton = el("button", "secondary", "OTP");
    otpButton.setAttribute("aria-label", `Show OTP codes for ${e.name}`);
    otpButton.disabled = !t || busy;
    otpButton.onclick = () =>
      showOtp(i).catch((err) => status(err.message, true));
    row.append(otpButton, button);
    list.append(row);
  }
}
/*! Detect KDBX by its binary signature; text formats are identified by their contents. */
async function loadFile(file) {
  if (!file || busy) return;
  if (file.size > 10 * 1024 * 1024) {
    status("File too large: 10 MB limit.", true);
    return;
  }
  reset();
  const gen = generation;
  setBusy(true);
  status("Reading and identifying format…");
  try {
    const data = await file.arrayBuffer();
    const signature = new Uint8Array(data, 0, Math.min(8, data.byteLength));
    const isKdbx =
      signature.length === 8 &&
      [3, 217, 162, 154, 103, 251, 75, 181].every((v, i) => signature[i] === v);
    backup = await call(
      isKdbx ? "kdbx-inspect" : "inspect",
      isKdbx ? data : new TextDecoder().decode(data),
      $("compatibility").checked,
    );
    if (gen !== generation) return;
    $("fileInfo").hidden = false;
    $("fileInfo").textContent = `${file.name} · ${backup.format}`;
    if (backup.rows) {
      entries = backup.rows.map((r) => ({ name: r.name || "Account", row: r }));
    } else if (backup.tokens) {
      entries = backup.tokens.map((token) => ({ name: token.name, token }));
      entries.forEach((_, i) => selected.add(i));
    }
    $("unlockForm").hidden = !backup.locked;
    $("authyOptions").hidden = !backup.rows;
    $("passwordHelp").textContent = backup.rows
      ? "The password set in Authy → Accounts → Backups, not your sign-in password."
      : "The password used to create this encrypted backup. For unprotected KDBX, leave it empty.";
    status(
      backup.locked
        ? backup.rows
          ? `${entries.length} accounts found. Enter your Authy backup password.`
          : "Encrypted backup recognized. Accounts will appear after unlocking."
        : `${entries.length} accounts imported. Select the ones to export.`,
    );
  } catch (e) {
    if (gen === generation) {
      backup = null;
      status(e.message, true);
    }
  } finally {
    if (gen === generation) setBusy(false);
  }
}
$("file").onchange = (e) => loadFile(e.target.files[0]);
for (const name of ["dragenter", "dragover"])
  $("drop").addEventListener(name, (e) => {
    e.preventDefault();
    $("drop").classList.add("drag");
  });
for (const name of ["dragleave", "drop"])
  $("drop").addEventListener(name, (e) => {
    e.preventDefault();
    $("drop").classList.remove("drag");
  });
$("drop").addEventListener("drop", (e) => loadFile(e.dataTransfer.files[0]));
document.addEventListener("dragover", (e) => e.preventDefault());
document.addEventListener("drop", (e) => e.preventDefault());
$("reset").onclick = reset;
$("compatibility").onchange = () => {
  reset();
  status(
    $("compatibility").checked
      ? "Compatibility enabled: HOTP, Steam and mOTP. Select a backup."
      : "Standard TOTP mode. Select a backup.",
  );
};
$("search").oninput = render;
$("selectAll").onchange = (e) => {
  selected.clear();
  if (e.target.checked)
    entries.forEach((t, i) => {
      if (t.token) selected.add(i);
    });
  render();
};
$("unlockForm").onsubmit = async (e) => {
  e.preventDefault();
  if (busy || !backup) return;
  let password = $("password").value;
  if (!password && !backup.format.includes("KDBX")) {
    status("Enter the backup password.", true);
    return;
  }
  const gen = generation;
  setBusy(true);
  try {
    if (backup.rows) {
      for (let i = 0; i < entries.length; i++) {
        if (gen !== generation) return;
        status(`Decrypting account ${i + 1} of ${entries.length}…`);
        const entry = entries[i];
        try {
          const token = await call(
            "authy",
            entry.row,
            password,
            $("encoding").value,
          );
          if (gen !== generation) return;
          entry.token = token;
          delete entry.error;
          selected.add(i);
        } catch (err) {
          if (gen !== generation) return;
          entry.error = err.message;
          delete entry.token;
          selected.delete(i);
        }
        render();
      }
      const count = entries.filter((x) => x.token).length;
      status(
        `${count} of ${entries.length} accounts decrypted. ${count < entries.length ? "Failed entries remain visible; you can retry." : "Compare codes with Authy before migrating."}`,
        count < entries.length,
      );
    } else {
      status("Decrypting backup… (time depends on the file parameters)");
      const result = await call(
        backup.format.includes("KDBX")
          ? "kdbx-in"
          : backup.format.startsWith("Ente")
            ? "ente-in"
            : "aegis-in",
        backup.data,
        password,
        $("compatibility").checked,
      );
      const tokens = result.tokens || result;
      const skipped = result.skipped || 0;
      if (gen !== generation) return;
      entries = tokens.map((token) => ({ name: token.name, token }));
      selected = new Set(entries.map((_, i) => i));
      $("unlockForm").hidden = true;
      backup = null;
      status(
        `${entries.length} accounts decrypted. ${skipped} entries without supported OTP fields excluded. Ready to verify.`,
      );
    }
  } catch (err) {
    if (gen === generation)
      status(
        err.message === "The operation failed for an operation-specific reason"
          ? "Wrong password or damaged backup."
          : err.message,
        true,
      );
  } finally {
    password = "";
    $("password").value = "";
    if (gen === generation) setBusy(false);
  }
};
async function showKey(i) {
  hideKey();
  active = i;
  const token = entries[i].token;
  $("keyTitle").textContent = token.issuer
    ? `${token.issuer} · ${token.name}`
    : token.name;
  $("secret").value =
    token.type === "motp" ? hex(fromBase32(token.secret)) : token.secret;
  $("secretLabel").textContent =
    token.type === "motp"
      ? "mOTP secret (hexadecimal)"
      : "Original key in Base32";
  $("motpPinGroup").hidden = token.type !== "motp";
  $("motpPin").value = token.type === "motp" ? token.pin : "";
  $("qr").hidden = token.type === "motp";
  $("keyParameters").hidden = ["steam", "motp"].includes(token.type);
  $("counterGroup").hidden = token.type !== "hotp";
  $("counter").value = token.counter ?? 0;
  $("periodGroup").hidden = token.type === "hotp";
  $("keyQrHelp").textContent =
    token.type === "motp"
      ? "mOTP: secret and PIN are both required. No interoperable QR is offered; export an Aegis backup."
      : token.type === "steam"
        ? "Steam QR uses otpauth://steam. Scan only with a compatible app such as Ente; it is not a standard TOTP QR."
        : "This QR contains a reusable OTP secret. Do not share it.";
  $("algorithm").value = token.algorithm;
  $("digits").value = token.digits;
  $("period").value = token.period;
  $("keyNote").textContent = token.ambiguous
    ? "The seed could be Base32 or hexadecimal. Compare the original code; if needed, decrypt again with an explicit encoding."
    : token.note || "Check that the code matches the source app.";
  $("keyStatus").textContent = "";
  $("keyDialog").showModal();
  try {
    if (token.type !== "motp")
      await QRCode.toCanvas($("qr"), uri(token), {
        width: 256,
        margin: 4,
        errorCorrectionLevel: "M",
        color: { dark: "#152c21", light: "#ffffff" },
      });
    if (active !== i) return;
  } catch {
    hideKey();
    throw Error("QR too large: use backup export.");
  }
  const tick = async () => {
    try {
      const code = await totp(token);
      if (active === i) $("code").textContent = code;
    } catch {
      if (active === i) $("code").textContent = "—";
    }
  };
  await tick();
  tickTimer = setInterval(tick, 1000);
  hideTimer = setTimeout(hideKey, 60000);
}
$("keyClose").onclick = hideKey;
$("keyDialog").addEventListener("cancel", (e) => {
  e.preventDefault();
  hideKey();
});
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    hideKey();
    hideOtp();
    cancelReveal();
  }
});
$("copy").onclick = async () => {
  try {
    await navigator.clipboard.writeText($("secret").value);
    $("keyStatus").textContent =
      "Key copied. The clipboard remains outside app control.";
  } catch {
    $("secret").select();
    $("keyStatus").textContent = "Copy with Ctrl+C or the device copy command.";
  }
};
$("saveParams").onclick = () => {
  try {
    const i = active;
    entries[i].token = normalize(
      {
        ...entries[i].token,
        algorithm: $("algorithm").value,
        digits: Number($("digits").value),
        period: Number($("period").value),
        ...(entries[i].token.type === "hotp"
          ? { counter: $("counter").value }
          : {}),
      },
      $("compatibility").checked,
    );
    render();
    showKey(i).catch((e) => status(e.message, true));
  } catch (e) {
    $("keyStatus").textContent = e.message;
  }
};
$("exportOpen").onclick = () => {
  const failed = entries.filter((e) => !e.token).length;
  $("exportSummary").textContent =
    `Exporting ${selected.size} of ${entries.length} accounts.${failed ? ` ${failed} locked or invalid entries are excluded.` : ""}`;
  $("exportStatus").textContent = "";
  $("format").onchange();
  $("exportDialog").showModal();
};
$("exportClose").onclick = closeExport;
$("exportDialog").addEventListener("cancel", (e) => {
  e.preventDefault();
  closeExport();
});
$("format").onchange = () => {
  const plain = $("format").value === "plain";
  $("plainWarning").hidden = !plain;
  $("exportPasswords").hidden = plain;
  $("newPassword").required = !plain;
  $("confirmPassword").required = !plain;
  $("plainConfirm").required = plain;
  const tokens = [...selected].map((i) => entries[i].token);
  try {
    assertExportable(tokens, $("format").value);
    $("exportCompatibility").textContent = "";
    $("exportCompatibility").hidden = true;
    $("download").disabled = busy;
  } catch (e) {
    $("exportCompatibility").textContent = e.message;
    $("exportCompatibility").hidden = false;
    $("download").disabled = true;
  }
};
$("format").onchange();
$("exportForm").onsubmit = async (e) => {
  e.preventDefault();
  if (busy) return;
  const format = $("format").value;
  let password = $("newPassword").value;
  const tokens = [...selected].map((i) => entries[i].token);
  if (!tokens.length) return;
  if (format === "plain" && !$("plainConfirm").checked) return;
  if (
    format !== "plain" &&
    (password.length < 12 || password !== $("confirmPassword").value)
  ) {
    $("exportStatus").textContent =
      "Use at least 12 characters and two matching passwords.";
    return;
  }
  const gen = generation;
  setBusy(true);
  $("exportStatus").textContent = "Preparing backup…";
  try {
    assertExportable(tokens, format);
    let content;
    if (format === "plain") content = tokens.map(uri).join("\n") + "\n";
    else if (format === "kdbx")
      content = await call("kdbx-out", tokens, password);
    else
      content = JSON.stringify(
        await call(format + "-out", tokens, password),
        null,
        2,
      );
    if (gen !== generation) return;
    const url = URL.createObjectURL(
      new Blob([content], {
        type:
          format === "kdbx"
            ? "application/octet-stream"
            : format === "plain"
              ? "text/plain;charset=utf-8"
              : "application/json",
      }),
    );
    const a = el("a");
    a.href = url;
    a.download = `totp-bridge-${format}-${new Date().toISOString().slice(0, 10)}.${format === "kdbx" ? "kdbx" : format === "plain" ? "txt" : "json"}`;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10000);
    closeExport();
    status(
      `Backup ${format} prepared: ${tokens.length} accounts. Import it into your destination app and verify the codes.`,
    );
  } catch (err) {
    if (gen === generation) $("exportStatus").textContent = err.message;
  } finally {
    password = "";
    $("newPassword").value = "";
    $("confirmPassword").value = "";
    if (gen === generation) setBusy(false);
  }
};
$("demo").onclick = () => {
  reset();
  entries = [
    ["GitHub", "demo@example.com"],
    ["Google", "demo account"],
    ["Proton", "demo@proton.me"],
  ].map(([issuer, name]) => ({
    name,
    token: normalize({
      issuer,
      name,
      secret: "JBSWY3DPEHPK3PXP",
      note: "PUBLIC DEMO DATA — never use this key for a real account.",
    }),
  }));
  if ($("compatibility").checked)
    for (const type of ["hotp", "steam", "motp"])
      entries.push({
        name: `${type.toUpperCase()} demo`,
        token: normalize(
          {
            type,
            name: `${type.toUpperCase()} demo`,
            issuer: "Public demo",
            secret: "JBSWY3DPEHPK3PXP",
            ...(type === "hotp" ? { counter: 0 } : {}),
            ...(type === "motp" ? { pin: "0123" } : {}),
          },
          true,
        ),
      });
  selected = new Set(entries.map((_, i) => i));
  status(
    `Demo mode: ${entries.length} public dummy keys, not linked to real accounts.`,
  );
  render();
};
if (!crypto.subtle) {
  status(
    "Web Crypto unavailable. Open via HTTPS or localhost in a current browser.",
    true,
  );
  $("file").disabled = true;
  $("demo").disabled = true;
}
render();
