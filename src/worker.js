import { inspectKdbx, importKdbx, exportKdbx } from "./kdbx.js";
import {
  inspect,
  decryptAuthy,
  importEnte,
  importAegis,
  exportEnte,
  exportAegis,
} from "./core.js";
self.onmessage = async ({ data: { id, op, args } }) => {
  try {
    let result;
    if (op === "kdbx-inspect") result = inspectKdbx(...args);
    else if (op === "kdbx-in") result = await importKdbx(...args);
    else if (op === "kdbx-out") result = await exportKdbx(...args);
    else if (op === "inspect") result = inspect(...args);
    else if (op === "authy") result = await decryptAuthy(...args);
    else if (op === "ente-in") result = await importEnte(...args);
    else if (op === "aegis-in") result = await importAegis(...args);
    else if (op === "ente-out") result = await exportEnte(...args);
    else if (op === "aegis-out") result = await exportAegis(...args);
    else throw Error("Invalid operation");
    self.postMessage({ id, result });
  } catch (e) {
    self.postMessage({ id, error: e.message || "Operation failed" });
  }
};
