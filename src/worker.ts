import fs from "node:fs";
import { webcrypto } from "node:crypto";
import { loadConfig } from "./config.js";
import { openDb } from "./db/db.js";
import { loadPolicyFromFile } from "./lib/policy.js";
import { startWorkerLoop } from "./worker/scan-worker.js";

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto as any;
}

const config = loadConfig(process.env);
fs.mkdirSync(config.ARTIFACT_STORAGE_DIR, { recursive: true });

const db = openDb(config.SQLITE_PATH);
const policy = loadPolicyFromFile(config.POLICY_FILE);
startWorkerLoop({ config, db, policy });

console.log("RootSigil worker started");
