import { webcrypto } from "node:crypto";
import fs from "node:fs";
import { loadConfig } from "./config.js";
import { openDb } from "./db/db.js";
import { loadPolicyFromFile } from "./lib/policy.js";
import { cleanupExpiredArtifacts } from "./lib/retention.js";
import { buildX402 } from "./payment/x402.js";
import { buildApp } from "./app.js";

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto as any;
}

const config = loadConfig(process.env);
fs.mkdirSync(config.ARTIFACT_STORAGE_DIR, { recursive: true });

const db = openDb(config.SQLITE_PATH);
try {
  const cleanup = cleanupExpiredArtifacts({
    db,
    artifact_storage_dir: config.ARTIFACT_STORAGE_DIR,
    artifact_retention_hours: config.ARTIFACT_RETENTION_HOURS
  });
  if (cleanup.removed > 0 || cleanup.skipped_outside_root > 0) {
    console.log(
      `Artifact cleanup checked=${cleanup.checked} removed=${cleanup.removed} skipped_outside_root=${cleanup.skipped_outside_root}`
    );
  }
} catch (e: any) {
  console.warn(`Artifact cleanup failed: ${String(e?.message || e)}`);
}
const policy = loadPolicyFromFile(config.POLICY_FILE);
const x402 = buildX402(config);

const app = buildApp({ config, db, policy, x402 });

app.listen(config.PORT, () => {
  console.log(`Skill Attestor listening on ${config.BASE_URL}`);
});
