import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";

const sqlitePath = process.env.SQLITE_PATH || "./rootsigil.sqlite";
const migrationsDir = new URL("../migrations/", import.meta.url);

fs.mkdirSync(path.dirname(sqlitePath), { recursive: true });
const db = new Database(sqlitePath);
db.pragma("journal_mode = WAL");
db.exec(
  `CREATE TABLE IF NOT EXISTS schema_migrations (
    filename TEXT PRIMARY KEY,
    applied_at INTEGER NOT NULL
  )`
);

const migrationFiles = fs
  .readdirSync(migrationsDir)
  .filter((f) => f.endsWith(".sql"))
  .sort();

let applied = 0;
for (const file of migrationFiles) {
  const alreadyApplied = db.prepare(`SELECT 1 FROM schema_migrations WHERE filename=? LIMIT 1`).get(file);
  if (alreadyApplied) continue;

  const sql = fs.readFileSync(new URL(file, migrationsDir), "utf8");
  const tx = db.transaction(() => {
    db.exec(sql);
    db.prepare(`INSERT INTO schema_migrations (filename, applied_at) VALUES (?, ?)`).run(file, Date.now());
  });
  tx();
  applied += 1;
}

console.log(`Applied ${applied} migration(s) to ${sqlitePath}`);
