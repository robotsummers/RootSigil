import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";

const sqlitePath = process.env.SQLITE_PATH || "./skill_attestor.sqlite";
const migrationsDir = new URL("../migrations/", import.meta.url);

fs.mkdirSync(path.dirname(sqlitePath), { recursive: true });
const db = new Database(sqlitePath);

const migrationFiles = fs
  .readdirSync(migrationsDir)
  .filter((f) => f.endsWith(".sql"))
  .sort();

for (const file of migrationFiles) {
  const sql = fs.readFileSync(new URL(file, migrationsDir), "utf8");
  db.exec(sql);
}

console.log(`Applied ${migrationFiles.length} migration(s) to ${sqlitePath}`);
