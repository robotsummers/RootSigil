import Database from "better-sqlite3";

export type SqliteDb = Database.Database;

export function openDb(sqlitePath: string): SqliteDb {
  const db = new Database(sqlitePath);
  db.pragma("journal_mode = WAL");
  return db;
}
