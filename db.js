// Database layer: PostgreSQL when DATABASE_URL is set (e.g. on Render),
// otherwise a local SQLite file (data/members.db) for easy local development.

const path = require("path");
const fs = require("fs");

let impl;

if (process.env.DATABASE_URL) {
  const { Pool } = require("pg");
  const url = process.env.DATABASE_URL;
  const needsSsl = process.env.PGSSL === "true" || /\.render\.com/.test(url);
  const pool = new Pool({
    connectionString: url,
    ssl: needsSsl ? { rejectUnauthorized: false } : undefined,
  });

  impl = {
    kind: "postgres",
    async init() {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS members (
          id            SERIAL PRIMARY KEY,
          real_name     VARCHAR(60)  NOT NULL,
          phone         VARCHAR(10)  NOT NULL UNIQUE,
          password_hash TEXT         NOT NULL,
          created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        )`);
    },
    async createMember({ name, phone, passwordHash }) {
      const { rows } = await pool.query(
        `INSERT INTO members (real_name, phone, password_hash)
         VALUES ($1, $2, $3)
         RETURNING id, real_name AS name, phone, created_at`,
        [name, phone, passwordHash]
      );
      return rows[0];
    },
    async findByPhone(phone) {
      const { rows } = await pool.query(
        `SELECT id, real_name AS name, phone, password_hash FROM members WHERE phone = $1`,
        [phone]
      );
      return rows[0] || null;
    },
    async findById(id) {
      const { rows } = await pool.query(
        `SELECT id, real_name AS name, phone FROM members WHERE id = $1`,
        [id]
      );
      return rows[0] || null;
    },
    async listMembers() {
      const { rows } = await pool.query(
        `SELECT id, real_name AS name, phone, created_at FROM members ORDER BY id ASC`
      );
      return rows;
    },
    isUniqueViolation: (err) => err && err.code === "23505",
  };
} else {
  const Database = require("better-sqlite3");
  const dir = path.join(__dirname, "data");
  fs.mkdirSync(dir, { recursive: true });
  const db = new Database(process.env.SQLITE_PATH || path.join(dir, "members.db"));
  db.pragma("journal_mode = WAL");

  impl = {
    kind: "sqlite",
    async init() {
      db.exec(`
        CREATE TABLE IF NOT EXISTS members (
          id            INTEGER PRIMARY KEY AUTOINCREMENT,
          real_name     TEXT NOT NULL,
          phone         TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          created_at    TEXT NOT NULL DEFAULT (datetime('now'))
        )`);
    },
    async createMember({ name, phone, passwordHash }) {
      const info = db
        .prepare(`INSERT INTO members (real_name, phone, password_hash) VALUES (?, ?, ?)`)
        .run(name, phone, passwordHash);
      return db
        .prepare(`SELECT id, real_name AS name, phone, created_at FROM members WHERE id = ?`)
        .get(info.lastInsertRowid);
    },
    async findByPhone(phone) {
      return (
        db
          .prepare(`SELECT id, real_name AS name, phone, password_hash FROM members WHERE phone = ?`)
          .get(phone) || null
      );
    },
    async findById(id) {
      return (
        db.prepare(`SELECT id, real_name AS name, phone FROM members WHERE id = ?`).get(id) || null
      );
    },
    async listMembers() {
      return db
        .prepare(`SELECT id, real_name AS name, phone, created_at FROM members ORDER BY id ASC`)
        .all();
    },
    isUniqueViolation: (err) => err && /UNIQUE constraint failed/i.test(err.message || ""),
  };
}

module.exports = impl;
