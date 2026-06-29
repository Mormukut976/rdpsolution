import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

const schema = `
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;
  PRAGMA busy_timeout = 5000;

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  ) STRICT;

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT
  ) STRICT;

  CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 3389,
    protocol TEXT NOT NULL DEFAULT 'rdp' CHECK (protocol IN ('rdp', 'vnc', 'ssh')),
    domain TEXT NOT NULL DEFAULT '',
    tls_mode TEXT NOT NULL DEFAULT 'verify' CHECK (tls_mode IN ('verify', 'ignore')),
    enabled INTEGER NOT NULL DEFAULT 1,
    agent_token_hash TEXT,
    agent_status TEXT NOT NULL DEFAULT 'unregistered'
      CHECK (agent_status IN ('unregistered', 'offline', 'online')),
    last_seen_at INTEGER,
    os_info TEXT,
    cpu_percent REAL,
    memory_percent REAL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  ) STRICT;

  CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    mode TEXT NOT NULL DEFAULT 'desktop' CHECK (mode IN ('desktop', 'remoteapp')),
    remote_app TEXT NOT NULL DEFAULT '',
    working_directory TEXT NOT NULL DEFAULT '',
    arguments TEXT NOT NULL DEFAULT '',
    icon TEXT NOT NULL DEFAULT 'monitor',
    enable_printing INTEGER NOT NULL DEFAULT 1,
    enable_file_transfer INTEGER NOT NULL DEFAULT 1,
    enable_audio INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  ) STRICT;

  CREATE TABLE IF NOT EXISTS application_assignments (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, application_id)
  ) STRICT;

  CREATE TABLE IF NOT EXISTS remote_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('issued', 'connected', 'ended', 'failed')),
    client_ip TEXT,
    started_at INTEGER NOT NULL,
    ended_at INTEGER
  ) STRICT;

  CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    detail_json TEXT NOT NULL DEFAULT '{}',
    ip_address TEXT,
    created_at INTEGER NOT NULL
  ) STRICT;

  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
  CREATE INDEX IF NOT EXISTS idx_apps_host ON applications(host_id);
  CREATE INDEX IF NOT EXISTS idx_assignments_user ON application_assignments(user_id);
  CREATE INDEX IF NOT EXISTS idx_remote_sessions_user ON remote_sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);
`;

export function createDatabase(databasePath) {
  if (databasePath !== ":memory:") {
    fs.mkdirSync(path.dirname(databasePath), { recursive: true });
  }

  const db = new DatabaseSync(databasePath);
  db.exec(schema);
  return db;
}

export function audit(
  db,
  { actorUserId = null, action, targetType = null, targetId = null, detail = {}, ip = null },
) {
  db.prepare(`
    INSERT INTO audit_events (
      actor_user_id, action, target_type, target_id, detail_json, ip_address, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    actorUserId,
    action,
    targetType,
    targetId,
    JSON.stringify(detail),
    ip,
    Date.now(),
  );
}

export function cleanupExpiredData(db) {
  const now = Date.now();
  db.prepare("DELETE FROM sessions WHERE expires_at < ?").run(now);
  db.prepare(`
    UPDATE hosts
       SET agent_status = 'offline'
     WHERE agent_status = 'online'
       AND (last_seen_at IS NULL OR last_seen_at < ?)
  `).run(now - 120_000);
}

export function parseJson(value, fallback = {}) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}
