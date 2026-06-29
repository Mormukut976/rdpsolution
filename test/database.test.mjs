import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { audit, cleanupExpiredData, createDatabase, parseJson } from "../src/db.mjs";

test("database initializes strict schema and cascades host applications", () => {
  const db = createDatabase(":memory:");
  const now = Date.now();
  const hostId = randomUUID();
  const applicationId = randomUUID();

  db.prepare(`
    INSERT INTO hosts (id, name, hostname, created_at, updated_at)
    VALUES (?, 'Test RDS', '10.0.0.2', ?, ?)
  `).run(hostId, now, now);
  db.prepare(`
    INSERT INTO applications (id, host_id, name, created_at, updated_at)
    VALUES (?, ?, 'Desktop', ?, ?)
  `).run(applicationId, hostId, now, now);

  db.prepare("DELETE FROM hosts WHERE id = ?").run(hostId);
  assert.equal(
    db.prepare("SELECT COUNT(*) AS count FROM applications").get().count,
    0,
  );
  db.close();
});

test("cleanup expires sessions and marks stale agents offline", () => {
  const db = createDatabase(":memory:");
  const now = Date.now();
  const userId = randomUUID();
  const hostId = randomUUID();

  db.prepare(`
    INSERT INTO users (
      id, email, display_name, password_hash, role, created_at, updated_at
    ) VALUES (?, 'test@example.test', 'Test', 'hash', 'admin', ?, ?)
  `).run(userId, now, now);
  db.prepare(`
    INSERT INTO sessions (
      token_hash, user_id, csrf_token, expires_at, last_seen_at
    ) VALUES ('expired', ?, 'csrf', ?, ?)
  `).run(userId, now - 1, now - 10_000);
  db.prepare(`
    INSERT INTO hosts (
      id, name, hostname, agent_status, last_seen_at, created_at, updated_at
    ) VALUES (?, 'Stale', '10.0.0.3', 'online', ?, ?, ?)
  `).run(hostId, now - 180_000, now, now);

  cleanupExpiredData(db);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM sessions").get().count, 0);
  assert.equal(
    db.prepare("SELECT agent_status FROM hosts WHERE id = ?").get(hostId).agent_status,
    "offline",
  );
  db.close();
});

test("audit events serialize structured details", () => {
  const db = createDatabase(":memory:");
  audit(db, {
    action: "test.event",
    targetType: "host",
    targetId: "host-1",
    detail: { safe: true },
    ip: "127.0.0.1",
  });
  const event = db.prepare("SELECT * FROM audit_events").get();
  assert.deepEqual(parseJson(event.detail_json), { safe: true });
  assert.deepEqual(parseJson("{broken", { fallback: true }), { fallback: true });
  db.close();
});
