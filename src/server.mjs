import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { audit, cleanupExpiredData, createDatabase, parseJson } from "./db.mjs";
import { getConfig } from "./config.mjs";
import {
  buildOtpAuthUri,
  clearSessionCookie,
  generateTotpSecret,
  hashPassword,
  parseCookies,
  randomToken,
  sessionCookie,
  tokenHash,
  validatePassword,
  verifyPassword,
  verifyTotp,
} from "./security.mjs";
import {
  buildConnectionPayload,
  buildGuacamoleLaunchUrl,
  encryptGuacamolePayload,
  validateGuacamoleSecret,
} from "./guacamole.mjs";

const MIME_TYPES = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".webmanifest": "application/manifest+json",
};

class HttpError extends Error {
  constructor(status, message, code = "request_failed", details = undefined) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

class SlidingWindowLimiter {
  constructor({ limit, windowMs }) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.entries = new Map();
  }

  hit(key) {
    const now = Date.now();
    const minimum = now - this.windowMs;
    const attempts = (this.entries.get(key) || []).filter((timestamp) => timestamp > minimum);
    attempts.push(now);
    this.entries.set(key, attempts);
    return attempts.length <= this.limit;
  }

  clear(key) {
    this.entries.delete(key);
  }
}

function sendJson(response, status, payload, headers = {}) {
  const body = JSON.stringify(payload);
  response.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
    ...headers,
  });
  response.end(body);
}

function sendEmpty(response, status = 204, headers = {}) {
  response.writeHead(status, { "Cache-Control": "no-store", ...headers });
  response.end();
}

async function readJson(request, maxBytes = 128 * 1024) {
  const chunks = [];
  let length = 0;

  for await (const chunk of request) {
    length += chunk.length;
    if (length > maxBytes) throw new HttpError(413, "Request body is too large.");
    chunks.push(chunk);
  }

  if (length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "Request body must be valid JSON.");
  }
}

function stringValue(value, field, { min = 0, max = 255, trim = true } = {}) {
  if (typeof value !== "string") {
    throw new HttpError(400, `${field} must be a string.`, "validation_error");
  }
  const result = trim ? value.trim() : value;
  if (result.length < min || result.length > max) {
    throw new HttpError(
      400,
      `${field} must contain between ${min} and ${max} characters.`,
      "validation_error",
    );
  }
  return result;
}

function emailValue(value) {
  const email = stringValue(value, "Email", { min: 3, max: 254 }).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new HttpError(400, "Enter a valid email address.", "validation_error");
  }
  return email;
}

function integerValue(value, field, { min, max }) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
    throw new HttpError(
      400,
      `${field} must be an integer between ${min} and ${max}.`,
      "validation_error",
    );
  }
  return parsed;
}

function booleanValue(value, fallback = false) {
  return value === undefined ? fallback : Boolean(value);
}

function publicUser(row) {
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    role: row.role,
    status: row.status,
    totpEnabled: Boolean(row.totp_enabled),
    createdAt: row.created_at,
  };
}

function publicHost(row) {
  return {
    id: row.id,
    name: row.name,
    hostname: row.hostname,
    port: row.port,
    protocol: row.protocol,
    domain: row.domain,
    tlsMode: row.tls_mode,
    enabled: Boolean(row.enabled),
    agentStatus: row.agent_status,
    lastSeenAt: row.last_seen_at,
    osInfo: row.os_info,
    cpuPercent: row.cpu_percent,
    memoryPercent: row.memory_percent,
    metadata: parseJson(row.metadata_json),
    createdAt: row.created_at,
  };
}

function publicApplication(row) {
  return {
    id: row.id,
    hostId: row.host_id,
    hostName: row.host_name,
    hostStatus: row.agent_status,
    name: row.name,
    description: row.description,
    mode: row.mode,
    remoteApp: row.remote_app,
    workingDirectory: row.working_directory,
    arguments: row.arguments,
    icon: row.icon,
    enablePrinting: Boolean(row.enable_printing),
    enableFileTransfer: Boolean(row.enable_file_transfer),
    enableAudio: Boolean(row.enable_audio),
    enabled: Boolean(row.enabled),
    createdAt: row.created_at,
  };
}

function requestIp(request, config) {
  if (config.trustProxy) {
    const forwarded = request.headers["x-forwarded-for"];
    if (typeof forwarded === "string") return forwarded.split(",")[0].trim();
  }
  return request.socket.remoteAddress || "";
}

function applySecurityHeaders(response) {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Permissions-Policy", "camera=(), geolocation=(), microphone=()");
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; " +
      "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
  );
}

function matchPath(pathname, pattern) {
  const match = pathname.match(pattern);
  return match ? match.slice(1).map(decodeURIComponent) : null;
}

function parseBearerToken(request) {
  const authorization = request.headers.authorization || "";
  return authorization.startsWith("Bearer ") ? authorization.slice(7).trim() : "";
}

function hostInput(body, existing = null) {
  const protocol = body.protocol ?? existing?.protocol ?? "rdp";
  if (!["rdp", "vnc", "ssh"].includes(protocol)) {
    throw new HttpError(400, "Unsupported host protocol.", "validation_error");
  }
  const tlsMode = body.tlsMode ?? existing?.tls_mode ?? "verify";
  if (!["verify", "ignore"].includes(tlsMode)) {
    throw new HttpError(400, "TLS mode must be verify or ignore.", "validation_error");
  }

  return {
    name: stringValue(body.name ?? existing?.name, "Name", { min: 2, max: 80 }),
    hostname: stringValue(body.hostname ?? existing?.hostname, "Hostname", {
      min: 1,
      max: 255,
    }),
    port: integerValue(body.port ?? existing?.port ?? 3389, "Port", {
      min: 1,
      max: 65535,
    }),
    protocol,
    domain: stringValue(body.domain ?? existing?.domain ?? "", "Domain", { max: 255 }),
    tlsMode,
    enabled: booleanValue(body.enabled, existing ? Boolean(existing.enabled) : true),
  };
}

function applicationInput(body, existing = null) {
  const mode = body.mode ?? existing?.mode ?? "desktop";
  if (!["desktop", "remoteapp"].includes(mode)) {
    throw new HttpError(400, "Mode must be desktop or remoteapp.", "validation_error");
  }
  const remoteApp = stringValue(
    body.remoteApp ?? existing?.remote_app ?? "",
    "RemoteApp alias",
    { max: 255 },
  );
  if (mode === "remoteapp" && !remoteApp) {
    throw new HttpError(400, "RemoteApp alias is required.", "validation_error");
  }

  return {
    hostId: stringValue(body.hostId ?? existing?.host_id, "Host", { min: 1, max: 64 }),
    name: stringValue(body.name ?? existing?.name, "Name", { min: 2, max: 80 }),
    description: stringValue(
      body.description ?? existing?.description ?? "",
      "Description",
      { max: 500 },
    ),
    mode,
    remoteApp,
    workingDirectory: stringValue(
      body.workingDirectory ?? existing?.working_directory ?? "",
      "Working directory",
      { max: 500 },
    ),
    arguments: stringValue(body.arguments ?? existing?.arguments ?? "", "Arguments", {
      max: 1000,
      trim: false,
    }),
    icon: stringValue(body.icon ?? existing?.icon ?? "monitor", "Icon", {
      min: 2,
      max: 40,
    }),
    enablePrinting: booleanValue(
      body.enablePrinting,
      existing ? Boolean(existing.enable_printing) : true,
    ),
    enableFileTransfer: booleanValue(
      body.enableFileTransfer,
      existing ? Boolean(existing.enable_file_transfer) : true,
    ),
    enableAudio: booleanValue(
      body.enableAudio,
      existing ? Boolean(existing.enable_audio) : true,
    ),
    enabled: booleanValue(body.enabled, existing ? Boolean(existing.enabled) : true),
  };
}

export function createOpenRemoteServer(overrides = {}) {
  const config = getConfig(overrides);
  const db = createDatabase(config.databasePath);
  const loginLimiter = new SlidingWindowLimiter({ limit: 12, windowMs: 15 * 60_000 });
  const setupLimiter = new SlidingWindowLimiter({ limit: 5, windowMs: 60 * 60_000 });
  cleanupExpiredData(db);
  const cleanupTimer = setInterval(() => cleanupExpiredData(db), 60_000);
  cleanupTimer.unref();

  function loadSession(request) {
    const rawToken = parseCookies(request.headers.cookie).openremote_session;
    if (!rawToken) return null;

    const row = db.prepare(`
      SELECT s.token_hash, s.csrf_token, s.expires_at, s.last_seen_at,
             u.id, u.email, u.display_name, u.role, u.status, u.totp_enabled, u.created_at
        FROM sessions s
        JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ?
    `).get(tokenHash(rawToken));

    if (!row || row.expires_at < Date.now() || row.status !== "active") {
      if (row) db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(row.token_hash);
      return null;
    }

    if (row.last_seen_at < Date.now() - 60_000) {
      db.prepare("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?").run(
        Date.now(),
        row.token_hash,
      );
    }
    return { token: rawToken, tokenHash: row.token_hash, csrfToken: row.csrf_token, user: row };
  }

  function requireAuth(request) {
    const session = loadSession(request);
    if (!session) throw new HttpError(401, "Sign in to continue.", "authentication_required");
    return session;
  }

  function requireAdmin(request) {
    const session = requireAuth(request);
    if (session.user.role !== "admin") {
      throw new HttpError(403, "Administrator access is required.", "forbidden");
    }
    return session;
  }

  function requireCsrf(request, session) {
    const token = request.headers["x-csrf-token"];
    if (!token || token !== session.csrfToken) {
      throw new HttpError(403, "Security token is missing or invalid.", "csrf_failed");
    }
  }

  function ensureSameOrigin(request) {
    const origin = request.headers.origin;
    if (!origin) return;
    const expected = new URL(config.publicUrl).origin;
    if (origin !== expected) {
      throw new HttpError(403, "Cross-origin request rejected.", "origin_rejected");
    }
  }

  async function apiHandler(request, response, url) {
    const method = request.method;
    const pathname = url.pathname;
    const ip = requestIp(request, config);
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) ensureSameOrigin(request);

    if (method === "GET" && pathname === "/api/health") {
      return sendJson(response, 200, {
        status: "ok",
        version: "0.1.0",
        database: "connected",
        guacamoleConfigured: validateGuacamoleSecret(config.guacamoleJsonSecret),
        time: Date.now(),
      });
    }

    if (method === "GET" && pathname === "/api/setup/status") {
      const count = db.prepare("SELECT COUNT(*) AS count FROM users").get().count;
      return sendJson(response, 200, { setupRequired: count === 0 });
    }

    if (method === "POST" && pathname === "/api/setup") {
      if (!setupLimiter.hit(ip)) {
        throw new HttpError(429, "Too many setup attempts. Try again later.", "rate_limited");
      }
      const count = db.prepare("SELECT COUNT(*) AS count FROM users").get().count;
      if (count > 0) throw new HttpError(409, "Initial setup is already complete.");
      const body = await readJson(request);
      const email = emailValue(body.email);
      const displayName = stringValue(body.displayName, "Display name", { min: 2, max: 80 });
      const passwordErrors = validatePassword(body.password);
      if (passwordErrors.length) {
        throw new HttpError(400, passwordErrors.join(" "), "weak_password", passwordErrors);
      }
      const now = Date.now();
      const id = randomUUID();
      const passwordHash = await hashPassword(body.password);
      db.prepare(`
        INSERT INTO users (
          id, email, display_name, password_hash, role, status, created_at, updated_at
        ) VALUES (?, ?, ?, ?, 'admin', 'active', ?, ?)
      `).run(id, email, displayName, passwordHash, now, now);
      audit(db, {
        actorUserId: id,
        action: "system.setup_completed",
        targetType: "user",
        targetId: id,
        ip,
      });
      return sendJson(response, 201, { created: true });
    }

    if (method === "POST" && pathname === "/api/auth/login") {
      const limiterKey = `${ip}:login`;
      if (!loginLimiter.hit(limiterKey)) {
        throw new HttpError(429, "Too many login attempts. Try again later.", "rate_limited");
      }

      const body = await readJson(request);
      const email = emailValue(body.email);
      const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
      const validPassword = user ? await verifyPassword(body.password || "", user.password_hash) : false;

      if (!user || !validPassword) {
        if (user) {
          const failures = user.failed_logins + 1;
          const lockedUntil = failures >= 5 ? Date.now() + 15 * 60_000 : null;
          db.prepare(`
            UPDATE users SET failed_logins = ?, locked_until = ?, updated_at = ? WHERE id = ?
          `).run(failures >= 5 ? 0 : failures, lockedUntil, Date.now(), user.id);
        }
        audit(db, {
          action: "auth.login_failed",
          targetType: "user",
          targetId: user?.id || null,
          detail: { email },
          ip,
        });
        throw new HttpError(401, "Email or password is incorrect.", "invalid_credentials");
      }

      if (user.status !== "active") {
        throw new HttpError(403, "This account is disabled.", "account_disabled");
      }
      if (user.locked_until && user.locked_until > Date.now()) {
        throw new HttpError(423, "Account is temporarily locked. Try again later.", "account_locked");
      }
      if (user.totp_enabled && !verifyTotp(user.totp_secret, body.totp)) {
        throw new HttpError(401, "Enter a valid authenticator code.", "totp_required");
      }

      const rawToken = randomToken(32);
      const csrfToken = randomToken(24);
      const maxAgeSeconds = config.sessionHours * 60 * 60;
      db.prepare("DELETE FROM sessions WHERE user_id = ? AND expires_at < ?").run(
        user.id,
        Date.now(),
      );
      db.prepare(`
        INSERT INTO sessions (
          token_hash, user_id, csrf_token, expires_at, last_seen_at, ip_address, user_agent
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        tokenHash(rawToken),
        user.id,
        csrfToken,
        Date.now() + maxAgeSeconds * 1000,
        Date.now(),
        ip,
        String(request.headers["user-agent"] || "").slice(0, 500),
      );
      db.prepare(`
        UPDATE users SET failed_logins = 0, locked_until = NULL, updated_at = ? WHERE id = ?
      `).run(Date.now(), user.id);
      loginLimiter.clear(limiterKey);
      audit(db, {
        actorUserId: user.id,
        action: "auth.login_succeeded",
        targetType: "user",
        targetId: user.id,
        ip,
      });
      return sendJson(
        response,
        200,
        { user: publicUser(user), csrfToken },
        {
          "Set-Cookie": sessionCookie(rawToken, {
            secure: config.secureCookies,
            maxAgeSeconds,
          }),
        },
      );
    }

    if (method === "POST" && pathname === "/api/auth/logout") {
      const session = requireAuth(request);
      requireCsrf(request, session);
      db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(session.tokenHash);
      audit(db, {
        actorUserId: session.user.id,
        action: "auth.logout",
        targetType: "user",
        targetId: session.user.id,
        ip,
      });
      return sendEmpty(response, 204, {
        "Set-Cookie": clearSessionCookie({ secure: config.secureCookies }),
      });
    }

    if (method === "GET" && pathname === "/api/me") {
      const session = requireAuth(request);
      return sendJson(response, 200, {
        user: publicUser(session.user),
        csrfToken: session.csrfToken,
      });
    }

    if (method === "GET" && pathname === "/api/dashboard") {
      const session = requireAuth(request);
      if (session.user.role === "admin") {
        const stats = db.prepare(`
          SELECT
            (SELECT COUNT(*) FROM users WHERE status = 'active') AS users,
            (SELECT COUNT(*) FROM hosts WHERE enabled = 1) AS hosts,
            (SELECT COUNT(*) FROM hosts WHERE agent_status = 'online') AS online_hosts,
            (SELECT COUNT(*) FROM applications WHERE enabled = 1) AS applications,
            (SELECT COUNT(*) FROM remote_sessions WHERE started_at > ?) AS sessions_today
        `).get(new Date().setHours(0, 0, 0, 0));
        const recent = db.prepare(`
          SELECT rs.id, rs.status, rs.started_at, rs.ended_at,
                 u.display_name AS user_name, a.name AS application_name, h.name AS host_name
            FROM remote_sessions rs
            JOIN users u ON u.id = rs.user_id
            JOIN applications a ON a.id = rs.application_id
            JOIN hosts h ON h.id = rs.host_id
           ORDER BY rs.started_at DESC LIMIT 8
        `).all();
        return sendJson(response, 200, {
          stats: {
            users: stats.users,
            hosts: stats.hosts,
            onlineHosts: stats.online_hosts,
            applications: stats.applications,
            sessionsToday: stats.sessions_today,
          },
          recentSessions: recent.map((row) => ({
            id: row.id,
            status: row.status,
            startedAt: row.started_at,
            endedAt: row.ended_at,
            userName: row.user_name,
            applicationName: row.application_name,
            hostName: row.host_name,
          })),
        });
      }
      const assigned = db.prepare(`
        SELECT COUNT(*) AS count
          FROM application_assignments aa
          JOIN applications a ON a.id = aa.application_id
         WHERE aa.user_id = ? AND a.enabled = 1
      `).get(session.user.id).count;
      const recent = db.prepare(`
        SELECT rs.id, rs.status, rs.started_at, rs.ended_at,
               a.name AS application_name, h.name AS host_name
          FROM remote_sessions rs
          JOIN applications a ON a.id = rs.application_id
          JOIN hosts h ON h.id = rs.host_id
         WHERE rs.user_id = ?
         ORDER BY rs.started_at DESC LIMIT 8
      `).all(session.user.id);
      return sendJson(response, 200, {
        stats: { applications: assigned, sessionsToday: recent.length },
        recentSessions: recent.map((row) => ({
          id: row.id,
          status: row.status,
          startedAt: row.started_at,
          endedAt: row.ended_at,
          applicationName: row.application_name,
          hostName: row.host_name,
        })),
      });
    }

    if (method === "GET" && pathname === "/api/hosts") {
      requireAdmin(request);
      const hosts = db.prepare("SELECT * FROM hosts ORDER BY name COLLATE NOCASE").all();
      return sendJson(response, 200, { hosts: hosts.map(publicHost) });
    }

    if (method === "POST" && pathname === "/api/hosts") {
      const session = requireAdmin(request);
      requireCsrf(request, session);
      const input = hostInput(await readJson(request));
      const id = randomUUID();
      const now = Date.now();
      db.prepare(`
        INSERT INTO hosts (
          id, name, hostname, port, protocol, domain, tls_mode, enabled, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        input.name,
        input.hostname,
        input.port,
        input.protocol,
        input.domain,
        input.tlsMode,
        Number(input.enabled),
        now,
        now,
      );
      audit(db, {
        actorUserId: session.user.id,
        action: "host.created",
        targetType: "host",
        targetId: id,
        detail: { name: input.name, hostname: input.hostname },
        ip,
      });
      return sendJson(response, 201, { host: publicHost(db.prepare("SELECT * FROM hosts WHERE id = ?").get(id)) });
    }

    let params = matchPath(pathname, /^\/api\/hosts\/([^/]+)$/);
    if (params && method === "PUT") {
      const session = requireAdmin(request);
      requireCsrf(request, session);
      const existing = db.prepare("SELECT * FROM hosts WHERE id = ?").get(params[0]);
      if (!existing) throw new HttpError(404, "Host not found.");
      const input = hostInput(await readJson(request), existing);
      db.prepare(`
        UPDATE hosts SET
          name = ?, hostname = ?, port = ?, protocol = ?, domain = ?,
          tls_mode = ?, enabled = ?, updated_at = ?
        WHERE id = ?
      `).run(
        input.name,
        input.hostname,
        input.port,
        input.protocol,
        input.domain,
        input.tlsMode,
        Number(input.enabled),
        Date.now(),
        existing.id,
      );
      audit(db, {
        actorUserId: session.user.id,
        action: "host.updated",
        targetType: "host",
        targetId: existing.id,
        detail: { name: input.name },
        ip,
      });
      return sendJson(response, 200, {
        host: publicHost(db.prepare("SELECT * FROM hosts WHERE id = ?").get(existing.id)),
      });
    }

    if (params && method === "DELETE") {
      const session = requireAdmin(request);
      requireCsrf(request, session);
      const existing = db.prepare("SELECT * FROM hosts WHERE id = ?").get(params[0]);
      if (!existing) throw new HttpError(404, "Host not found.");
      db.prepare("DELETE FROM hosts WHERE id = ?").run(existing.id);
      audit(db, {
        actorUserId: session.user.id,
        action: "host.deleted",
        targetType: "host",
        targetId: existing.id,
        detail: { name: existing.name },
        ip,
      });
      return sendEmpty(response);
    }

    params = matchPath(pathname, /^\/api\/hosts\/([^/]+)\/agent-token$/);
    if (params && method === "POST") {
      const session = requireAdmin(request);
      requireCsrf(request, session);
      const host = db.prepare("SELECT * FROM hosts WHERE id = ?").get(params[0]);
      if (!host) throw new HttpError(404, "Host not found.");
      const rawToken = `ora_${randomToken(32)}`;
      db.prepare(`
        UPDATE hosts
           SET agent_token_hash = ?, agent_status = 'offline', updated_at = ?
         WHERE id = ?
      `).run(tokenHash(rawToken), Date.now(), host.id);
      audit(db, {
        actorUserId: session.user.id,
        action: "host.agent_token_rotated",
        targetType: "host",
        targetId: host.id,
        ip,
      });
      return sendJson(response, 201, { token: rawToken });
    }

    if (method === "POST" && pathname === "/api/agent/heartbeat") {
      const rawToken = parseBearerToken(request);
      if (!rawToken) throw new HttpError(401, "Agent token is required.");
      const host = db.prepare("SELECT * FROM hosts WHERE agent_token_hash = ?").get(
        tokenHash(rawToken),
      );
      if (!host) throw new HttpError(401, "Agent token is invalid.");
      const body = await readJson(request, 64 * 1024);
      const osInfo = stringValue(body.osInfo || "Windows", "OS info", { max: 500 });
      const cpuPercent = Math.min(100, Math.max(0, Number(body.cpuPercent) || 0));
      const memoryPercent = Math.min(100, Math.max(0, Number(body.memoryPercent) || 0));
      const metadata = body.metadata && typeof body.metadata === "object" ? body.metadata : {};
      db.prepare(`
        UPDATE hosts SET
          agent_status = 'online', last_seen_at = ?, os_info = ?,
          cpu_percent = ?, memory_percent = ?, metadata_json = ?, updated_at = ?
        WHERE id = ?
      `).run(
        Date.now(),
        osInfo,
        cpuPercent,
        memoryPercent,
        JSON.stringify(metadata).slice(0, 10_000),
        Date.now(),
        host.id,
      );
      return sendJson(response, 200, { accepted: true, nextHeartbeatSeconds: 30 });
    }

    if (method === "GET" && pathname === "/api/agent/config") {
      const rawToken = parseBearerToken(request);
      if (!rawToken) throw new HttpError(401, "Agent token is required.");
      const host = db.prepare("SELECT * FROM hosts WHERE agent_token_hash = ?").get(
        tokenHash(rawToken),
      );
      if (!host) throw new HttpError(401, "Agent token is invalid.");
      const applications = db.prepare(`
        SELECT id, name, mode, remote_app, working_directory, arguments
          FROM applications WHERE host_id = ? AND enabled = 1 ORDER BY name
      `).all(host.id);
      return sendJson(response, 200, {
        hostId: host.id,
        applications: applications.map((app) => ({
          id: app.id,
          name: app.name,
          mode: app.mode,
          remoteApp: app.remote_app,
          workingDirectory: app.working_directory,
          arguments: app.arguments,
        })),
      });
    }

    if (method === "GET" && pathname === "/api/applications") {
      const session = requireAuth(request);
      const baseQuery = `
        SELECT a.*, h.name AS host_name, h.agent_status
          FROM applications a JOIN hosts h ON h.id = a.host_id
      `;
      const applications =
        session.user.role === "admin"
          ? db.prepare(`${baseQuery} ORDER BY a.name COLLATE NOCASE`).all()
          : db.prepare(`
              ${baseQuery}
              JOIN application_assignments aa ON aa.application_id = a.id
             WHERE aa.user_id = ? AND a.enabled = 1 AND h.enabled = 1
             ORDER BY a.name COLLATE NOCASE
            `).all(session.user.id);
      return sendJson(response, 200, {
        applications: applications.map(publicApplication),
      });
    }

    if (method === "POST" && pathname === "/api/applications") {
      const session = requireAdmin(request);
      requireCsrf(request, session);
      const input = applicationInput(await readJson(request));
      if (!db.prepare("SELECT id FROM hosts WHERE id = ?").get(input.hostId)) {
        throw new HttpError(400, "Selected host does not exist.", "validation_error");
      }
      const id = randomUUID();
      const now = Date.now();
      db.prepare(`
        INSERT INTO applications (
          id, host_id, name, description, mode, remote_app, working_directory,
          arguments, icon, enable_printing, enable_file_transfer, enable_audio,
          enabled, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        id,
        input.hostId,
        input.name,
        input.description,
        input.mode,
        input.remoteApp,
        input.workingDirectory,
        input.arguments,
        input.icon,
        Number(input.enablePrinting),
        Number(input.enableFileTransfer),
        Number(input.enableAudio),
        Number(input.enabled),
        now,
        now,
      );
      audit(db, {
        actorUserId: session.user.id,
        action: "application.created",
        targetType: "application",
        targetId: id,
        detail: { name: input.name, mode: input.mode },
        ip,
      });
      const row = db.prepare(`
        SELECT a.*, h.name AS host_name, h.agent_status
          FROM applications a JOIN hosts h ON h.id = a.host_id WHERE a.id = ?
      `).get(id);
      return sendJson(response, 201, { application: publicApplication(row) });
    }

    params = matchPath(pathname, /^\/api\/applications\/([^/]+)$/);
    if (params && method === "PUT") {
      const session = requireAdmin(request);
      requireCsrf(request, session);
      const existing = db.prepare("SELECT * FROM applications WHERE id = ?").get(params[0]);
      if (!existing) throw new HttpError(404, "Application not found.");
      const input = applicationInput(await readJson(request), existing);
      if (!db.prepare("SELECT id FROM hosts WHERE id = ?").get(input.hostId)) {
        throw new HttpError(400, "Selected host does not exist.", "validation_error");
      }
      db.prepare(`
        UPDATE applications SET
          host_id = ?, name = ?, description = ?, mode = ?, remote_app = ?,
          working_directory = ?, arguments = ?, icon = ?, enable_printing = ?,
          enable_file_transfer = ?, enable_audio = ?, enabled = ?, updated_at = ?
        WHERE id = ?
      `).run(
        input.hostId,
        input.name,
        input.description,
        input.mode,
        input.remoteApp,
        input.workingDirectory,
        input.arguments,
        input.icon,
        Number(input.enablePrinting),
        Number(input.enableFileTransfer),
        Number(input.enableAudio),
        Number(input.enabled),
        Date.now(),
        existing.id,
      );
      audit(db, {
        actorUserId: session.user.id,
        action: "application.updated",
        targetType: "application",
        targetId: existing.id,
        detail: { name: input.name },
        ip,
      });
      const row = db.prepare(`
        SELECT a.*, h.name AS host_name, h.agent_status
          FROM applications a JOIN hosts h ON h.id = a.host_id WHERE a.id = ?
      `).get(existing.id);
      return sendJson(response, 200, { application: publicApplication(row) });
    }

    if (params && method === "DELETE") {
      const session = requireAdmin(request);
      requireCsrf(request, session);
      const existing = db.prepare("SELECT * FROM applications WHERE id = ?").get(params[0]);
      if (!existing) throw new HttpError(404, "Application not found.");
      db.prepare("DELETE FROM applications WHERE id = ?").run(existing.id);
      audit(db, {
        actorUserId: session.user.id,
        action: "application.deleted",
        targetType: "application",
        targetId: existing.id,
        detail: { name: existing.name },
        ip,
      });
      return sendEmpty(response);
    }

    params = matchPath(pathname, /^\/api\/applications\/([^/]+)\/launch$/);
    if (params && method === "POST") {
      const session = requireAuth(request);
      requireCsrf(request, session);
      const application = db.prepare(`
        SELECT a.*, h.name AS host_name, h.hostname, h.port, h.protocol, h.domain,
               h.tls_mode, h.enabled AS host_enabled, h.agent_status
          FROM applications a JOIN hosts h ON h.id = a.host_id
         WHERE a.id = ?
      `).get(params[0]);
      if (!application || !application.enabled || !application.host_enabled) {
        throw new HttpError(404, "Application is unavailable.");
      }
      if (session.user.role !== "admin") {
        const assigned = db.prepare(`
          SELECT 1 FROM application_assignments
           WHERE user_id = ? AND application_id = ?
        `).get(session.user.id, application.id);
        if (!assigned) throw new HttpError(403, "This application is not assigned to you.");
      }
      if (!validateGuacamoleSecret(config.guacamoleJsonSecret)) {
        throw new HttpError(
          503,
          "Browser gateway is not configured. Set GUACAMOLE_JSON_SECRET.",
          "gateway_not_configured",
        );
      }
      const body = await readJson(request);
      const credentials = {
        username: stringValue(body.username, "Windows username", { min: 1, max: 255 }),
        password: stringValue(body.password, "Windows password", {
          min: 1,
          max: 1024,
          trim: false,
        }),
        domain: stringValue(body.domain || "", "Windows domain", { max: 255 }),
      };
      const sessionId = randomUUID();
      const now = Date.now();
      db.prepare(`
        INSERT INTO remote_sessions (
          id, user_id, application_id, host_id, status, client_ip, started_at
        ) VALUES (?, ?, ?, ?, 'issued', ?, ?)
      `).run(sessionId, session.user.id, application.id, application.host_id, ip, now);
      const payload = buildConnectionPayload({
        user: session.user,
        application,
        host: {
          ...application,
          id: application.host_id,
          name: application.host_name,
        },
        credentials,
        sessionId,
      });
      const encrypted = encryptGuacamolePayload(payload, config.guacamoleJsonSecret);
      const launchUrl = buildGuacamoleLaunchUrl(config.guacamolePublicUrl, encrypted);
      audit(db, {
        actorUserId: session.user.id,
        action: "session.launch_issued",
        targetType: "application",
        targetId: application.id,
        detail: { sessionId, applicationName: application.name },
        ip,
      });
      return sendJson(response, 201, {
        sessionId,
        launchUrl,
        expiresAt: payload.expires,
      });
    }

    if (method === "GET" && pathname === "/api/users") {
      requireAdmin(request);
      const users = db.prepare("SELECT * FROM users ORDER BY display_name COLLATE NOCASE").all();
      const assignments = db.prepare(`
        SELECT user_id, application_id FROM application_assignments
      `).all();
      const byUser = new Map();
      for (const assignment of assignments) {
        if (!byUser.has(assignment.user_id)) byUser.set(assignment.user_id, []);
        byUser.get(assignment.user_id).push(assignment.application_id);
      }
      return sendJson(response, 200, {
        users: users.map((user) => ({
          ...publicUser(user),
          applicationIds: byUser.get(user.id) || [],
        })),
      });
    }

    if (method === "POST" && pathname === "/api/users") {
      const session = requireAdmin(request);
      requireCsrf(request, session);
      const body = await readJson(request);
      const email = emailValue(body.email);
      const displayName = stringValue(body.displayName, "Display name", { min: 2, max: 80 });
      const role = body.role === "admin" ? "admin" : "user";
      const passwordErrors = validatePassword(body.password);
      if (passwordErrors.length) {
        throw new HttpError(400, passwordErrors.join(" "), "weak_password", passwordErrors);
      }
      const id = randomUUID();
      const now = Date.now();
      try {
        db.prepare(`
          INSERT INTO users (
            id, email, display_name, password_hash, role, status, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?)
        `).run(id, email, displayName, await hashPassword(body.password), role, now, now);
      } catch (error) {
        if (String(error.message).includes("UNIQUE")) {
          throw new HttpError(409, "A user with this email already exists.");
        }
        throw error;
      }
      audit(db, {
        actorUserId: session.user.id,
        action: "user.created",
        targetType: "user",
        targetId: id,
        detail: { email, role },
        ip,
      });
      return sendJson(response, 201, {
        user: publicUser(db.prepare("SELECT * FROM users WHERE id = ?").get(id)),
      });
    }

    params = matchPath(pathname, /^\/api\/users\/([^/]+)$/);
    if (params && method === "PUT") {
      const session = requireAdmin(request);
      requireCsrf(request, session);
      const existing = db.prepare("SELECT * FROM users WHERE id = ?").get(params[0]);
      if (!existing) throw new HttpError(404, "User not found.");
      const body = await readJson(request);
      const displayName = stringValue(body.displayName ?? existing.display_name, "Display name", {
        min: 2,
        max: 80,
      });
      const role = body.role ?? existing.role;
      const status = body.status ?? existing.status;
      if (!["admin", "user"].includes(role) || !["active", "disabled"].includes(status)) {
        throw new HttpError(400, "Role or status is invalid.", "validation_error");
      }
      if (
        existing.role === "admin" &&
        (role !== "admin" || status !== "active") &&
        db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND status = 'active'").get()
          .count <= 1
      ) {
        throw new HttpError(409, "The last active administrator cannot be disabled or demoted.");
      }
      let passwordHash = existing.password_hash;
      if (body.password) {
        const errors = validatePassword(body.password);
        if (errors.length) throw new HttpError(400, errors.join(" "), "weak_password", errors);
        passwordHash = await hashPassword(body.password);
      }
      db.prepare(`
        UPDATE users SET
          display_name = ?, role = ?, status = ?, password_hash = ?, updated_at = ?
        WHERE id = ?
      `).run(displayName, role, status, passwordHash, Date.now(), existing.id);
      if (status === "disabled") db.prepare("DELETE FROM sessions WHERE user_id = ?").run(existing.id);
      audit(db, {
        actorUserId: session.user.id,
        action: "user.updated",
        targetType: "user",
        targetId: existing.id,
        detail: { role, status },
        ip,
      });
      return sendJson(response, 200, {
        user: publicUser(db.prepare("SELECT * FROM users WHERE id = ?").get(existing.id)),
      });
    }

    params = matchPath(pathname, /^\/api\/users\/([^/]+)\/assignments$/);
    if (params && method === "PUT") {
      const session = requireAdmin(request);
      requireCsrf(request, session);
      const user = db.prepare("SELECT id FROM users WHERE id = ?").get(params[0]);
      if (!user) throw new HttpError(404, "User not found.");
      const body = await readJson(request);
      const applicationIds = Array.isArray(body.applicationIds)
        ? [...new Set(body.applicationIds.filter((id) => typeof id === "string"))]
        : [];
      if (applicationIds.length) {
        const placeholders = applicationIds.map(() => "?").join(",");
        const validCount = db
          .prepare(`SELECT COUNT(*) AS count FROM applications WHERE id IN (${placeholders})`)
          .get(...applicationIds).count;
        if (validCount !== applicationIds.length) {
          throw new HttpError(400, "One or more applications do not exist.");
        }
      }
      db.exec("BEGIN IMMEDIATE");
      try {
        db.prepare("DELETE FROM application_assignments WHERE user_id = ?").run(user.id);
        const insert = db.prepare(`
          INSERT INTO application_assignments (user_id, application_id, created_at)
          VALUES (?, ?, ?)
        `);
        for (const applicationId of applicationIds) {
          insert.run(user.id, applicationId, Date.now());
        }
        db.exec("COMMIT");
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
      audit(db, {
        actorUserId: session.user.id,
        action: "user.assignments_updated",
        targetType: "user",
        targetId: user.id,
        detail: { applicationIds },
        ip,
      });
      return sendJson(response, 200, { applicationIds });
    }

    if (method === "POST" && pathname === "/api/me/totp/start") {
      const session = requireAuth(request);
      requireCsrf(request, session);
      const secret = generateTotpSecret();
      db.prepare(`
        UPDATE users SET totp_secret = ?, totp_enabled = 0, updated_at = ? WHERE id = ?
      `).run(secret, Date.now(), session.user.id);
      return sendJson(response, 200, {
        secret,
        otpAuthUri: buildOtpAuthUri({ secret, email: session.user.email }),
      });
    }

    if (method === "POST" && pathname === "/api/me/totp/enable") {
      const session = requireAuth(request);
      requireCsrf(request, session);
      const user = db.prepare("SELECT * FROM users WHERE id = ?").get(session.user.id);
      const body = await readJson(request);
      if (!user.totp_secret || !verifyTotp(user.totp_secret, body.code)) {
        throw new HttpError(400, "Authenticator code is invalid.", "invalid_totp");
      }
      db.prepare("UPDATE users SET totp_enabled = 1, updated_at = ? WHERE id = ?").run(
        Date.now(),
        user.id,
      );
      audit(db, {
        actorUserId: user.id,
        action: "security.totp_enabled",
        targetType: "user",
        targetId: user.id,
        ip,
      });
      return sendJson(response, 200, { enabled: true });
    }

    if (method === "POST" && pathname === "/api/me/totp/disable") {
      const session = requireAuth(request);
      requireCsrf(request, session);
      const user = db.prepare("SELECT * FROM users WHERE id = ?").get(session.user.id);
      const body = await readJson(request);
      if (!(await verifyPassword(body.password || "", user.password_hash))) {
        throw new HttpError(401, "Password is incorrect.", "invalid_credentials");
      }
      db.prepare(`
        UPDATE users SET totp_secret = NULL, totp_enabled = 0, updated_at = ? WHERE id = ?
      `).run(Date.now(), user.id);
      audit(db, {
        actorUserId: user.id,
        action: "security.totp_disabled",
        targetType: "user",
        targetId: user.id,
        ip,
      });
      return sendJson(response, 200, { enabled: false });
    }

    if (method === "GET" && pathname === "/api/audit") {
      requireAdmin(request);
      const limit = Math.min(200, Math.max(1, Number(url.searchParams.get("limit")) || 100));
      const rows = db.prepare(`
        SELECT ae.*, u.display_name AS actor_name, u.email AS actor_email
          FROM audit_events ae LEFT JOIN users u ON u.id = ae.actor_user_id
         ORDER BY ae.created_at DESC LIMIT ?
      `).all(limit);
      return sendJson(response, 200, {
        events: rows.map((row) => ({
          id: row.id,
          actorName: row.actor_name || "System",
          actorEmail: row.actor_email,
          action: row.action,
          targetType: row.target_type,
          targetId: row.target_id,
          detail: parseJson(row.detail_json),
          ipAddress: row.ip_address,
          createdAt: row.created_at,
        })),
      });
    }

    throw new HttpError(404, "API endpoint not found.", "not_found");
  }

  function staticHandler(request, response, url) {
    if (!["GET", "HEAD"].includes(request.method)) {
      throw new HttpError(405, "Method not allowed.");
    }
    let relative = decodeURIComponent(url.pathname);
    if (relative === "/") relative = "/index.html";
    const candidate = path.resolve(config.staticPath, `.${relative}`);
    if (!candidate.startsWith(`${path.resolve(config.staticPath)}${path.sep}`)) {
      throw new HttpError(403, "Invalid path.");
    }
    const filePath = fs.existsSync(candidate) && fs.statSync(candidate).isFile()
      ? candidate
      : path.join(config.staticPath, "index.html");
    const stat = fs.statSync(filePath);
    response.writeHead(200, {
      "Content-Type": MIME_TYPES[path.extname(filePath)] || "application/octet-stream",
      "Content-Length": stat.size,
      "Cache-Control": filePath.endsWith("index.html")
        ? "no-cache"
        : "public, max-age=3600",
    });
    if (request.method === "HEAD") return response.end();
    fs.createReadStream(filePath).pipe(response);
  }

  const server = http.createServer(async (request, response) => {
    applySecurityHeaders(response);
    try {
      const url = new URL(request.url, config.publicUrl);
      if (url.pathname.startsWith("/api/")) {
        await apiHandler(request, response, url);
      } else {
        staticHandler(request, response, url);
      }
    } catch (error) {
      if (response.headersSent) {
        response.destroy();
        return;
      }
      const status = error instanceof HttpError ? error.status : 500;
      if (status >= 500) console.error(error);
      sendJson(response, status, {
        error: {
          code: error instanceof HttpError ? error.code : "internal_error",
          message: error instanceof HttpError ? error.message : "An unexpected error occurred.",
          ...(error instanceof HttpError && error.details ? { details: error.details } : {}),
        },
      });
    }
  });

  return {
    config,
    db,
    server,
    async listen() {
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(config.port, config.host, resolve);
      });
      return server.address();
    },
    async close() {
      clearInterval(cleanupTimer);
      if (server.listening) {
        await new Promise((resolve, reject) =>
          server.close((error) => (error ? reject(error) : resolve())),
        );
      }
      db.close();
    },
  };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
  const app = createOpenRemoteServer();
  app.listen()
    .then(() => {
      console.log(`OpenRemote ${app.config.environment} server`);
      console.log(`Portal: ${app.config.publicUrl}`);
      console.log(`Database: ${app.config.databasePath}`);
      if (!validateGuacamoleSecret(app.config.guacamoleJsonSecret)) {
        console.warn("Browser gateway disabled: configure GUACAMOLE_JSON_SECRET.");
      }
    })
    .catch((error) => {
      console.error(error);
      process.exitCode = 1;
    });

  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.once(signal, async () => {
      await app.close();
      process.exit(0);
    });
  }
}
