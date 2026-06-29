import path from "node:path";
import { fileURLToPath } from "node:url";

const sourceDir = path.dirname(fileURLToPath(import.meta.url));
export const projectRoot = path.resolve(sourceDir, "..");

function booleanEnv(name, fallback = false) {
  const value = process.env[name];
  if (value === undefined) return fallback;
  return ["1", "true", "yes", "on"].includes(value.toLowerCase());
}

function integerEnv(name, fallback, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = Number.parseInt(process.env[name] ?? "", 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function resolveProjectPath(value) {
  if (path.isAbsolute(value)) return value;
  return path.resolve(projectRoot, value);
}

export function getConfig(overrides = {}) {
  const port = integerEnv("OPENREMOTE_PORT", 17880, { min: 1, max: 65535 });
  const host = process.env.OPENREMOTE_HOST || "127.0.0.1";

  return {
    host,
    port,
    publicUrl: process.env.OPENREMOTE_PUBLIC_URL || `http://localhost:${port}`,
    databasePath: resolveProjectPath(
      process.env.OPENREMOTE_DB_PATH || "./data/openremote.sqlite",
    ),
    staticPath: path.join(projectRoot, "public"),
    sessionHours: integerEnv("OPENREMOTE_SESSION_HOURS", 12, { min: 1, max: 168 }),
    secureCookies: booleanEnv("OPENREMOTE_SECURE_COOKIES"),
    trustProxy: booleanEnv("OPENREMOTE_TRUST_PROXY"),
    guacamolePublicUrl:
      process.env.GUACAMOLE_PUBLIC_URL || "http://localhost:8080/guacamole/",
    guacamoleJsonSecret: process.env.GUACAMOLE_JSON_SECRET || "",
    environment: process.env.NODE_ENV || "development",
    ...overrides,
  };
}
