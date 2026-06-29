import {
  createHash,
  createHmac,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(scryptCallback);
const SCRYPT_N = 16_384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEY_LENGTH = 64;

export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

export function tokenHash(value) {
  return createHash("sha256").update(value).digest("hex");
}

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, SCRYPT_KEY_LENGTH, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: 64 * 1024 * 1024,
  });

  return [
    "scrypt",
    SCRYPT_N,
    SCRYPT_R,
    SCRYPT_P,
    salt.toString("base64url"),
    Buffer.from(derived).toString("base64url"),
  ].join("$");
}

export async function verifyPassword(password, encoded) {
  try {
    const [algorithm, n, r, p, saltValue, hashValue] = encoded.split("$");
    if (algorithm !== "scrypt") return false;

    const expected = Buffer.from(hashValue, "base64url");
    const actual = await scrypt(password, Buffer.from(saltValue, "base64url"), expected.length, {
      N: Number(n),
      r: Number(r),
      p: Number(p),
      maxmem: 64 * 1024 * 1024,
    });

    return timingSafeEqual(expected, Buffer.from(actual));
  } catch {
    return false;
  }
}

export function validatePassword(password) {
  const errors = [];
  if (typeof password !== "string" || password.length < 12) {
    errors.push("Password must contain at least 12 characters.");
  }
  if (!/[a-z]/.test(password)) errors.push("Add a lowercase letter.");
  if (!/[A-Z]/.test(password)) errors.push("Add an uppercase letter.");
  if (!/[0-9]/.test(password)) errors.push("Add a number.");
  if (!/[^A-Za-z0-9]/.test(password)) errors.push("Add a symbol.");
  return errors;
}

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function encodeBase32(buffer) {
  let bits = "";
  for (const byte of buffer) bits += byte.toString(2).padStart(8, "0");

  let output = "";
  for (let index = 0; index < bits.length; index += 5) {
    const chunk = bits.slice(index, index + 5).padEnd(5, "0");
    output += BASE32_ALPHABET[Number.parseInt(chunk, 2)];
  }
  return output;
}

export function decodeBase32(value) {
  const clean = value.toUpperCase().replace(/=+$/g, "").replace(/\s/g, "");
  let bits = "";
  for (const character of clean) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index < 0) throw new Error("Invalid base32 value");
    bits += index.toString(2).padStart(5, "0");
  }

  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  return Buffer.from(bytes);
}

export function generateTotpSecret() {
  return encodeBase32(randomBytes(20));
}

export function generateTotp(secret, time = Date.now(), stepSeconds = 30, digits = 6) {
  const counter = Math.floor(time / 1000 / stepSeconds);
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", decodeBase32(secret)).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const number =
    (digest.readUInt32BE(offset) & 0x7fffffff) % Math.pow(10, digits);
  return number.toString().padStart(digits, "0");
}

export function verifyTotp(secret, code, time = Date.now(), window = 1) {
  const normalized = String(code ?? "").replace(/\s/g, "");
  if (!/^\d{6}$/.test(normalized)) return false;

  for (let offset = -window; offset <= window; offset += 1) {
    const expected = generateTotp(secret, time + offset * 30_000);
    const left = Buffer.from(normalized);
    const right = Buffer.from(expected);
    if (left.length === right.length && timingSafeEqual(left, right)) return true;
  }
  return false;
}

export function buildOtpAuthUri({ secret, email, issuer = "OpenRemote" }) {
  const label = encodeURIComponent(`${issuer}:${email}`);
  const query = new URLSearchParams({
    secret,
    issuer,
    algorithm: "SHA1",
    digits: "6",
    period: "30",
  });
  return `otpauth://totp/${label}?${query}`;
}

export function parseCookies(header = "") {
  const result = {};
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (!key) continue;
    try {
      result[key] = decodeURIComponent(value);
    } catch {
      result[key] = value;
    }
  }
  return result;
}

export function sessionCookie(token, { secure = false, maxAgeSeconds = 43_200 } = {}) {
  const parts = [
    `openremote_session=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

export function clearSessionCookie({ secure = false } = {}) {
  const parts = [
    "openremote_session=",
    "Path=/",
    "HttpOnly",
    "SameSite=Strict",
    "Max-Age=0",
  ];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}
