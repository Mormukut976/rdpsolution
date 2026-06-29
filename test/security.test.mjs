import assert from "node:assert/strict";
import test from "node:test";
import {
  buildOtpAuthUri,
  decodeBase32,
  encodeBase32,
  generateTotp,
  hashPassword,
  validatePassword,
  verifyPassword,
  verifyTotp,
} from "../src/security.mjs";

test("passwords are hashed with scrypt and verified safely", async () => {
  const password = "A-strong-password-42!";
  const encoded = await hashPassword(password);

  assert.match(encoded, /^scrypt\$/);
  assert.equal(await verifyPassword(password, encoded), true);
  assert.equal(await verifyPassword("wrong-password", encoded), false);
  assert.notEqual(encoded, await hashPassword(password), "salts must be unique");
});

test("password policy reports missing requirements", () => {
  assert.deepEqual(validatePassword("short"), [
    "Password must contain at least 12 characters.",
    "Add an uppercase letter.",
    "Add a number.",
    "Add a symbol.",
  ]);
  assert.deepEqual(validatePassword("ValidPassword1!"), []);
});

test("base32 encoder and decoder round-trip RFC test secret", () => {
  const secret = Buffer.from("12345678901234567890", "ascii");
  const encoded = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  assert.equal(encodeBase32(secret), encoded);
  assert.deepEqual(decodeBase32(encoded), secret);
});

test("TOTP matches the RFC 6238 SHA-1 test vector", () => {
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  assert.equal(generateTotp(secret, 59_000), "287082");
  assert.equal(verifyTotp(secret, "287082", 59_000, 0), true);
  assert.equal(verifyTotp(secret, "000000", 59_000, 0), false);
});

test("otpauth URI identifies the account and issuer", () => {
  const uri = buildOtpAuthUri({
    secret: "ABCDEF234567",
    email: "admin@example.test",
    issuer: "OpenRemote",
  });
  assert.match(uri, /^otpauth:\/\/totp\/OpenRemote%3Aadmin%40example\.test\?/);
  assert.match(uri, /secret=ABCDEF234567/);
  assert.match(uri, /issuer=OpenRemote/);
});
