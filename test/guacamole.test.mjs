import assert from "node:assert/strict";
import test from "node:test";
import {
  createDecipheriv,
  createHmac,
  timingSafeEqual,
} from "node:crypto";
import {
  buildConnectionPayload,
  buildGuacamoleLaunchUrl,
  encryptGuacamolePayload,
  validateGuacamoleSecret,
} from "../src/guacamole.mjs";

function decryptPayload(value, hexSecret) {
  const key = Buffer.from(hexSecret, "hex");
  const decipher = createDecipheriv("aes-128-cbc", key, Buffer.alloc(16));
  const signed = Buffer.concat([
    decipher.update(Buffer.from(value, "base64")),
    decipher.final(),
  ]);
  const signature = signed.subarray(0, 32);
  const plaintext = signed.subarray(32);
  const expected = createHmac("sha256", key).update(plaintext).digest();
  assert.equal(timingSafeEqual(signature, expected), true);
  return JSON.parse(plaintext.toString("utf8"));
}

test("Guacamole secret must be a 128-bit hexadecimal key", () => {
  assert.equal(validateGuacamoleSecret("0123456789abcdef0123456789abcdef"), true);
  assert.equal(validateGuacamoleSecret("too-short"), false);
  assert.equal(validateGuacamoleSecret("z".repeat(32)), false);
});

test("JSON authentication payload is signed and encrypted per Guacamole contract", () => {
  const secret = "0123456789abcdef0123456789abcdef";
  const payload = { username: "admin@example.test", expires: 123, connections: {} };
  const encrypted = encryptGuacamolePayload(payload, secret);
  assert.deepEqual(decryptPayload(encrypted, secret), payload);
});

test("RDP RemoteApp payload includes printing, drive, and short-lived credentials", () => {
  const before = Date.now();
  const payload = buildConnectionPayload({
    user: { id: "user-1", email: "user@example.test" },
    application: {
      name: "Accounts",
      mode: "remoteapp",
      remote_app: "accounts",
      working_directory: "C:\\Accounts",
      arguments: "--safe",
      enable_printing: 1,
      enable_file_transfer: 1,
      enable_audio: 0,
    },
    host: {
      name: "RDS 1",
      hostname: "10.0.0.15",
      port: 3389,
      protocol: "rdp",
      domain: "ACME",
      tls_mode: "verify",
    },
    credentials: { username: "jsmith", password: "not-stored", domain: "" },
    sessionId: "session-1",
  });
  const connection = payload.connections["Accounts · RDS 1"];

  assert.equal(connection.protocol, "rdp");
  assert.equal(connection.parameters.hostname, "10.0.0.15");
  assert.equal(connection.parameters.domain, "ACME");
  assert.equal(connection.parameters["remote-app"], "||accounts");
  assert.equal(connection.parameters["enable-printing"], "true");
  assert.equal(connection.parameters["enable-drive"], "true");
  assert.equal(connection.parameters["disable-audio"], "true");
  assert.ok(payload.expires >= before + 44_000);
  assert.ok(payload.expires <= before + 46_000);
});

test("launch URL safely URL-encodes encrypted ticket", () => {
  const url = buildGuacamoleLaunchUrl(
    "https://remote.example.test/guacamole/",
    "abc+/==",
  );
  assert.equal(new URL(url).searchParams.get("data"), "abc+/==");
});
