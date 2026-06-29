import { createCipheriv, createHmac } from "node:crypto";

export function validateGuacamoleSecret(secret) {
  return typeof secret === "string" && /^[a-fA-F0-9]{32}$/.test(secret);
}

export function encryptGuacamolePayload(payload, hexSecret) {
  if (!validateGuacamoleSecret(hexSecret)) {
    throw new Error("GUACAMOLE_JSON_SECRET must be exactly 32 hexadecimal characters.");
  }

  const key = Buffer.from(hexSecret, "hex");
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const signature = createHmac("sha256", key).update(plaintext).digest();
  const signed = Buffer.concat([signature, plaintext]);
  const cipher = createCipheriv("aes-128-cbc", key, Buffer.alloc(16));
  return Buffer.concat([cipher.update(signed), cipher.final()]).toString("base64");
}

export function buildConnectionPayload({
  user,
  application,
  host,
  credentials,
  sessionId,
  lifetimeMs = 45_000,
}) {
  const connectionName = `${application.name} · ${host.name}`;
  const parameters = {
    hostname: host.hostname,
    port: String(host.port),
    username: credentials.username,
    password: credentials.password,
    domain: credentials.domain || host.domain || "",
    security: "nla",
    "ignore-cert": host.tls_mode === "ignore" ? "true" : "false",
    "enable-printing": application.enable_printing ? "true" : "false",
    "enable-drive": application.enable_file_transfer ? "true" : "false",
    "drive-name": "OpenRemote",
    "drive-path": `/drive/${user.id}/${sessionId}`,
    "create-drive-path": "true",
    "disable-audio": application.enable_audio ? "false" : "true",
    "enable-font-smoothing": "true",
    "resize-method": "display-update",
    "recording-path": `/recordings/${user.id}`,
    "recording-name": `${sessionId}`,
    "create-recording-path": "true",
  };

  if (application.mode === "remoteapp") {
    const remoteApp = application.remote_app.startsWith("||")
      ? application.remote_app
      : `||${application.remote_app}`;
    parameters["remote-app"] = remoteApp;
    if (application.working_directory) {
      parameters["remote-app-dir"] = application.working_directory;
    }
    if (application.arguments) parameters["remote-app-args"] = application.arguments;
  }

  return {
    username: user.email,
    expires: Date.now() + lifetimeMs,
    connections: {
      [connectionName]: {
        id: sessionId,
        protocol: host.protocol,
        parameters,
      },
    },
  };
}

export function buildGuacamoleLaunchUrl(baseUrl, encryptedPayload) {
  const url = new URL(baseUrl);
  url.searchParams.set("data", encryptedPayload);
  return url.toString();
}
