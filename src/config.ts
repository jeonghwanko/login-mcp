import path from "node:path";
import { assertSafeConfig } from "./session-path.js";

export interface Config {
  dataDir: string;
  /** Null when LOGIN_MCP_KEY is unset. Never log this value. */
  encryptionKey: string | null;
}

export function readEncryptionKey(env: NodeJS.ProcessEnv = process.env): string | null {
  const raw = env.LOGIN_MCP_KEY;
  if (raw == null || raw.length === 0) return null;
  if (raw.length > 4096) {
    throw new Error("LOGIN_MCP_KEY is too long.");
  }
  return raw;
}

export function getConfig(
  env: NodeJS.ProcessEnv = process.env,
  cwd: string = process.cwd(),
): Config {
  const dataDir = env.LOGIN_MCP_DATA_DIR || path.join(cwd, "data");
  assertSafeConfig({ dataDir });
  return {
    dataDir,
    encryptionKey: readEncryptionKey(env),
  };
}
