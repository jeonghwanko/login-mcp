import path from "node:path";
import { assertSafeConfig } from "./session-path.js";

export interface Config {
  dataDir: string;
  userDataDir: string;
  originsFile: string;
}

export function getConfig(
  env: NodeJS.ProcessEnv = process.env,
  cwd: string = process.cwd(),
): Config {
  const dataDir = env.LOGIN_MCP_DATA_DIR || path.join(cwd, "data");
  const config: Config = {
    dataDir,
    userDataDir: env.LOGIN_MCP_USER_DATA_DIR || path.join(dataDir, "chrome-profile"),
    originsFile: env.LOGIN_MCP_ORIGINS_FILE || path.join(dataDir, "origins.json"),
  };
  assertSafeConfig(config);
  return config;
}
