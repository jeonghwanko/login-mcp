import fs from "node:fs/promises";
import path from "node:path";
import { assertOrigin } from "./policy.js";

export interface OriginStore {
  list(): Promise<string[]>;
  has(origin: string): Promise<boolean>;
  confirm(origin: string): Promise<string[]>;
}

interface OriginsFile {
  origins: string[];
}

export async function readOrigins(file: string): Promise<string[]> {
  let raw: string;
  try {
    raw = await fs.readFile(file, "utf8");
  } catch (error) {
    if (isNotFound(error)) return [];
    throw error;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Origins file is not valid JSON. Refusing to read it.");
  }
  if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as OriginsFile).origins)) {
    throw new Error("Origins file has an unexpected shape. Refusing to read it.");
  }
  const origins: string[] = [];
  for (const entry of (parsed as OriginsFile).origins) {
    if (typeof entry !== "string") continue;
    try {
      const origin = assertOrigin(entry);
      if (!origins.includes(origin)) origins.push(origin);
    } catch {
      continue;
    }
  }
  origins.sort();
  return origins;
}

export function createFileStore(file: string): OriginStore {
  return {
    list: () => readOrigins(file),
    async has(origin: string) {
      const origins = await readOrigins(file);
      return origins.includes(origin);
    },
    async confirm(origin: string) {
      const valid = assertOrigin(origin);
      const origins = await readOrigins(file);
      if (!origins.includes(valid)) origins.push(valid);
      origins.sort();
      await fs.mkdir(path.dirname(file), { recursive: true });
      const body = JSON.stringify({ origins }, null, 2) + "\n";
      const tmp = `${file}.tmp`;
      await fs.writeFile(tmp, body, { mode: 0o600 });
      await fs.rename(tmp, file);
      return origins;
    },
  };
}

function isNotFound(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: string }).code === "ENOENT"
  );
}
