import crypto from "node:crypto";
import fs from "node:fs";
import fsPromises from "node:fs/promises";
import path from "node:path";
import { createMutex } from "./mutex.js";
import { assertOrigin } from "./policy.js";
import { mayTighten } from "./session-path.js";

export interface OriginStore {
  list(): Promise<string[]>;
  has(origin: string): Promise<boolean>;
  confirm(origin: string): Promise<string[]>;
}

interface OriginsFile {
  origins: string[];
}

const MAX_ORIGINS_BYTES = 256 * 1024;
const MAX_ORIGINS = 1000;

const locks = new Map<string, <T>(fn: () => Promise<T>) => Promise<T>>();

function fileLock(file: string): <T>(fn: () => Promise<T>) => Promise<T> {
  const key = path.resolve(file);
  let lock = locks.get(key);
  if (!lock) {
    lock = createMutex();
    locks.set(key, lock);
  }
  return lock;
}

export async function readOrigins(file: string): Promise<string[]> {
  let raw: string;
  try {
    raw = await readRegularFile(file);
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
  const lock = fileLock(file);
  return {
    list: () => lock(() => readOrigins(file)),
    async has(origin: string) {
      const origins = await lock(() => readOrigins(file));
      return origins.includes(origin);
    },
    async confirm(origin: string) {
      const valid = assertOrigin(origin);
      return lock(async () => {
        await dropOwnedSymlink(file);
        const origins = await readOrigins(file);
        if (!origins.includes(valid)) origins.push(valid);
        if (origins.length > MAX_ORIGINS) {
          throw new Error("Too many confirmed origins.");
        }
        origins.sort();
        await atomicWrite(file, JSON.stringify({ origins }, null, 2) + "\n");
        return origins;
      });
    },
  };
}

async function readRegularFile(file: string): Promise<string> {
  const st = await fsPromises.lstat(file);
  if (st.isSymbolicLink()) {
    throw new Error("Origins file must not be a symlink.");
  }
  if (!st.isFile()) {
    throw new Error("Origins path is not a regular file.");
  }
  if (st.size > MAX_ORIGINS_BYTES) {
    throw new Error("Origins file is too large.");
  }
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  const fh = await fsPromises.open(file, flags);
  try {
    await fh.chmod(0o600);
    const after = await fh.stat();
    if ((after.mode & 0o077) !== 0) {
      throw new Error("Origins file is readable by other users and could not be locked down.");
    }
    return await fh.readFile({ encoding: "utf8" });
  } finally {
    await fh.close();
  }
}

async function dropOwnedSymlink(file: string): Promise<void> {
  let st: fs.Stats;
  try {
    st = await fsPromises.lstat(file);
  } catch (error) {
    if (isNotFound(error)) return;
    throw error;
  }
  if (!st.isSymbolicLink()) return;
  try {
    await fsPromises.unlink(file);
  } catch {
    throw new Error("Origins file must not be a symlink.");
  }
}

async function atomicWrite(file: string, body: string): Promise<void> {
  const dir = path.dirname(file);
  await fsPromises.mkdir(dir, { recursive: true, mode: 0o700 });
  if (mayTighten(dir)) {
    await fsPromises.chmod(dir, 0o700);
  }
  const tmp = path.join(
    dir,
    `.${path.basename(file)}.${process.pid}.${crypto.randomBytes(8).toString("hex")}.tmp`,
  );
  const fh = await fsPromises.open(tmp, "wx", 0o600);
  try {
    await fh.chmod(0o600);
    await fh.writeFile(body);
    await fh.sync();
  } catch (error) {
    await fh.close().catch(() => undefined);
    await fsPromises.unlink(tmp).catch(() => undefined);
    throw error;
  }
  await fh.close();
  await fsPromises.rename(tmp, file);
  await fsPromises.chmod(file, 0o600);
  const mode = (await fsPromises.stat(file)).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error("Origins file is readable by other users and could not be locked down.");
  }
}

function isNotFound(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: string }).code === "ENOENT"
  );
}
