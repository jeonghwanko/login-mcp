import crypto from "node:crypto";
import fs from "node:fs";
import fsPromises from "node:fs/promises";
import path from "node:path";
import { createMutex } from "./mutex.js";
import { mayTighten } from "./session-path.js";

const MAX_JSON_BYTES = 256 * 1024;

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

export function isNotFound(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: string }).code === "ENOENT"
  );
}

export async function readPrivateJson(file: string): Promise<unknown | undefined> {
  return fileLock(file)(async () => {
    let raw: string;
    try {
      raw = await readRegularFile(file);
    } catch (error) {
      if (isNotFound(error)) return undefined;
      throw error;
    }
    try {
      return JSON.parse(raw) as unknown;
    } catch {
      throw new Error("Private JSON file is not valid JSON. Refusing to read it.");
    }
  });
}

export async function writePrivateJson(file: string, value: unknown): Promise<void> {
  const body = JSON.stringify(value, null, 2) + "\n";
  await fileLock(file)(async () => {
    await dropOwnedSymlink(file);
    await atomicWrite(file, body);
  });
}

export async function readRegularFile(file: string): Promise<string> {
  const st = await fsPromises.lstat(file);
  if (st.isSymbolicLink()) {
    throw new Error("Private file must not be a symlink.");
  }
  if (!st.isFile()) {
    throw new Error("Private path is not a regular file.");
  }
  if (st.size > MAX_JSON_BYTES) {
    throw new Error("Private file is too large.");
  }
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  const fh = await fsPromises.open(file, flags);
  try {
    await fh.chmod(0o600);
    const after = await fh.stat();
    if ((after.mode & 0o077) !== 0) {
      throw new Error("Private file is readable by other users and could not be locked down.");
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
    throw new Error("Private file must not be a symlink.");
  }
}

export async function atomicWrite(file: string, body: string): Promise<void> {
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
    throw new Error("Private file is readable by other users and could not be locked down.");
  }
}
