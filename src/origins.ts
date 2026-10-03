import fs from "node:fs";
import fsPromises from "node:fs/promises";
import { createMutex } from "./mutex.js";
import { assertOrigin } from "./policy.js";
import { isNotFound, readPrivateJson, writePrivateJson } from "./private-file.js";
import { listSiteIds, resolveSitePaths, type SitePaths } from "./site-path.js";
import { mayTighten } from "./session-path.js";

export interface SiteRecord {
  site: string;
  origins: string[];
  lastUsed: string | null;
}

export interface OriginStore {
  list(): Promise<SiteRecord[]>;
  has(site: string, origin: string): Promise<boolean>;
  confirm(site: string, origins: string[]): Promise<string[]>;
  touch(site: string, when?: Date): Promise<string>;
}

const MAX_ORIGINS = 1000;

const locks = new Map<string, <T>(fn: () => Promise<T>) => Promise<T>>();

function siteLock(root: string): <T>(fn: () => Promise<T>) => Promise<T> {
  let lock = locks.get(root);
  if (!lock) {
    lock = createMutex();
    locks.set(root, lock);
  }
  return lock;
}

async function ensureSite(dataDir: string, site: string): Promise<SitePaths> {
  const paths = resolveSitePaths(dataDir, site);
  await fsPromises.mkdir(paths.root, { recursive: true, mode: 0o700 });
  const created = resolveSitePaths(dataDir, site);
  if (mayTighten(created.root)) await fsPromises.chmod(created.root, 0o700);
  return created;
}

async function readOrigins(file: string): Promise<string[]> {
  const parsed = await readPrivateJson(file);
  if (parsed === undefined) return [];
  if (!parsed || typeof parsed !== "object" || !Array.isArray((parsed as { origins?: unknown }).origins)) {
    throw new Error("Origins file has an unexpected shape. Refusing to read it.");
  }
  const origins: string[] = [];
  for (const entry of (parsed as { origins: unknown[] }).origins) {
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

async function readLastUsed(file: string): Promise<string | null> {
  const parsed = await readPrivateJson(file);
  if (!parsed || typeof parsed !== "object") return null;
  const value = (parsed as { lastUsed?: unknown }).lastUsed;
  if (typeof value !== "string" || value.length === 0 || value.length > 40) return null;
  return value;
}

export function createFileStore(dataDir: string): OriginStore {
  return {
    async list() {
      const records: SiteRecord[] = [];
      for (const id of listSiteIds(dataDir)) {
        const paths = resolveSitePaths(dataDir, id);
        records.push({
          site: id,
          origins: await readOrigins(paths.origins),
          lastUsed: await readLastUsed(paths.meta),
        });
      }
      return records;
    },
    async has(site: string, origin: string) {
      const paths = resolveSitePaths(dataDir, site);
      const origins = await readOrigins(paths.origins);
      return origins.includes(origin);
    },
    async confirm(site: string, origins: string[]) {
      const valid = [...new Set(origins.map((origin) => assertOrigin(origin)))].sort();
      if (valid.length === 0) throw new Error("No origin to confirm.");
      const paths = await ensureSite(dataDir, site);
      return siteLock(paths.root)(async () => {
        try {
          const st = await fsPromises.lstat(paths.origins);
          if (st.isSymbolicLink()) await fsPromises.unlink(paths.origins);
        } catch (error) {
          if (!isNotFound(error)) throw error;
        }
        const existing = await readOrigins(paths.origins);
        for (const origin of valid) {
          if (!existing.includes(origin)) existing.push(origin);
        }
        if (existing.length > MAX_ORIGINS) throw new Error("Too many confirmed origins.");
        existing.sort();
        await writePrivateJson(paths.origins, { origins: existing });
        return existing;
      });
    },
    async touch(site: string, when: Date = new Date()) {
      const paths = await ensureSite(dataDir, site);
      const lastUsed = when.toISOString();
      await siteLock(paths.root)(async () => {
        await writePrivateJson(paths.meta, { lastUsed });
      });
      return lastUsed;
    },
  };
}

export function profileLooksPresent(paths: SitePaths): boolean {
  try {
    const profile = fs.lstatSync(paths.profile);
    if (!profile.isSymbolicLink() && profile.isDirectory()) return true;
  } catch {
    // missing profile
  }
  try {
    const vault = fs.lstatSync(paths.vault);
    return vault.isFile() && !vault.isSymbolicLink();
  } catch {
    return false;
  }
}
