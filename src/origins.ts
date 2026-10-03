import fs from "node:fs";
import fsPromises from "node:fs/promises";
import { createMutex } from "./mutex.js";
import { assertOrigin } from "./policy.js";
import { isNotFound, readPrivateJson, writePrivateJson } from "./private-file.js";
import { listSiteIds, resolveSitePaths, type SitePaths } from "./site-path.js";
import { mayTighten } from "./session-path.js";

export type SessionState = "ok" | "needs_login";

export interface OriginRecord {
  loginOrigin: string | null;
  workOrigins: string[];
  origins: string[];
}

export interface SiteRecord extends OriginRecord {
  site: string;
  lastUsed: string | null;
  /** When auth_confirm last succeeded. Not updated by later reads. */
  lastConfirmed: string | null;
  session: SessionState;
}

export interface OriginStore {
  list(): Promise<SiteRecord[]>;
  has(site: string, origin: string): Promise<boolean>;
  /** First origin is the login origin. Later origins are work origins. */
  confirm(site: string, origins: string[]): Promise<string[]>;
  touch(site: string, when?: Date, session?: SessionState, options?: { confirmed?: boolean }): Promise<string>;
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

function pushOrigin(origins: string[], entry: unknown): void {
  if (typeof entry !== "string") return;
  try {
    const origin = assertOrigin(entry);
    if (!origins.includes(origin)) origins.push(origin);
  } catch {
    // Drop paths, credentials, and other values that are not origins.
  }
}

export function parseOriginRecord(parsed: unknown): OriginRecord {
  if (parsed === undefined) return { loginOrigin: null, workOrigins: [], origins: [] };
  if (!parsed || typeof parsed !== "object") {
    throw new Error("Origins file has an unexpected shape. Refusing to read it.");
  }
  const body = parsed as { origins?: unknown; loginOrigin?: unknown; workOrigins?: unknown };
  const hasShape =
    Array.isArray(body.origins) ||
    typeof body.loginOrigin === "string" ||
    body.loginOrigin === null ||
    Array.isArray(body.workOrigins);
  if (!hasShape) throw new Error("Origins file has an unexpected shape. Refusing to read it.");
  const bag: string[] = [];
  if (Array.isArray(body.origins)) {
    for (const entry of body.origins) pushOrigin(bag, entry);
  }
  let loginOrigin: string | null = null;
  if (typeof body.loginOrigin === "string") {
    try {
      loginOrigin = assertOrigin(body.loginOrigin);
      if (!bag.includes(loginOrigin)) bag.push(loginOrigin);
    } catch {
      loginOrigin = null;
    }
  }
  if (Array.isArray(body.workOrigins)) {
    for (const entry of body.workOrigins) pushOrigin(bag, entry);
  }
  const workOrigins = bag.filter((origin) => origin !== loginOrigin).sort();
  const origins = [...(loginOrigin ? [loginOrigin] : []), ...workOrigins];
  const unique = [...new Set(origins)].sort();
  return { loginOrigin, workOrigins, origins: unique };
}

async function readOriginRecord(file: string): Promise<OriginRecord> {
  const parsed = await readPrivateJson(file);
  if (parsed === undefined) return { loginOrigin: null, workOrigins: [], origins: [] };
  return parseOriginRecord(parsed);
}

const LAST_USED = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

export function parseSessionState(value: unknown): SessionState {
  return value === "needs_login" ? "needs_login" : "ok";
}

async function readMeta(file: string): Promise<{ lastUsed: string | null; lastConfirmed: string | null; session: SessionState }> {
  const parsed = await readPrivateJson(file);
  if (!parsed || typeof parsed !== "object") return { lastUsed: null, lastConfirmed: null, session: "ok" };
  const body = parsed as { lastUsed?: unknown; lastConfirmed?: unknown; session?: unknown };
  const lastUsed = typeof body.lastUsed === "string" && LAST_USED.test(body.lastUsed) ? body.lastUsed : null;
  const lastConfirmed =
    typeof body.lastConfirmed === "string" && LAST_USED.test(body.lastConfirmed) ? body.lastConfirmed : null;
  return { lastUsed, lastConfirmed, session: parseSessionState(body.session) };
}

export function createFileStore(dataDir: string): OriginStore {
  return {
    async list() {
      const records: SiteRecord[] = [];
      for (const id of listSiteIds(dataDir)) {
        const paths = resolveSitePaths(dataDir, id);
        const record = await readOriginRecord(paths.origins);
        const meta = await readMeta(paths.meta);
        records.push({
          site: id,
          loginOrigin: record.loginOrigin,
          workOrigins: record.workOrigins,
          origins: record.origins,
          lastUsed: meta.lastUsed,
          lastConfirmed: meta.lastConfirmed,
          session: meta.session,
        });
      }
      return records;
    },
    async has(site: string, origin: string) {
      const paths = resolveSitePaths(dataDir, site);
      const record = await readOriginRecord(paths.origins);
      return record.origins.includes(origin);
    },
    async confirm(site: string, origins: string[]) {
      const incoming: string[] = [];
      for (const origin of origins) {
        const valid = assertOrigin(origin);
        if (!incoming.includes(valid)) incoming.push(valid);
      }
      if (incoming.length === 0) throw new Error("No origin to confirm.");
      const loginUpdate = incoming[0]!;
      const paths = await ensureSite(dataDir, site);
      return siteLock(paths.root)(async () => {
        try {
          const st = await fsPromises.lstat(paths.origins);
          if (st.isSymbolicLink()) await fsPromises.unlink(paths.origins);
        } catch (error) {
          if (!isNotFound(error)) throw error;
        }
        const existing = await readOriginRecord(paths.origins);
        const allowed = new Set(existing.origins);
        for (const origin of incoming) allowed.add(origin);
        if (allowed.size > MAX_ORIGINS) throw new Error("Too many confirmed origins.");
        const loginOrigin = loginUpdate;
        const workOrigins = [...allowed].filter((origin) => origin !== loginOrigin).sort();
        const all = [...allowed].sort();
        await writePrivateJson(paths.origins, { loginOrigin, workOrigins, origins: all });
        return all;
      });
    },
    async touch(site: string, when: Date = new Date(), session?: SessionState, options?: { confirmed?: boolean }) {
      const paths = await ensureSite(dataDir, site);
      const lastUsed = when.toISOString();
      await siteLock(paths.root)(async () => {
        const prev = await readMeta(paths.meta);
        const next = session === "needs_login" || session === "ok" ? session : prev.session;
        const lastConfirmed = options?.confirmed ? lastUsed : prev.lastConfirmed;
        await writePrivateJson(paths.meta, { lastUsed, lastConfirmed, session: next });
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
