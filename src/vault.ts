import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { listSiteIds, resolveSitePaths, SitePathError, type SitePaths } from "./site-path.js";

const MAGIC = Buffer.from("LMCP");
const VERSION = 1;
const HEADER_LEN = 4 + 1 + 16 + 12;
const TAG_LEN = 16;
const SCRYPT_N = 16384;

/**
 * At rest, a profile is either a mode-0700 directory or a scrypt + AES-256-GCM vault.
 * The key is never written and errors are scrubbed of it.
 * Symlinks are not followed and are not packed.
 */
export function createProfileVault(encryptionKey: string | null): {
  unlockSite(dataDir: string, site: string): void;
  lockSite(dataDir: string, site: string): void;
  lockAll(dataDir: string): void;
} {
  function scrub(error: unknown): Error {
    let message = error instanceof SitePathError || error instanceof Error ? error.message : String(error);
    if (encryptionKey) message = message.split(encryptionKey).join("[redacted]");
    return new Error(message);
  }

  function unlockSite(dataDir: string, site: string): void {
    try {
      const paths = resolveSitePaths(dataDir, site);
      fs.mkdirSync(paths.root, { recursive: true, mode: 0o700 });
      const fresh = resolveSitePaths(dataDir, site);
      tightenDir(fresh.root);
      if (fs.existsSync(fresh.profile)) {
        const st = fs.lstatSync(fresh.profile);
        if (st.isSymbolicLink()) throw new SitePathError("Profile directory must not be a symlink.");
        tightenTree(fresh.profile);
        return;
      }
      if (encryptionKey && isRegularFile(fresh.vault)) {
        decryptVault(fresh, encryptionKey);
        tightenTree(fresh.profile);
        return;
      }
      if (!encryptionKey && isRegularFile(fresh.vault)) {
        throw new Error("Profile is encrypted. Set LOGIN_MCP_KEY to unlock it. The key is not logged.");
      }
      fs.mkdirSync(fresh.profile, { recursive: true, mode: 0o700 });
      tightenTree(fresh.profile);
    } catch (error) {
      throw scrub(error);
    }
  }

  function lockSite(dataDir: string, site: string): void {
    try {
      const paths = resolveSitePaths(dataDir, site);
      if (!fs.existsSync(paths.profile)) return;
      const st = fs.lstatSync(paths.profile);
      if (st.isSymbolicLink()) throw new SitePathError("Profile directory must not be a symlink.");
      if (!st.isDirectory()) throw new SitePathError("Profile path exists and is not a directory.");
      tightenTree(paths.profile);
      if (!encryptionKey) return;
      const pack = path.join(paths.root, ".profile.pack");
      try {
        packProfile(paths.profile, pack);
        fs.chmodSync(pack, 0o600);
        encryptFile(pack, paths.vault, encryptionKey);
      } finally {
        fs.rmSync(pack, { force: true });
      }
      safeRemoveProfile(paths);
    } catch (error) {
      throw scrub(error);
    }
  }

  function lockAll(dataDir: string): void {
    for (const id of listSiteIds(dataDir)) {
      try {
        lockSite(dataDir, id);
      } catch (error) {
        const message = scrub(error).message;
        console.error(`[login-mcp] profile lock failed site=${id} ${message}`);
      }
    }
  }

  return { unlockSite, lockSite, lockAll };
}

export type ProfileLockReason = "browser_closed" | "process_exit" | "relaunch";

/**
 * Lock a site profile when its browser goes away.
 * relaunch leaves the plaintext directory in place so the same site can start again.
 * SIGKILL never invokes this: the process is gone before the close hook can run.
 */
export function relockClosedSite(
  vault: { lockSite(dataDir: string, site: string): void },
  dataDir: string,
  site: string,
  reason: ProfileLockReason,
): void {
  if (reason === "relaunch") return;
  vault.lockSite(dataDir, site);
}

/**
 * True when Chrome's SingletonLock names a process that is still running.
 * A stale lock (SIGKILL leftover) is not in use. This never signals the process.
 */
export function chromeProfileInUse(profileDir: string): boolean {
  const lockPath = path.join(profileDir, "SingletonLock");
  let target: string;
  try {
    const st = fs.lstatSync(lockPath);
    if (!st.isSymbolicLink()) return false;
    target = fs.readlinkSync(lockPath);
  } catch {
    return false;
  }
  const match = /-(\d+)$/.exec(target);
  if (!match) return false;
  const pid = Number(match[1]);
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    return code === "EPERM";
  }
}

/** The legacy shared profile is never sealed, chmod'd, or removed. */
export function isLegacySharedProfile(dataDir: string, candidate: string): boolean {
  const legacy = path.resolve(dataDir, "chrome-profile");
  const resolved = path.resolve(candidate);
  return resolved === legacy || resolved.startsWith(legacy + path.sep);
}

/**
 * Encrypt plaintext site profiles left behind after SIGKILL, before anything else
 * opens them. With no key, only mode 0700/0600 is applied. Sessions are not deleted.
 * A live Chrome lock is skipped. data/chrome-profile is never touched.
 */
export function sealLeftoverProfiles(
  vault: { lockSite(dataDir: string, site: string): void },
  dataDir: string,
): void {
  for (const id of listSiteIds(dataDir)) {
    try {
      const paths = resolveSitePaths(dataDir, id);
      if (isLegacySharedProfile(dataDir, paths.profile) || isLegacySharedProfile(dataDir, paths.root)) {
        continue;
      }
      if (!fs.existsSync(paths.profile)) continue;
      const st = fs.lstatSync(paths.profile);
      if (st.isSymbolicLink() || !st.isDirectory()) continue;
      if (chromeProfileInUse(paths.profile)) continue;
      vault.lockSite(dataDir, id);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[login-mcp] profile seal failed site=${id} ${message.split("\n")[0]?.slice(0, 200)}`);
    }
  }
}

function isRegularFile(file: string): boolean {
  try {
    const st = fs.lstatSync(file);
    return st.isFile() && !st.isSymbolicLink();
  } catch {
    return false;
  }
}

function tightenDir(dir: string): void {
  const st = fs.lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) {
    throw new SitePathError("Session directory must not be a symlink.");
  }
  const flags = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | (fs.constants.O_NOFOLLOW ?? 0);
  const fd = fs.openSync(dir, flags);
  try {
    fs.fchmodSync(fd, 0o700);
    const mode = fs.fstatSync(fd).mode & 0o777;
    if ((mode & 0o077) !== 0) {
      throw new Error("Could not make the session directory private (mode 0700).");
    }
  } finally {
    fs.closeSync(fd);
  }
}

export function tightenTree(dir: string): void {
  tightenDir(dir);
  for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
    if (ent.name === "." || ent.name === "..") continue;
    const child = path.join(dir, ent.name);
    if (ent.isSymbolicLink()) continue;
    if (ent.isDirectory()) {
      tightenTree(child);
      continue;
    }
    if (ent.isFile()) {
      fs.chmodSync(child, 0o600);
    }
  }
}

function assertProfileInside(paths: SitePaths): void {
  const rootReal = fs.realpathSync(paths.root);
  const profileReal = fs.realpathSync(paths.profile);
  if (path.relative(rootReal, profileReal) !== "profile") {
    throw new SitePathError("Refusing to remove a profile outside the site directory.");
  }
}

function safeRemoveProfile(paths: SitePaths): void {
  const st = fs.lstatSync(paths.profile);
  if (st.isSymbolicLink() || !st.isDirectory()) {
    throw new SitePathError("Refusing to remove a profile that is not a real directory.");
  }
  assertProfileInside(paths);
  fs.rmSync(paths.profile, { recursive: true, force: false });
}

function deriveKey(secret: string, salt: Buffer): Buffer {
  return crypto.scryptSync(secret, salt, 32, { N: SCRYPT_N, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
}

function encryptFile(plainPath: string, vaultPath: string, secret: string): void {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveKey(secret, salt);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const tmp = `${vaultPath}.${process.pid}.tmp`;
  const out = fs.openSync(tmp, "w", 0o600);
  try {
    fs.writeSync(out, Buffer.concat([MAGIC, Buffer.from([VERSION]), salt, iv]));
    const input = fs.openSync(plainPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    try {
      const buf = Buffer.alloc(64 * 1024);
      while (true) {
        const n = fs.readSync(input, buf, 0, buf.length, null);
        if (n <= 0) break;
        const enc = cipher.update(buf.subarray(0, n));
        if (enc.length > 0) fs.writeSync(out, enc);
      }
    } finally {
      fs.closeSync(input);
    }
    const fin = cipher.final();
    if (fin.length > 0) fs.writeSync(out, fin);
    fs.writeSync(out, cipher.getAuthTag());
    fs.fsyncSync(out);
  } catch (error) {
    fs.closeSync(out);
    fs.rmSync(tmp, { force: true });
    key.fill(0);
    throw error;
  }
  fs.closeSync(out);
  key.fill(0);
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, vaultPath);
  fs.chmodSync(vaultPath, 0o600);
}

function decryptVault(paths: SitePaths, secret: string): void {
  const st = fs.lstatSync(paths.vault);
  if (st.isSymbolicLink() || !st.isFile()) {
    throw new Error("Profile vault must be a regular file.");
  }
  if (st.size < HEADER_LEN + TAG_LEN) {
    throw new Error("Profile vault could not be unlocked.");
  }
  const fh = fs.openSync(paths.vault, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  let key: Buffer | null = null;
  const pack = path.join(paths.root, ".profile.pack");
  try {
    const header = Buffer.alloc(HEADER_LEN);
    if (fs.readSync(fh, header, 0, HEADER_LEN, 0) !== HEADER_LEN) {
      throw new Error("Profile vault could not be unlocked.");
    }
    if (!header.subarray(0, 4).equals(MAGIC) || header[4] !== VERSION) {
      throw new Error("Profile vault could not be unlocked.");
    }
    const salt = header.subarray(5, 21);
    const iv = header.subarray(21, 33);
    const tagStart = st.size - TAG_LEN;
    const tag = Buffer.alloc(TAG_LEN);
    if (fs.readSync(fh, tag, 0, TAG_LEN, tagStart) !== TAG_LEN) {
      throw new Error("Profile vault could not be unlocked.");
    }
    key = deriveKey(secret, salt);
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const out = fs.openSync(pack, "w", 0o600);
    try {
      const buf = Buffer.alloc(64 * 1024);
      let offset = HEADER_LEN;
      while (offset < tagStart) {
        const n = fs.readSync(fh, buf, 0, Math.min(buf.length, tagStart - offset), offset);
        if (n <= 0) throw new Error("Profile vault could not be unlocked.");
        offset += n;
        const dec = decipher.update(buf.subarray(0, n));
        if (dec.length > 0) fs.writeSync(out, dec);
      }
      const fin = decipher.final();
      if (fin.length > 0) fs.writeSync(out, fin);
      fs.fsyncSync(out);
    } catch (error) {
      fs.closeSync(out);
      fs.rmSync(pack, { force: true });
      throw new Error("Profile vault could not be unlocked.");
    }
    fs.closeSync(out);
    fs.mkdirSync(paths.profile, { mode: 0o700 });
    try {
      unpackProfile(pack, paths.profile);
    } catch (error) {
      fs.rmSync(paths.profile, { recursive: true, force: true });
      throw error;
    }
  } finally {
    fs.closeSync(fh);
    key?.fill(0);
    fs.rmSync(pack, { force: true });
  }
}

function packProfile(profile: string, dest: string): void {
  const out = fs.openSync(dest, "w", 0o600);
  try {
    walk(profile, "");
    const end = Buffer.alloc(2);
    fs.writeSync(out, end);
  } finally {
    fs.closeSync(out);
  }

  function walk(dir: string, rel: string): void {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      if (ent.name === "." || ent.name === ".." || ent.name.includes("/") || ent.name.includes("\\")) continue;
      const relPath = rel ? `${rel}/${ent.name}` : ent.name;
      if (relPath.split("/").includes("..")) continue;
      const abs = path.join(dir, ent.name);
      const st = fs.lstatSync(abs);
      if (st.isSymbolicLink()) continue;
      if (st.isDirectory()) {
        writeRecord(out, relPath, false, null);
        walk(abs, relPath);
      } else if (st.isFile()) {
        writeRecord(out, relPath, true, abs);
      }
    }
  }
}

function writeRecord(fd: number, rel: string, isFile: boolean, file: string | null): void {
  const pathBuf = Buffer.from(rel, "utf8");
  if (pathBuf.length === 0 || pathBuf.length > 40_000) {
    throw new Error("Profile path is too long to lock.");
  }
  const size = file ? fs.statSync(file).size : 0;
  const header = Buffer.alloc(2 + 1 + 8);
  header.writeUInt16BE(pathBuf.length, 0);
  header.writeUInt8(isFile ? 1 : 0, 2);
  header.writeBigUInt64BE(BigInt(size), 3);
  fs.writeSync(fd, header);
  fs.writeSync(fd, pathBuf);
  if (!file) return;
  const inFd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const buf = Buffer.alloc(64 * 1024);
    let left = size;
    while (left > 0) {
      const n = fs.readSync(inFd, buf, 0, Math.min(buf.length, left), null);
      if (n <= 0) throw new Error("Profile file changed while it was locked.");
      fs.writeSync(fd, buf.subarray(0, n));
      left -= n;
    }
  } finally {
    fs.closeSync(inFd);
  }
}

function unpackProfile(pack: string, profile: string): void {
  const fd = fs.openSync(pack, "r");
  try {
    const rootReal = fs.realpathSync(profile);
    while (true) {
      const lenBuf = Buffer.alloc(2);
      if (readFull(fd, lenBuf) !== 2) throw new Error("Profile archive is truncated.");
      const pathLen = lenBuf.readUInt16BE(0);
      if (pathLen === 0) return;
      const rest = Buffer.alloc(1 + 8);
      if (readFull(fd, rest) !== rest.length) throw new Error("Profile archive is truncated.");
      const isFile = rest[0] === 1;
      const size = Number(rest.readBigUInt64BE(1));
      if (!Number.isSafeInteger(size) || size < 0) throw new Error("Profile archive is invalid.");
      const pathBuf = Buffer.alloc(pathLen);
      if (readFull(fd, pathBuf) !== pathLen) throw new Error("Profile archive is truncated.");
      const rel = pathBuf.toString("utf8");
      const dest = safeJoin(rootReal, rel);
      if (!isFile) {
        fs.mkdirSync(dest, { mode: 0o700 });
        const st = fs.lstatSync(dest);
        if (st.isSymbolicLink() || !st.isDirectory()) {
          throw new SitePathError("Profile archive tried to create a symlink.");
        }
        continue;
      }
      fs.mkdirSync(path.dirname(dest), { recursive: true, mode: 0o700 });
      const flags =
        fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        (fs.constants.O_NOFOLLOW ?? 0);
      const out = fs.openSync(dest, flags, 0o600);
      try {
        let left = size;
        const buf = Buffer.alloc(64 * 1024);
        while (left > 0) {
          const n = fs.readSync(fd, buf, 0, Math.min(buf.length, left), null);
          if (n <= 0) throw new Error("Profile archive is truncated.");
          fs.writeSync(out, buf.subarray(0, n));
          left -= n;
        }
        fs.fchmodSync(out, 0o600);
      } finally {
        fs.closeSync(out);
      }
    }
  } finally {
    fs.closeSync(fd);
  }
}

function safeJoin(rootReal: string, rel: string): string {
  if (rel.length === 0 || rel.includes("\0") || rel.includes("\\") || path.isAbsolute(rel)) {
    throw new SitePathError("Profile archive path is not allowed.");
  }
  const parts = rel.split("/");
  if (parts.some((part) => part === "" || part === "." || part === "..")) {
    throw new SitePathError("Profile archive path is not allowed.");
  }
  const dest = path.resolve(rootReal, ...parts);
  const relDest = path.relative(rootReal, dest);
  if (relDest.startsWith("..") || path.isAbsolute(relDest)) {
    throw new SitePathError("Profile archive path escapes the profile directory.");
  }
  return dest;
}

function readFull(fd: number, buf: Buffer): number {
  let off = 0;
  while (off < buf.length) {
    const n = fs.readSync(fd, buf, off, buf.length - off, null);
    if (n <= 0) return off;
    off += n;
  }
  return off;
}
