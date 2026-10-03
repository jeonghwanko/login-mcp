import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export interface SessionPaths {
  dataDir: string;
  userDataDir: string;
  originsFile: string;
}

function reservedProfileDirs(): string[] {
  const home = os.homedir();
  return [
    path.join(home, ".config", "google-chrome"),
    path.join(home, ".config", "google-chrome-beta"),
    path.join(home, ".config", "google-chrome-unstable"),
    path.join(home, ".config", "chromium"),
    path.join(home, "snap", "chromium", "common", "chromium"),
    path.join(home, "Library", "Application Support", "Google", "Chrome"),
    path.join(home, "Library", "Application Support", "Chromium"),
    path.join(home, "AppData", "Local", "Google", "Chrome", "User Data"),
  ].map((dir) => path.resolve(dir));
}

function assertNotReserved(label: string, target: string): void {
  const resolved = path.resolve(target);
  const root = path.parse(resolved).root;
  if (resolved === root) {
    throw new Error(`Refusing to use the filesystem root as the ${label}.`);
  }
  for (const reserved of reservedProfileDirs()) {
    const insideReserved = resolved === reserved || resolved.startsWith(reserved + path.sep);
    const containsReserved = reserved.startsWith(resolved + path.sep);
    if (insideReserved || containsReserved) {
      throw new Error(
        `Refusing to use the system Chrome profile as the ${label}. Set a dedicated directory instead.`,
      );
    }
  }
}

/** Shared temp dirs and account roots must never be chmod'd by this server. */
export function mayTighten(dir: string): boolean {
  const resolved = path.resolve(dir);
  const blocked = new Set(
    [
      "/",
      "/tmp",
      "/var/tmp",
      "/dev/shm",
      "/run",
      "/home",
      os.homedir(),
      path.join(os.homedir(), ".config"),
      path.join(os.homedir(), "Library"),
    ].map((entry) => path.resolve(entry)),
  );
  return !blocked.has(resolved);
}

export function assertSafeConfig(config: SessionPaths): void {
  assertNotReserved("data directory", config.dataDir);
  assertNotReserved("profile directory", config.userDataDir);
  assertNotReserved("origins file", config.originsFile);
  assertNotReserved("origins directory", path.dirname(config.originsFile));
}

/**
 * Create a dedicated directory and force mode 0700.
 * Refuses a symlinked leaf so a swapped path cannot point Chrome at another profile.
 */
export function preparePrivateDir(dir: string): void {
  const resolved = path.resolve(dir);
  assertNotReserved("session directory", resolved);
  if (!mayTighten(resolved)) {
    throw new Error(`Refusing to keep session data in ${resolved}. Use a dedicated directory.`);
  }
  if (fs.existsSync(resolved)) {
    const st = fs.lstatSync(resolved);
    if (st.isSymbolicLink()) {
      throw new Error("Session directory must not be a symlink.");
    }
    if (!st.isDirectory()) {
      throw new Error("Session path exists and is not a directory.");
    }
  } else {
    fs.mkdirSync(resolved, { recursive: true, mode: 0o700 });
  }
  const leaf = fs.lstatSync(resolved);
  if (leaf.isSymbolicLink() || !leaf.isDirectory()) {
    throw new Error("Session directory must not be a symlink.");
  }
  assertNotReserved("session directory", fs.realpathSync(resolved));
  const flags =
    fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | (fs.constants.O_NOFOLLOW ?? 0);
  const fd = fs.openSync(resolved, flags);
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
