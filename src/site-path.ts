import fs from "node:fs";
import path from "node:path";

export class SitePathError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SitePathError";
  }
}

export interface SitePaths {
  id: string;
  root: string;
  profile: string;
  vault: string;
  origins: string;
  meta: string;
  signal: string;
}

const SITE_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/** Site ids are a single path segment. Anything else is rejected, including traversal. */
export function assertSiteId(input: string): string {
  if (typeof input !== "string") {
    throw new SitePathError("Site id is not allowed.");
  }
  const id = input.normalize("NFKC").trim();
  if (
    id !== input.trim() ||
    id === "." ||
    id === ".." ||
    id.includes("..") ||
    id.includes("/") ||
    id.includes("\\") ||
    id.includes("\0") ||
    !SITE_ID.test(id)
  ) {
    throw new SitePathError(
      "Site id is not allowed. Use 1-64 characters of a-z, 0-9, underscore, or hyphen. Paths are rejected.",
    );
  }
  return id;
}

export function sitesRoot(dataDir: string): string {
  return path.join(path.resolve(dataDir), "sites");
}

function assertRealDir(parent: string, child: string, label: string): void {
  const listed = fs.lstatSync(child);
  if (listed.isSymbolicLink()) {
    throw new SitePathError(`${label} must not be a symlink.`);
  }
  if (!listed.isDirectory()) {
    throw new SitePathError(`${label} is not a directory.`);
  }
  const parentReal = fs.realpathSync(parent);
  const childReal = fs.realpathSync(child);
  const rel = path.relative(parentReal, childReal);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new SitePathError("Site path escapes the data directory.");
  }
}

/**
 * Resolve a site's files under data/sites/<id>.
 * Missing directories are fine. Existing symlink components are refused.
 */
export function resolveSitePaths(dataDir: string, site: string): SitePaths {
  const id = assertSiteId(site);
  const dataRoot = path.resolve(dataDir);
  if (fs.existsSync(dataRoot)) {
    const dataStat = fs.lstatSync(dataRoot);
    if (dataStat.isSymbolicLink()) {
      throw new SitePathError("Data directory must not be a symlink.");
    }
    if (!dataStat.isDirectory()) {
      throw new SitePathError("Data directory is not a directory.");
    }
  }
  const rootParent = sitesRoot(dataDir);
  if (fs.existsSync(rootParent)) {
    assertRealDir(dataRoot, rootParent, "Sites directory");
  }
  const root = path.join(rootParent, id);
  const rel = path.relative(rootParent, root);
  if (rel !== id || rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new SitePathError("Site path escapes the data directory.");
  }
  if (fs.existsSync(root)) {
    assertRealDir(fs.existsSync(rootParent) ? rootParent : dataRoot, root, "Site directory");
    if (fs.existsSync(rootParent)) assertRealDir(rootParent, root, "Site directory");
  }
  const profile = path.join(root, "profile");
  if (fs.existsSync(profile)) {
    const st = fs.lstatSync(profile);
    if (st.isSymbolicLink()) {
      throw new SitePathError("Profile directory must not be a symlink.");
    }
    if (!st.isDirectory()) {
      throw new SitePathError("Profile path exists and is not a directory.");
    }
    assertRealDir(root, profile, "Profile directory");
  }
  return {
    id,
    root,
    profile,
    vault: path.join(root, "profile.vault"),
    origins: path.join(root, "origins.json"),
    meta: path.join(root, "meta.json"),
    signal: path.join(root, "human-signal.json"),
  };
}

export function listSiteIds(dataDir: string): string[] {
  const root = sitesRoot(dataDir);
  let st: fs.Stats;
  try {
    st = fs.lstatSync(root);
  } catch {
    return [];
  }
  if (st.isSymbolicLink() || !st.isDirectory()) return [];
  const dataRoot = path.resolve(dataDir);
  try {
    assertRealDir(dataRoot, root, "Sites directory");
  } catch {
    return [];
  }
  const ids: string[] = [];
  for (const name of fs.readdirSync(root)) {
    let id: string;
    try {
      id = assertSiteId(name);
    } catch {
      continue;
    }
    const child = path.join(root, name);
    let childStat: fs.Stats;
    try {
      childStat = fs.lstatSync(child);
    } catch {
      continue;
    }
    if (childStat.isSymbolicLink() || !childStat.isDirectory()) continue;
    try {
      assertRealDir(root, child, "Site directory");
    } catch {
      continue;
    }
    ids.push(id);
  }
  ids.sort();
  return ids;
}
