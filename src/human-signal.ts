import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import readline from "node:readline/promises";
import { assertOrigin } from "./policy.js";
import { isNotFound, readPrivateJson, writePrivateJson } from "./private-file.js";
import { assertSiteId, resolveSitePaths, SitePathError } from "./site-path.js";

export const HUMAN_SIGNAL_TTL_MS = 10 * 60 * 1000;

export class HumanSignalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HumanSignalError";
  }
}

export interface HumanSignals {
  beginLogin(site: string, origin: string): Promise<string | null>;
  assertRecent(site: string, origins: string[]): Promise<string[]>;
  /** Writes a signed signal. Call only after a human click or typed code, or from tests. */
  allow(site: string, origins: string[]): Promise<void>;
  close(): Promise<void>;
}

interface Challenge {
  nonce: string;
  code: string;
  site: string;
  origin: string;
  exp: number;
}

const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function shortCode(): string {
  const bytes = crypto.randomBytes(12);
  let raw = "";
  for (const byte of bytes) raw += CODE_ALPHABET[byte % CODE_ALPHABET.length];
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
}

function normalizeCode(input: string): string {
  return input.normalize("NFKC").trim().toUpperCase().replace(/[\s-]/g, "");
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => {
    if (ch === "&") return "&amp;";
    if (ch === "<") return "&lt;";
    if (ch === ">") return "&gt;";
    if (ch === '"') return "&quot;";
    return "&#39;";
  });
}

function isLoopback(address: string | undefined): boolean {
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

interface SignalFile {
  site: string;
  origins: string[];
  at: number;
  sig: string;
}

export function createHumanSignals(options: {
  dataDir: string;
  serve?: boolean;
  now?: () => number;
  ttlMs?: number;
}): HumanSignals {
  const now = options.now ?? (() => Date.now());
  const ttlMs = options.ttlMs ?? HUMAN_SIGNAL_TTL_MS;
  const fileKey = crypto.randomBytes(32);
  const challenges = new Map<string, Challenge>();
  let failures = 0;
  let server: http.Server | null = null;
  let port = 0;
  let starting: Promise<number> | null = null;

  function payload(site: string, origins: string[], at: number): string {
    return JSON.stringify({ at, origins: [...origins].sort(), site });
  }

  function sign(site: string, origins: string[], at: number): string {
    return crypto.createHmac("sha256", fileKey).update(payload(site, origins, at)).digest("hex");
  }

  async function allow(site: string, origins: string[]): Promise<void> {
    const id = assertSiteId(site);
    const valid = [...new Set(origins.map((origin) => assertOrigin(origin)))].sort();
    if (valid.length === 0) throw new HumanSignalError("A human allow signal needs an origin.");
    if (valid.length > 2) throw new HumanSignalError("A human allow signal can include only a login origin and one work origin.");
    const at = now();
    const paths = resolveSitePaths(options.dataDir, id);
    fs.mkdirSync(paths.root, { recursive: true, mode: 0o700 });
    const body: SignalFile = { site: id, origins: valid, at, sig: sign(id, valid, at) };
    await writePrivateJson(paths.signal, body);
  }

  async function assertRecent(site: string, origins: string[]): Promise<string[]> {
    const id = assertSiteId(site);
    const requested = origins.map((origin) => assertOrigin(origin));
    let parsed: unknown;
    try {
      parsed = await readPrivateJson(resolveSitePaths(options.dataDir, id).signal);
    } catch (error) {
      if (error instanceof SitePathError) throw new HumanSignalError(error.message);
      throw new HumanSignalError("Human allow signal could not be read.");
    }
    if (!parsed || typeof parsed !== "object") {
      throw new HumanSignalError("A recent human allow signal is required.");
    }
    const file = parsed as Partial<SignalFile>;
    if (file.site !== id || !Array.isArray(file.origins) || typeof file.at !== "number" || typeof file.sig !== "string") {
      throw new HumanSignalError("A recent human allow signal is required.");
    }
    const stored: string[] = [];
    for (const entry of file.origins) {
      if (typeof entry !== "string") continue;
      try {
        const origin = assertOrigin(entry);
        if (!stored.includes(origin)) stored.push(origin);
      } catch {
        continue;
      }
    }
    stored.sort();
    const expected = sign(id, stored, file.at);
    const given = Buffer.from(file.sig);
    const want = Buffer.from(expected);
    if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) {
      throw new HumanSignalError("A recent human allow signal is required.");
    }
    const age = now() - file.at;
    if (age < -60_000 || age > ttlMs) {
      throw new HumanSignalError("The human allow signal is older than 10 minutes.");
    }
    for (const origin of requested) {
      if (!stored.includes(origin)) {
        throw new HumanSignalError("The human allow signal does not include that origin.");
      }
    }
    return stored;
  }

  async function approveFromChallenge(challenge: Challenge, workOrigin: string | undefined): Promise<void> {
    const origins = [challenge.origin];
    if (workOrigin && workOrigin.trim().length > 0) origins.push(workOrigin.trim());
    await allow(challenge.site, origins);
    challenges.delete(challenge.nonce);
  }

  function findByCode(code: string): Challenge | undefined {
    const normalized = normalizeCode(code);
    for (const challenge of challenges.values()) {
      if (challenge.code === normalized && challenge.exp >= now()) return challenge;
    }
    return undefined;
  }

  async function ensureServer(): Promise<number> {
    if (!options.serve) return 0;
    if (port) return port;
    if (starting) return starting;
    starting = new Promise<number>((resolve, reject) => {
      const created = http.createServer((req, res) => {
        void onRequest(req, res);
      });
      created.once("error", reject);
      created.listen(0, "127.0.0.1", () => {
        const address = created.address();
        port = typeof address === "object" && address ? address.port : 0;
        server = created;
        const portFile = portPath(options.dataDir);
        fs.mkdirSync(options.dataDir, { recursive: true, mode: 0o700 });
        fs.writeFileSync(portFile, `${port}\n`, { mode: 0o600 });
        fs.chmodSync(portFile, 0o600);
        resolve(port);
      });
    });
    try {
      return await starting;
    } catch (error) {
      starting = null;
      throw error;
    }
  }

  async function beginLogin(site: string, origin: string): Promise<string | null> {
    const id = assertSiteId(site);
    const valid = assertOrigin(origin);
    if (!options.serve) return null;
    const bound = await ensureServer();
    const nonce = crypto.randomBytes(32).toString("hex");
    const code = normalizeCode(shortCode());
    challenges.set(nonce, { nonce, code, site: id, origin: valid, exp: now() + ttlMs });
    return `http://127.0.0.1:${bound}/allow/${nonce}`;
  }

  async function onRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (!isLoopback(req.socket.remoteAddress)) {
      res.writeHead(403, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      res.end("Forbidden");
      return;
    }
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (req.method === "POST" && url.pathname === "/confirm-code") {
      const body = await readBody(req);
      let parsed: { code?: unknown; site?: unknown; origin?: unknown; workOrigin?: unknown };
      try {
        parsed = JSON.parse(body) as typeof parsed;
      } catch {
        res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
        res.end("Bad request");
        return;
      }
      if (failures >= 8) {
        challenges.clear();
        res.writeHead(429, { "content-type": "text/plain; charset=utf-8" });
        res.end("Too many attempts. Start auth_login again.");
        return;
      }
      const challenge = typeof parsed.code === "string" ? findByCode(parsed.code) : undefined;
      if (!challenge) {
        failures += 1;
        res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
        res.end("The confirmation code was not accepted.");
        return;
      }
      if (typeof parsed.site === "string" && parsed.site !== challenge.site) {
        failures += 1;
        res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
        res.end("The confirmation code was not accepted.");
        return;
      }
      if (typeof parsed.origin === "string" && parsed.origin !== challenge.origin) {
        failures += 1;
        res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
        res.end("The confirmation code was not accepted.");
        return;
      }
      try {
        const work = typeof parsed.workOrigin === "string" ? parsed.workOrigin : undefined;
        await approveFromChallenge(challenge, work);
      } catch {
        res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
        res.end("The work origin was rejected.");
        return;
      }
      failures = 0;
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      res.end("Allowed. Call auth_confirm within 10 minutes.");
      return;
    }

    const match = /^\/allow\/([a-f0-9]{64})$/.exec(url.pathname);
    if (!match) {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      res.end("Not found");
      return;
    }
    const challenge = challenges.get(match[1] ?? "");
    if (!challenge || challenge.exp < now()) {
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
      res.end("Not found");
      return;
    }
    if (req.method === "GET") {
      const display = `${challenge.code.slice(0, 4)}-${challenge.code.slice(4, 8)}-${challenge.code.slice(8, 12)}`;
      const html = `<!doctype html>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<title>이 사이트 허용</title>
<style>body{font-family:sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem}code{font-size:1.3rem}</style>
<h1>이 사이트 허용</h1>
<p>사이트 <strong>${escapeHtml(challenge.site)}</strong></p>
<p>로그인 오리진 <strong>${escapeHtml(challenge.origin)}</strong></p>
<p>터미널에서 확인하려면 이 코드를 입력하세요.</p>
<p><code id="allow-code">${escapeHtml(display)}</code></p>
<form method="post">
<label>작업 오리진 (선택) <input name="workOrigin" placeholder="https://www.example.com" size="40" maxlength="200"></label>
<p><button type="submit">이 사이트 허용</button></p>
</form>`;
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      res.end(html);
      return;
    }
    if (req.method === "POST") {
      const body = await readBody(req);
      const form = new URLSearchParams(body);
      try {
        await approveFromChallenge(challenge, form.get("workOrigin") ?? undefined);
      } catch {
        res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
        res.end("The work origin was rejected.");
        return;
      }
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      res.end("<!doctype html><meta charset=utf-8><title>허용됨</title><p>허용했습니다. 10분 안에 auth_confirm을 호출하세요.</p>");
      return;
    }
    res.writeHead(405, { "content-type": "text/plain; charset=utf-8" });
    res.end("Method not allowed");
  }

  async function close(): Promise<void> {
    challenges.clear();
    fileKey.fill(0);
    const file = portPath(options.dataDir);
    fs.rmSync(file, { force: true });
    const current = server;
    server = null;
    port = 0;
    starting = null;
    if (!current) return;
    await new Promise<void>((resolve) => current.close(() => resolve()));
  }

  return { beginLogin, assertRecent, allow, close };
}

function portPath(dataDir: string): string {
  return `${dataDir.replace(/\/$/, "")}/confirm.port`;
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > 4096) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

export async function confirmFromTerminal(options: {
  dataDir: string;
  site?: string;
  origin?: string;
  workOrigin?: string;
  isTTY: boolean;
  stdin: NodeJS.ReadableStream;
  stdout: NodeJS.WritableStream;
}): Promise<void> {
  if (!options.isTTY) {
    throw new Error("A human must confirm from an interactive terminal. auth_confirm cannot approve a site by itself.");
  }
  const file = portPath(options.dataDir);
  let portText: string;
  try {
    const st = fs.lstatSync(file);
    if (st.isSymbolicLink() || !st.isFile()) {
      throw new Error("Confirmation port file is not a regular file.");
    }
    portText = fs.readFileSync(file, "utf8").trim();
  } catch (error) {
    if (isNotFound(error) || (error instanceof Error && /ENOENT/.test(error.message))) {
      throw new Error("login-mcp is not running, so there is no confirmation code. Call auth_login first.");
    }
    if (error instanceof Error && /ENOENT/.test(String((error as NodeJS.ErrnoException).code))) {
      throw new Error("login-mcp is not running, so there is no confirmation code. Call auth_login first.");
    }
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") {
      throw new Error("login-mcp is not running, so there is no confirmation code. Call auth_login first.");
    }
    throw error;
  }
  if (!/^\d+$/.test(portText)) {
    throw new Error("login-mcp is not running, so there is no confirmation code. Call auth_login first.");
  }
  const rl = readline.createInterface({ input: options.stdin, output: options.stdout });
  let answer = "";
  try {
    answer = await rl.question(
      "Chrome 탭의 허용 코드를 입력하세요 (이 사이트 허용). Enter cancels: ",
    );
  } finally {
    rl.close();
  }
  if (normalizeCode(answer).length === 0) {
    throw new Error("Not confirmed.");
  }
  const response = await fetch(`http://127.0.0.1:${portText}/confirm-code`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      code: answer,
      site: options.site,
      origin: options.origin,
      workOrigin: options.workOrigin,
    }),
  });
  if (!response.ok) {
    throw new Error("The confirmation code was not accepted.");
  }
}
