import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import { confirmFromTerminal, createHumanSignals } from "../src/human-signal.ts";
import { createFileStore } from "../src/origins.ts";
import { writePrivateJson } from "../src/private-file.ts";
import { createService } from "../src/service.ts";
import { assertSiteId, resolveSitePaths } from "../src/site-path.ts";
import { createProfileVault, relockClosedSite } from "../src/vault.ts";
import { chromeLaunchArgs, type BrowserControl, type BrowserOps, type PageSignals } from "../src/browser.ts";

const SENTINEL = "COOKIEVALUE-do-not-leak-7f3a9c";
const KEY = "super-secret-login-mcp-key";

function tempDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "login-mcp-sec-"));
}

test("site id traversal and symlink profiles are rejected", () => {
  for (const bad of ["../etc", "..", ".", "foo/bar", "foo\\bar", "/etc/passwd", "a/../../b", "", "Demo", "bad host"]) {
    assert.throws(() => assertSiteId(bad), /not allowed/, bad);
  }
  assert.equal(assertSiteId("wishket"), "wishket");
  assert.equal(assertSiteId("a"), "a");

  const dir = tempDir();
  const outside = path.join(dir, "outside-profile");
  fs.mkdirSync(outside, { recursive: true });
  fs.writeFileSync(path.join(outside, "Cookies"), SENTINEL);
  const sites = path.join(dir, "sites");
  fs.mkdirSync(sites);
  fs.symlinkSync(outside, path.join(sites, "evil"));
  assert.throws(() => resolveSitePaths(dir, "evil"), /symlink/);
  assert.equal(fs.readFileSync(path.join(outside, "Cookies"), "utf8"), SENTINEL);

  const real = path.join(sites, "demo");
  fs.mkdirSync(real);
  fs.symlinkSync(outside, path.join(real, "profile"));
  assert.throws(() => resolveSitePaths(dir, "demo"), /symlink/);
  assert.equal(fs.readFileSync(path.join(outside, "Cookies"), "utf8"), SENTINEL);
});

test("vault encrypts with LOGIN_MCP_KEY and only chmods when the key is unset", () => {
  const dir = tempDir();
  const legacy = path.join(dir, "chrome-profile");
  fs.mkdirSync(legacy);
  fs.writeFileSync(path.join(legacy, "Cookies"), "legacy-" + SENTINEL);

  const paths = resolveSitePaths(dir, "demo");
  fs.mkdirSync(paths.profile, { recursive: true, mode: 0o755 });
  fs.mkdirSync(path.join(paths.profile, "Default"), { mode: 0o755 });
  const cookie = path.join(paths.profile, "Default", "Cookies");
  fs.writeFileSync(cookie, Buffer.from(SENTINEL + "\0binary", "utf8"), { mode: 0o644 });

  const plain = createProfileVault(null);
  plain.lockSite(dir, "demo");
  assert.equal(fs.existsSync(paths.vault), false);
  assert.equal(fs.statSync(paths.profile).mode & 0o077, 0);
  assert.equal(fs.statSync(cookie).mode & 0o077, 0);
  assert.equal(fs.readFileSync(cookie).includes(Buffer.from(SENTINEL)), true);

  const vault = createProfileVault(KEY);
  vault.lockAll(dir);
  assert.equal(fs.existsSync(paths.profile), false);
  assert.equal(fs.existsSync(paths.vault), true);
  const blob = fs.readFileSync(paths.vault);
  assert.equal(blob.includes(Buffer.from(SENTINEL)), false);
  assert.equal(blob.includes(Buffer.from(KEY)), false);
  assert.equal(fs.readFileSync(path.join(legacy, "Cookies"), "utf8"), "legacy-" + SENTINEL);

  assert.throws(() => createProfileVault(KEY + "-wrong").unlockSite(dir, "demo"), /could not be unlocked/);
  const wrongMessage = (() => {
    try {
      createProfileVault(KEY + "-wrong").unlockSite(dir, "demo");
      return "";
    } catch (error) {
      return error instanceof Error ? error.message : String(error);
    }
  })();
  assert.equal(wrongMessage.includes(KEY), false);
  assert.equal(wrongMessage.includes("wrong"), false);
  assert.equal(fs.existsSync(paths.profile), false);

  vault.unlockSite(dir, "demo");
  const restored = fs.readFileSync(path.join(paths.profile, "Default", "Cookies"));
  assert.equal(restored.equals(Buffer.from(SENTINEL + "\0binary", "utf8")), true);
  assert.equal(fs.statSync(paths.profile).mode & 0o077, 0);
  assert.equal(fs.statSync(path.join(paths.profile, "Default", "Cookies")).mode & 0o077, 0);
});

test("confirm records a human-approved origin pair and refuses a forged signal file", async () => {
  const dir = tempDir();
  let now = 1_700_000_000_000;
  const human = createHumanSignals({ dataDir: dir, serve: false, now: () => now });
  const store = createFileStore(dir);
  const browser = idleBrowser();
  const service = createService({
    store,
    browser,
    human,
    dataDir: dir,
    log: () => undefined,
    resolveHost: async () => ["93.184.216.34"],
  });

  const denied = await service.confirm("wishket", "https://auth.example", "https://www.example");
  assert.equal(denied.isError, true);
  assert.match(denied.text, /human_signal_required/);
  assert.equal((await store.list()).length, 0);

  const signal = resolveSitePaths(dir, "wishket");
  fs.mkdirSync(signal.root, { recursive: true });
  await writePrivateJson(signal.signal, {
    site: "wishket",
    origins: ["https://auth.example", "https://www.example"],
    at: now,
    sig: "00",
    cookies: [{ name: "sid", value: SENTINEL }],
  });
  const forged = await service.confirm("wishket", "https://auth.example");
  assert.equal(forged.isError, true);
  assert.match(forged.text, /human_signal_required/);
  assert.equal(forged.text.includes(SENTINEL), false);

  await human.allow("wishket", ["https://auth.example", "https://www.example"]);
  const allowed = await service.confirm("wishket", "https://auth.example", "https://www.example");
  assert.equal(allowed.isError, undefined);
  const body = JSON.parse(allowed.text) as { origins: string[] };
  assert.deepEqual(body.origins, ["https://auth.example", "https://www.example"]);
  assert.equal(allowed.text.includes(SENTINEL), false);

  now += 11 * 60 * 1000;
  const expired = await service.confirm("wishket", "https://auth.example");
  assert.equal(expired.isError, true);
  assert.match(expired.text, /human_signal_required|10 minutes/);
  await human.close();
});

test("localhost allow button and terminal code record a human signal", async () => {
  const dir = tempDir();
  const human = createHumanSignals({ dataDir: dir, serve: true });
  try {
    const url = await human.beginLogin("wishket", "https://auth.example");
    assert.ok(url);
    assert.match(url, /^http:\/\/127\.0\.0\.1:\d+\/allow\/[a-f0-9]{64}$/);
    const html = await (await fetch(url)).text();
    assert.match(html, /이 사이트 허용/);
    const code = /id="allow-code">([^<]+)/.exec(html)?.[1];
    assert.ok(code);
    assert.equal(url.includes(code.replace(/-/g, "")), false);

    const posted = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ workOrigin: "https://www.example" }),
    });
    assert.equal(posted.ok, true);
    assert.deepEqual(await human.assertRecent("wishket", ["https://auth.example", "https://www.example"]), [
      "https://auth.example",
      "https://www.example",
    ]);

    const again = await human.beginLogin("other", "https://other.example");
    const againHtml = await (await fetch(again!)).text();
    const againCode = /id="allow-code">([^<]+)/.exec(againHtml)?.[1];
    assert.ok(againCode);
    await assert.rejects(
      () =>
        confirmFromTerminal({
          dataDir: dir,
          site: "other",
          origin: "https://other.example",
          isTTY: false,
          stdin: Readable.from(["y\n"]),
          stdout: new Writable({
            write(_chunk, _enc, cb) {
              cb();
            },
          }),
        }),
      /interactive terminal/,
    );
    await confirmFromTerminal({
      dataDir: dir,
      site: "other",
      origin: "https://other.example",
      workOrigin: "https://work.example",
      isTTY: true,
      stdin: Readable.from([`${againCode}\n`]),
      stdout: new Writable({
        write(_chunk, _enc, cb) {
          cb();
        },
      }),
    });
    assert.deepEqual(await human.assertRecent("other", ["https://other.example", "https://work.example"]), [
      "https://other.example",
      "https://work.example",
    ]);
  } finally {
    await human.close();
  }
});

function idleBrowser(): BrowserControl {
  const page: PageSignals = {
    title: "",
    url: "about:blank",
    hasPasswordInput: false,
    textSample: "",
  };
  const ops: BrowserOps = {
    async login() {},
    async open(url: string) {
      return { ...page, url };
    },
    async inspect() {
      return null;
    },
    async readText() {
      return { text: "", truncated: false };
    },
    async act() {},
    async blank() {},
  };
  return {
    profileExists: () => false,
    isOpen: () => false,
    openSite: () => null,
    exclusive(_site, fn) {
      return fn(ops);
    },
    async close() {},
  };
}

test("relock helper encrypts on browser close, chmod-only without a key, and skips relaunch", () => {
  const dir = tempDir();
  const paths = resolveSitePaths(dir, "demo");
  fs.mkdirSync(path.join(paths.profile, "Default"), { recursive: true });
  const cookie = path.join(paths.profile, "Default", "Cookies");
  fs.writeFileSync(cookie, SENTINEL);

  const vault = createProfileVault(KEY);
  relockClosedSite(vault, dir, "demo", "relaunch");
  assert.equal(fs.existsSync(cookie), true);
  assert.equal(fs.readFileSync(cookie, "utf8"), SENTINEL);
  assert.equal(fs.existsSync(paths.vault), false);

  relockClosedSite(vault, dir, "demo", "browser_closed");
  assert.equal(fs.existsSync(paths.profile), false);
  assert.equal(fs.existsSync(paths.vault), true);
  const blob = fs.readFileSync(paths.vault);
  assert.equal(blob.includes(Buffer.from(SENTINEL)), false);
  assert.equal(blob.includes(Buffer.from(KEY)), false);

  assert.doesNotThrow(() => relockClosedSite(vault, dir, "demo", "process_exit"));
  assert.equal(fs.existsSync(paths.profile), false);

  vault.unlockSite(dir, "demo");
  assert.equal(fs.readFileSync(path.join(paths.profile, "Default", "Cookies"), "utf8"), SENTINEL);

  const plain = createProfileVault(null);
  relockClosedSite(plain, dir, "demo", "browser_closed");
  assert.equal(fs.existsSync(paths.profile), true);
  assert.equal(fs.statSync(paths.profile).mode & 0o077, 0);
  assert.equal(fs.statSync(path.join(paths.profile, "Default", "Cookies")).mode & 0o077, 0);
  assert.equal(fs.readFileSync(path.join(paths.profile, "Default", "Cookies"), "utf8"), SENTINEL);

  const rules = "MAP example.com 93.184.216.34";
  assert.deepEqual(chromeLaunchArgs(rules).at(-1), `--host-resolver-rules=${rules}`);
  assert.equal(chromeLaunchArgs("").some((arg) => arg.startsWith("--host-resolver-rules=")), false);
});
