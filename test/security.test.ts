import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import { confirmFromTerminal, createHumanSignals, selectAllowOrigins } from "../src/human-signal.ts";
import { createFileStore } from "../src/origins.ts";
import { writePrivateJson } from "../src/private-file.ts";
import { createService } from "../src/service.ts";
import { assertSiteId, resolveSitePaths } from "../src/site-path.ts";
import { createProfileVault, relockClosedSite, sealLeftoverProfiles } from "../src/vault.ts";
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

test("selectAllowOrigins keeps the wishket login and work origins and drops the allow server", () => {
  const tabs = [
    "https://auth.wishket.com/login",
    "https://www.wishket.com/projects?token=secret-token",
    "http://127.0.0.1:9/allow/abc",
    "about:blank",
    "https://evil.example/bank",
  ];
  assert.deepEqual(
    selectAllowOrigins({ loginOrigin: "https://www.wishket.com", tabUrls: tabs, allowPort: 9 }),
    ["https://www.wishket.com", "https://auth.wishket.com"],
  );
  assert.deepEqual(
    selectAllowOrigins({ loginOrigin: "https://auth.wishket.com", tabUrls: ["https://www.wishket.com/home"], allowPort: 9 }),
    ["https://auth.wishket.com", "https://www.wishket.com"],
  );
  const picked = selectAllowOrigins({ loginOrigin: "https://auth.wishket.com", tabUrls: tabs, allowPort: 9 }).join(" ");
  assert.equal(picked.includes("secret-token"), false);
  assert.equal(picked.includes("127.0.0.1"), false);
  assert.equal(picked.includes("evil.example"), false);
  assert.deepEqual(
    selectAllowOrigins({
      loginOrigin: "https://auth.example",
      explicitWorkOrigin: "https://www.example",
    }),
    ["https://auth.example", "https://www.example"],
  );
});

test("allow button stores both origins and confirms them without asking for auth_confirm", async () => {
  const dir = tempDir();
  const store = createFileStore(dir);
  let buttonCalls = 0;
  let tabs = ["https://auth.wishket.com/login", "https://www.wishket.com/"];
  const human = createHumanSignals({
    dataDir: dir,
    serve: true,
    openTabUrls: () => tabs,
    onButtonAllow: async (site, origins) => {
      buttonCalls += 1;
      assert.equal(site, "wishket");
      await store.confirm(site, origins);
      await store.touch(site, new Date(), undefined, { confirmed: true });
    },
  });
  try {
    const url = await human.beginLogin("wishket", "https://www.wishket.com");
    assert.ok(url);
    const allowPort = new URL(url).port;
    tabs = [...tabs, `http://127.0.0.1:${allowPort}/allow/abc`, "about:blank"];
    const html = await (await fetch(url)).text();
    const buttonAt = html.indexOf(">이 사이트 허용</button>");
    const authAt = html.indexOf("https://auth.wishket.com");
    const wwwAt = html.indexOf("https://www.wishket.com");
    assert.ok(buttonAt > authAt && authAt >= 0);
    assert.ok(buttonAt > wwwAt && wwwAt >= 0);
    assert.equal(html.includes("127.0.0.1"), false);
    assert.equal(html.includes("auth_confirm"), false);

    const posted = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ workOrigin: "" }),
    });
    assert.equal(posted.ok, true);
    const body = await posted.text();
    assert.match(body, /허용되었습니다/);
    assert.equal(body.includes("auth_confirm"), false);
    assert.equal(buttonCalls, 1);
    assert.deepEqual(await human.assertRecent("wishket", ["https://auth.wishket.com", "https://www.wishket.com"]), [
      "https://auth.wishket.com",
      "https://www.wishket.com",
    ]);
    const listed = await store.list();
    assert.deepEqual(listed[0]?.origins, ["https://auth.wishket.com", "https://www.wishket.com"]);
    assert.equal(typeof listed[0]?.lastConfirmed, "string");

    const again = await human.beginLogin("other", "https://other.example");
    const againHtml = await (await fetch(again!)).text();
    const againCode = /id="allow-code">([^<]+)/.exec(againHtml)?.[1];
    assert.ok(againCode);
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
    assert.equal(buttonCalls, 1);
    const after = await store.list();
    const other = after.find((record) => record.site === "other");
    assert.ok(other);
    assert.deepEqual(other.origins, []);
    assert.equal(other.lastConfirmed, null);
    const wishket = after.find((record) => record.site === "wishket");
    assert.deepEqual(wishket?.origins, ["https://auth.wishket.com", "https://www.wishket.com"]);
    assert.equal(wishket?.lastConfirmed, listed[0]?.lastConfirmed);
    assert.deepEqual(await human.assertRecent("other", ["https://other.example", "https://work.example"]), [
      "https://other.example",
      "https://work.example",
    ]);
  } finally {
    await human.close();
  }
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
    listOpenTabUrls: () => [],
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

test("startup seal encrypts a plaintext leftover, chmods without a key, and does not touch a live chrome profile", () => {
  const dir = tempDir();
  const legacy = path.join(dir, "chrome-profile");
  fs.mkdirSync(path.join(legacy, "Default"), { recursive: true, mode: 0o755 });
  const legacyCookie = path.join(legacy, "Default", "Cookies");
  fs.writeFileSync(legacyCookie, "legacy-" + SENTINEL, { mode: 0o644 });
  fs.chmodSync(legacyCookie, 0o644);
  fs.chmodSync(legacy, 0o755);
  fs.symlinkSync(`box-${process.pid}`, path.join(legacy, "SingletonLock"));

  const live = resolveSitePaths(dir, "live");
  fs.mkdirSync(path.join(live.profile, "Default"), { recursive: true, mode: 0o755 });
  const liveCookie = path.join(live.profile, "Default", "Cookies");
  fs.writeFileSync(liveCookie, "live-" + SENTINEL, { mode: 0o644 });
  fs.symlinkSync(`box-${process.pid}`, path.join(live.profile, "SingletonLock"));

  const stale = resolveSitePaths(dir, "stale");
  fs.mkdirSync(path.join(stale.profile, "Default"), { recursive: true, mode: 0o755 });
  const staleCookie = path.join(stale.profile, "Default", "Cookies");
  fs.writeFileSync(staleCookie, "stale-" + SENTINEL, { mode: 0o644 });
  fs.symlinkSync("box-99999999", path.join(stale.profile, "SingletonLock"));

  const plainDir = tempDir();
  const plainPaths = resolveSitePaths(plainDir, "demo");
  fs.mkdirSync(path.join(plainPaths.profile, "Default"), { recursive: true, mode: 0o755 });
  const plainCookie = path.join(plainPaths.profile, "Default", "Cookies");
  fs.writeFileSync(plainCookie, "plain-" + SENTINEL, { mode: 0o644 });

  sealLeftoverProfiles(createProfileVault(null), plainDir);
  assert.equal(fs.existsSync(plainPaths.profile), true);
  assert.equal(fs.existsSync(plainPaths.vault), false);
  assert.equal(fs.statSync(plainPaths.profile).mode & 0o077, 0);
  assert.equal(fs.statSync(plainCookie).mode & 0o077, 0);
  assert.equal(fs.readFileSync(plainCookie, "utf8"), "plain-" + SENTINEL);

  sealLeftoverProfiles(createProfileVault(KEY), dir);
  assert.equal(fs.readFileSync(legacyCookie, "utf8"), "legacy-" + SENTINEL);
  assert.equal(fs.statSync(legacy).mode & 0o777, 0o755);
  assert.equal(fs.statSync(legacyCookie).mode & 0o777, 0o644);
  assert.equal(fs.existsSync(liveCookie), true);
  assert.equal(fs.readFileSync(liveCookie, "utf8"), "live-" + SENTINEL);
  assert.equal(fs.existsSync(live.vault), false);
  assert.equal(fs.existsSync(stale.profile), false);
  assert.equal(fs.existsSync(stale.vault), true);
  const blob = fs.readFileSync(stale.vault);
  assert.equal(blob.includes(Buffer.from("stale-" + SENTINEL)), false);
  assert.equal(blob.includes(Buffer.from(KEY)), false);
  createProfileVault(KEY).unlockSite(dir, "stale");
  assert.equal(fs.readFileSync(path.join(stale.profile, "Default", "Cookies"), "utf8"), "stale-" + SENTINEL);
});
