import assert from "node:assert/strict";
import test from "node:test";
import type { BrowserControl, BrowserOps, PageSignals } from "../src/browser.ts";
import { HumanSignalError, type HumanSignals } from "../src/human-signal.ts";
import type { OriginStore } from "../src/origins.ts";
import { createService, type Status } from "../src/service.ts";

const SITE = "demo";

function memoryStore(initial: string[] = []): OriginStore & { confirmed: string[]; session: "ok" | "needs_login" } {
  const confirmed = [...initial];
  let session: "ok" | "needs_login" = "ok";
  let lastUsed: string | null = null;
  return {
    confirmed,
    get session() {
      return session;
    },
    async list() {
      const origins = [...confirmed].sort();
      const loginOrigin = origins[0] ?? null;
      return [
        {
          site: SITE,
          origins,
          loginOrigin,
          workOrigins: origins.filter((origin) => origin !== loginOrigin),
          lastUsed,
          session,
        },
      ];
    },
    async has(site: string, origin: string) {
      return site === SITE && confirmed.includes(origin);
    },
    async confirm(site: string, origins: string[]) {
      if (site !== SITE) throw new Error("unexpected site");
      for (const origin of origins) {
        if (!confirmed.includes(origin)) confirmed.push(origin);
      }
      return [...confirmed].sort();
    },
    async touch(_site: string, _when?: Date, next?: "ok" | "needs_login") {
      lastUsed = new Date().toISOString();
      if (next === "ok" || next === "needs_login") session = next;
      return lastUsed;
    },
  };
}

function allowHuman(): HumanSignals {
  return {
    async beginLogin() {
      return null;
    },
    async assertRecent(_site, origins) {
      return origins;
    },
    async allow() {},
    async close() {},
  };
}

async function resolveHost(hostname: string): Promise<string[]> {
  const host = hostname.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (host === "localhost") return ["127.0.0.1"];
  if (host === "example.com" || host.endsWith(".example") || host.endsWith(".example.com")) {
    return ["93.184.216.34"];
  }
  throw new Error(`no dns for ${host}`);
}

function fakeBrowser(
  overrides: Partial<BrowserOps> & Partial<Pick<BrowserControl, "profileExists" | "isOpen" | "openSite" | "close">> = {},
): BrowserControl & { calls: string[] } {
  const calls: string[] = [];
  const page: PageSignals = {
    title: "Dashboard",
    url: "https://example.com/dashboard",
    hasPasswordInput: false,
    textSample: "Hello",
  };
  const ops: BrowserOps = {
    async login(url: string) {
      calls.push(`login ${url}`);
    },
    async open(url: string) {
      calls.push(`open ${url}`);
      return { ...page, url };
    },
    async inspect() {
      calls.push("inspect");
      return page;
    },
    async readText(selector?: string) {
      calls.push(`read ${selector ?? ""}`);
      return { text: "Hello from the page", truncated: false };
    },
    async act(action, selector) {
      calls.push(`act ${action} ${selector}`);
    },
    async blank() {
      calls.push("blank");
    },
  };
  for (const key of ["login", "open", "inspect", "readText", "act", "blank"] as const) {
    const override = overrides[key];
    if (override) ops[key] = override as never;
  }
  return {
    calls,
    profileExists: overrides.profileExists ?? (() => true),
    isOpen: overrides.isOpen ?? (() => false),
    openSite: overrides.openSite ?? (() => null),
    close: overrides.close ?? (async () => {
      calls.push("close");
    }),
    exclusive(_site, fn) {
      return fn(ops);
    },
  };
}

function serviceWith(store: OriginStore, browser: BrowserControl, human: HumanSignals = allowHuman()) {
  return createService({ store, browser, human, log: () => undefined, resolveHost });
}

test("status shape has no cookie fields", async () => {
  const service = serviceWith(memoryStore(["https://example.com"]), fakeBrowser());
  const result = await service.status();
  assert.equal(result.isError, undefined);
  const status = JSON.parse(result.text) as Status;
  assert.deepEqual(Object.keys(status).sort(), ["browserOpen", "lines", "openSite", "sites"]);
  assert.equal(typeof status.browserOpen, "boolean");
  assert.equal(status.openSite, null);
  assert.equal(status.sites.length, 1);
  assert.equal(status.lines.length, 1);
  const site = status.sites[0]!;
  assert.deepEqual(Object.keys(site).sort(), ["lastUsed", "line", "origins", "profileExists", "session", "site"]);
  assert.equal(site.site, SITE);
  assert.deepEqual(site.origins, ["https://example.com"]);
  assert.equal(site.session, "ok");
  assert.equal(site.line, "demo origins=https://example.com lastUsed=- session=ok");
  assert.equal(status.lines[0], site.line);
  assert.equal(typeof site.profileExists, "boolean");
  walkNoSecrets(status);
  assert.equal(result.text.toLowerCase().includes("cookie"), false);
  assert.equal(result.text.includes("?"), false);
});

test("login does not confirm the origin or accept credential URLs", async () => {
  const store = memoryStore();
  const browser = fakeBrowser();
  const service = serviceWith(store, browser);
  const opened = await service.login(SITE, "https://example.com/login");
  assert.equal(opened.isError, undefined);
  const body = JSON.parse(opened.text) as { opened: boolean; instructions: string; site: string };
  assert.equal(body.opened, true);
  assert.equal(body.site, SITE);
  assert.match(body.instructions, /will not type your password/i);
  assert.match(body.instructions, /이 사이트 허용/);
  assert.deepEqual(store.confirmed, []);
  assert.deepEqual(browser.calls, ["login https://example.com/login"]);

  const rejected = await service.login(SITE, "https://user:secret@example.com/login");
  assert.equal(rejected.isError, true);
  assert.match(rejected.text, /credentials/);
  assert.equal(rejected.text.includes("secret"), false);
  assert.deepEqual(browser.calls, ["login https://example.com/login"]);
});

test("login result does not include the human confirmation url", async () => {
  const browser = fakeBrowser({
    async login() {
      browser.calls.push("login");
      throw new Error("navigation failed http://127.0.0.1:9/allow/super-secret-nonce");
    },
  });
  const human: HumanSignals = {
    async beginLogin() {
      return "http://127.0.0.1:9/allow/super-secret-nonce";
    },
    async assertRecent() {
      return [];
    },
    async allow() {},
    async close() {},
  };
  const service = serviceWith(memoryStore(), browser, human);
  const result = await service.login(SITE, "https://example.com/login");
  assert.equal(result.isError, true);
  assert.equal(result.text.includes("super-secret-nonce"), false);
});

test("unconfirmed origin read is refused", async () => {
  const browser = fakeBrowser();
  const service = serviceWith(memoryStore(), browser);
  const opened = await service.open(SITE, "https://example.com/app");
  assert.equal(opened.isError, true);
  assert.match(opened.text, /origin_not_confirmed/);

  const read = await service.read(SITE, { url: "https://example.com/app" });
  assert.equal(read.isError, true);
  assert.match(read.text, /origin_not_confirmed/);
  assert.equal(read.text.toLowerCase().includes("cookie"), false);

  const acted = await service.act(SITE, { action: "click", selector: "button.go" });
  assert.equal(acted.isError, true);
  assert.match(acted.text, /origin_not_confirmed|no_page/);
  assert.deepEqual(browser.calls, ["inspect", "blank"]);
});

test("site id traversal is rejected", async () => {
  const browser = fakeBrowser();
  const service = serviceWith(memoryStore(), browser);
  for (const site of ["../etc", "..", "foo/bar", "/etc/passwd", "demo/../../chrome-profile", "a\\b"]) {
    const result = await service.login(site, "https://example.com/secret-path");
    assert.equal(result.isError, true, site);
    assert.match(result.text, /invalid_site|not allowed/);
    assert.equal(result.text.includes("secret-path"), false, site);
  }
  assert.deepEqual(browser.calls, []);
});

test("confirm without a human signal is refused", async () => {
  const store = memoryStore();
  const human: HumanSignals = {
    async beginLogin() {
      return null;
    },
    async assertRecent() {
      throw new HumanSignalError("A recent human allow signal is required.");
    },
    async allow() {
      throw new Error("confirm must not mint a human signal");
    },
    async close() {},
  };
  const service = serviceWith(store, fakeBrowser(), human);
  const result = await service.confirm(SITE, "https://example.com", "https://www.example.com");
  assert.equal(result.isError, true);
  assert.match(result.text, /human_signal_required/);
  assert.equal(result.text.toLowerCase().includes("cookie"), false);
  assert.deepEqual(store.confirmed, []);
});

test("act refuses password fields and challenge widgets before any browser action", async () => {
  const browser = fakeBrowser({
    async inspect() {
      browser.calls.push("inspect");
      return {
        title: "Dashboard",
        url: "https://example.com/dashboard",
        hasPasswordInput: false,
        textSample: "Hello",
      };
    },
  });
  const service = serviceWith(memoryStore(["https://example.com"]), browser);

  const password = await service.act(SITE, {
    action: "fill",
    selector: 'input[type="password"]',
    value: "hunter2",
  });
  assert.equal(password.isError, true);
  assert.match(password.text, /password_field_refused/);
  assert.equal(password.text.includes("hunter2"), false);

  const widget = await service.act(SITE, {
    action: "click",
    selector: "iframe.g-recaptcha",
  });
  assert.equal(widget.isError, true);
  assert.match(widget.text, /challenge_refused/);
  assert.deepEqual(browser.calls, []);
});

test("act refuses to continue on a login page and does not perform the action", async () => {
  const browser = fakeBrowser({
    async inspect() {
      browser.calls.push("inspect");
      return {
        title: "Sign in",
        url: "https://example.com/login",
        hasPasswordInput: true,
        textSample: "Enter your password",
      };
    },
  });
  const service = serviceWith(memoryStore(["https://example.com"]), browser);
  const result = await service.act(SITE, { action: "click", selector: "button.next" });
  assert.equal(result.isError, true);
  assert.match(result.text, /human_action_required/);
  assert.match(result.text, /session expired/i);
  assert.match(result.text, /log in again/i);
  assert.deepEqual(browser.calls, ["inspect"]);
});

test("confirmed open returns title, url, and a human-action flag", async () => {
  const service = serviceWith(memoryStore(["https://example.com"]), fakeBrowser());
  const result = await service.open(SITE, "https://example.com/dashboard");
  const body = JSON.parse(result.text) as {
    title: string;
    url: string;
    human_action_required: boolean;
  };
  assert.equal(result.isError, undefined);
  assert.equal(body.title, "Dashboard");
  assert.equal(body.url, "https://example.com/dashboard");
  assert.equal(body.human_action_required, false);
});

test("open and read drop cross-origin redirects without returning the other page", async () => {
  const browser = fakeBrowser({
    async open(url: string) {
      browser.calls.push(`open ${url}`);
      return {
        title: "SECRET-TITLE",
        url: "https://bank.example/account?code=secret-token#access_token=zzz",
        hasPasswordInput: false,
        textSample: "balance",
      };
    },
    async readText() {
      browser.calls.push("read");
      return { text: "secret balance", truncated: false };
    },
  });
  const service = serviceWith(memoryStore(["https://example.com"]), browser);
  const opened = await service.open(SITE, "https://example.com/go");
  assert.equal(opened.isError, true);
  assert.match(opened.text, /origin_not_confirmed/);
  assert.match(opened.text, /bank\.example/);
  assert.equal(opened.text.includes("secret-token"), false);
  assert.equal(opened.text.includes("SECRET-TITLE"), false);
  assert.equal(opened.text.includes("account"), false);
  const read = await service.read(SITE, { url: "https://example.com/go" });
  assert.equal(read.isError, true);
  assert.equal(read.text.includes("secret balance"), false);
  assert.equal(read.text.includes("secret-token"), false);
  assert.deepEqual(browser.calls, ["open https://example.com/go", "blank", "open https://example.com/go", "blank"]);
});

test("read does not return text when a confirmed site lands on a login page", async () => {
  const browser = fakeBrowser({
    async open(url: string) {
      browser.calls.push(`open ${url}`);
      return {
        title: "Sign in",
        url: "https://example.com/login",
        hasPasswordInput: true,
        textSample: "Enter your password",
      };
    },
    async readText() {
      browser.calls.push("read");
      return { text: "Enter your password hunter2", truncated: false };
    },
  });
  const service = serviceWith(memoryStore(["https://example.com"]), browser);
  const result = await service.read(SITE, { url: "https://example.com/login" });
  const body = JSON.parse(result.text) as { human_action_required?: boolean; message?: string; text?: string };
  assert.equal(body.human_action_required, true);
  assert.match(body.message ?? "", /session expired/i);
  assert.match(body.message ?? "", /log in again/i);
  assert.equal("text" in body, false);
  assert.equal(result.text.includes("hunter2"), false);
  assert.deepEqual(browser.calls, ["open https://example.com/login"]);
});

test("login refuses metadata hosts and does not echo the path", async () => {
  const browser = fakeBrowser();
  const service = serviceWith(memoryStore(), browser);
  const rejected = await service.login(SITE, "http://169.254.169.254/latest/meta-data/iam/secret");
  assert.equal(rejected.isError, true);
  assert.equal(rejected.text.includes("secret"), false);
  assert.equal(rejected.text.includes("meta-data"), false);
  assert.deepEqual(browser.calls, []);
});

test("login refuses a DNS name that resolves to a metadata address", async () => {
  const browser = fakeBrowser();
  const service = createService({
    store: memoryStore(),
    browser,
    human: allowHuman(),
    log: () => undefined,
    resolveHost: async () => ["93.184.216.34", "169.254.169.254"],
  });
  const rejected = await service.login(SITE, "https://rebind.example/latest/meta-data/secret");
  assert.equal(rejected.isError, true);
  assert.match(rejected.text, /link-local|metadata|unspecified/);
  assert.equal(rejected.text.includes("secret"), false);
  assert.equal(rejected.text.includes("meta-data"), false);
  assert.deepEqual(browser.calls, []);
});

test("fill errors do not return the typed value", async () => {
  const browser = fakeBrowser({
    async act() {
      browser.calls.push("act");
      throw new Error("cannot fill super-secret-value");
    },
  });
  const service = serviceWith(memoryStore(["https://example.com"]), browser);
  const result = await service.act(SITE, { action: "fill", selector: "input[name=q]", value: "super-secret-value" });
  assert.equal(result.isError, true);
  assert.equal(result.text.includes("super-secret-value"), false);
});

test("same-origin open redacts credential query values", async () => {
  const browser = fakeBrowser({
    async open(url: string) {
      browser.calls.push(`open ${url}`);
      return {
        title: "Dashboard",
        url: "https://example.com/cb?code=secret-token&tab=1#access_token=zzz",
        hasPasswordInput: false,
        textSample: "Hello",
      };
    },
  });
  const service = serviceWith(memoryStore(["https://example.com"]), browser);
  const result = await service.open(SITE, "https://example.com/cb");
  assert.equal(result.isError, undefined);
  const body = JSON.parse(result.text) as { url: string };
  assert.equal(body.url.includes("secret-token"), false);
  assert.equal(body.url.includes("access_token"), false);
  assert.match(body.url, /tab=1/);
});


test("origin pair allows the login and work origins and blanks any other origin", async () => {
  const store = memoryStore(["https://auth.example", "https://www.example"]);
  const browser = fakeBrowser({
    async open(url: string) {
      browser.calls.push(`open ${url}`);
      if (url.endsWith("/hop")) {
        return {
          title: "SECRET-TITLE",
          url: "https://bank.example/account?token=secret-token",
          hasPasswordInput: false,
          textSample: "balance",
        };
      }
      return {
        title: "Work",
        url,
        hasPasswordInput: false,
        textSample: "inbox",
      };
    },
  });
  const service = serviceWith(store, browser);
  const work = await service.open(SITE, "https://www.example/inbox");
  assert.equal(work.isError, undefined);
  const login = await service.open(SITE, "https://auth.example/session");
  assert.equal(login.isError, undefined);
  const hopped = await service.open(SITE, "https://www.example/hop");
  assert.equal(hopped.isError, true);
  assert.match(hopped.text, /origin_not_confirmed/);
  assert.match(hopped.text, /human_action_required/);
  assert.equal(hopped.text.includes("secret-token"), false);
  assert.equal(hopped.text.includes("SECRET-TITLE"), false);
  assert.equal(hopped.text.includes("account"), false);
  assert.ok(browser.calls.includes("blank"));
});

test("status session is needs_login after a login page and the line has no query secrets", async () => {
  const store = memoryStore(["https://example.com"]);
  let loginPage = true;
  const browser = fakeBrowser({
    async open(url: string) {
      browser.calls.push(`open ${url}`);
      if (loginPage) {
        return {
          title: "Sign in",
          url: "https://example.com/login?token=secret-token&next=/home",
          hasPasswordInput: true,
          textSample: "Enter your password",
        };
      }
      return {
        title: "Dashboard",
        url: "https://example.com/dashboard",
        hasPasswordInput: false,
        textSample: "Hello",
      };
    },
  });
  const service = serviceWith(store, browser);
  const expired = await service.open(SITE, "https://example.com/login");
  const expiredBody = JSON.parse(expired.text) as { human_action_required?: boolean };
  assert.equal(expiredBody.human_action_required, true);
  assert.equal(expired.text.includes("secret-token"), false);
  const needs = JSON.parse((await service.status()).text) as Status;
  assert.equal(needs.sites[0]?.session, "needs_login");
  assert.match(needs.lines[0] ?? "", /^demo origins=https:\/\/example.com lastUsed=.+ session=needs_login$/);
  assert.equal((needs.lines[0] ?? "").includes("secret-token"), false);
  assert.equal((needs.lines[0] ?? "").includes("?"), false);
  assert.equal((needs.lines[0] ?? "").toLowerCase().includes("cookie"), false);
  loginPage = false;
  const again = await service.open(SITE, "https://example.com/dashboard");
  assert.equal(again.isError, undefined);
  const okStatus = JSON.parse((await service.status()).text) as Status;
  assert.equal(okStatus.sites[0]?.session, "ok");
  assert.match(okStatus.lines[0] ?? "", /session=ok$/);
});

test("open, read, and act re-resolve DNS pins and reject metadata answers", async () => {
  const store = memoryStore(["https://example.com"]);
  const browser = fakeBrowser();
  const launches: Array<{ pins?: { hostname: string; addresses: readonly string[] }[]; relaunch?: boolean }> = [];
  let lookups = 0;
  let answers = ["93.184.216.34"];
  const recording = {
    ...browser,
    exclusive(
      site: string,
      fn: Parameters<BrowserControl["exclusive"]>[1],
      options?: Parameters<BrowserControl["exclusive"]>[2],
    ) {
      launches.push(options ?? {});
      return browser.exclusive(site, fn);
    },
  };
  const service = createService({
    store,
    browser: recording,
    human: allowHuman(),
    log: () => undefined,
    resolveHost: async (hostname: string) => {
      lookups += 1;
      if (hostname === "rebind.example") return ["169.254.169.254"];
      return answers;
    },
  });
  const beforeOpen = lookups;
  const opened = await service.open(SITE, "https://example.com/dashboard");
  assert.equal(opened.isError, undefined);
  assert.ok(lookups > beforeOpen);
  const openLaunch = launches.at(-1);
  assert.equal(openLaunch?.relaunch, true);
  assert.ok(openLaunch?.pins?.some((pin) => pin.hostname === "example.com" && pin.addresses.includes("93.184.216.34")));

  const beforeRead = lookups;
  const read = await service.read(SITE, { url: "https://example.com/dashboard" });
  assert.equal(read.isError, undefined);
  assert.ok(lookups > beforeRead);
  assert.equal(launches.at(-1)?.relaunch, true);

  const beforeAct = lookups;
  const acted = await service.act(SITE, { action: "click", selector: "button.go" });
  assert.equal(acted.isError, undefined);
  assert.ok(lookups > beforeAct);
  assert.equal(launches.at(-1)?.relaunch, false);

  answers = ["169.254.169.254", "93.184.216.34"];
  const callsBefore = browser.calls.length;
  const rejected = await service.open(SITE, "https://example.com/secret-path");
  assert.equal(rejected.isError, true);
  assert.match(rejected.text, /link-local|metadata|unspecified/);
  assert.equal(rejected.text.includes("secret-path"), false);
  assert.equal(browser.calls.length, callsBefore);

  const foreign = await service.open(SITE, "https://rebind.example/latest/meta-data/secret");
  assert.equal(foreign.isError, true);
  assert.match(foreign.text, /link-local|metadata|unspecified/);
  assert.equal(foreign.text.includes("secret"), false);
  assert.equal(foreign.text.includes("meta-data"), false);
  assert.equal(browser.calls.length, callsBefore);
});

function walkNoSecrets(value: unknown): void {
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    assert.equal(/cookie|token|password|storage|authorization/i.test(key), false, key);
    walkNoSecrets(child);
  }
}
