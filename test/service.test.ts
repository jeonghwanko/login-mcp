import assert from "node:assert/strict";
import test from "node:test";
import type { BrowserControl, PageSignals } from "../src/browser.ts";
import type { OriginStore } from "../src/origins.ts";
import { createService, type Status } from "../src/service.ts";

function memoryStore(initial: string[] = []): OriginStore & { confirmed: string[] } {
  const confirmed = [...initial];
  return {
    confirmed,
    async list() {
      return [...confirmed].sort();
    },
    async has(origin: string) {
      return confirmed.includes(origin);
    },
    async confirm(origin: string) {
      if (!confirmed.includes(origin)) confirmed.push(origin);
      return [...confirmed].sort();
    },
  };
}

function fakeBrowser(overrides: Partial<BrowserControl> = {}): BrowserControl & {
  calls: string[];
} {
  const calls: string[] = [];
  const page: PageSignals = {
    title: "Dashboard",
    url: "https://example.com/dashboard",
    hasPasswordInput: false,
    textSample: "Hello",
  };
  const browser: BrowserControl & { calls: string[] } = {
    calls,
    profileExists: () => true,
    isOpen: () => false,
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
    async close() {
      calls.push("close");
    },
  };
  return Object.assign(browser, overrides, { calls });
}

test("status shape is profile, browser, and origins only", async () => {
  const service = createService({
    store: memoryStore(["https://example.com"]),
    browser: fakeBrowser(),
    log: () => undefined,
  });
  const result = await service.status();
  assert.equal(result.isError, undefined);
  const status = JSON.parse(result.text) as Status;
  assert.deepEqual(Object.keys(status).sort(), ["browserOpen", "origins", "profileExists"]);
  assert.equal(typeof status.profileExists, "boolean");
  assert.equal(typeof status.browserOpen, "boolean");
  assert.deepEqual(status.origins, ["https://example.com"]);
  assert.equal(result.text.includes("cookie"), false);
});

test("login does not confirm the origin or accept credential URLs", async () => {
  const store = memoryStore();
  const browser = fakeBrowser();
  const service = createService({ store, browser, log: () => undefined });
  const opened = await service.login("https://example.com/login");
  assert.equal(opened.isError, undefined);
  const body = JSON.parse(opened.text) as { opened: boolean; instructions: string };
  assert.equal(body.opened, true);
  assert.match(body.instructions, /will not type your password/i);
  assert.deepEqual(store.confirmed, []);
  assert.deepEqual(browser.calls, ["login https://example.com/login"]);

  const rejected = await service.login("https://user:secret@example.com/login");
  assert.equal(rejected.isError, true);
  assert.match(rejected.text, /credentials/);
  assert.equal(rejected.text.includes("secret"), false);
  assert.deepEqual(browser.calls, ["login https://example.com/login"]);
});

test("open, read, and act refuse unconfirmed origins without touching the page", async () => {
  const browser = fakeBrowser();
  const service = createService({
    store: memoryStore(),
    browser,
    log: () => undefined,
  });
  const opened = await service.open("https://example.com/app");
  assert.equal(opened.isError, true);
  assert.match(opened.text, /origin_not_confirmed/);

  const read = await service.read({ url: "https://example.com/app" });
  assert.equal(read.isError, true);
  assert.match(read.text, /origin_not_confirmed/);

  const acted = await service.act({ action: "click", selector: "button.go" });
  assert.equal(acted.isError, true);
  assert.match(acted.text, /origin_not_confirmed|no_page/);
  assert.deepEqual(browser.calls, ["inspect"]);
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
  const service = createService({
    store: memoryStore(["https://example.com"]),
    browser,
    log: () => undefined,
  });

  const password = await service.act({
    action: "fill",
    selector: 'input[type="password"]',
    value: "hunter2",
  });
  assert.equal(password.isError, true);
  assert.match(password.text, /password_field_refused/);
  assert.equal(password.text.includes("hunter2"), false);

  const widget = await service.act({
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
  const service = createService({
    store: memoryStore(["https://example.com"]),
    browser,
    log: () => undefined,
  });
  const result = await service.act({ action: "click", selector: "button.next" });
  assert.equal(result.isError, true);
  assert.match(result.text, /human_action_required/);
  assert.deepEqual(browser.calls, ["inspect"]);
});

test("confirmed open returns title, url, and a human-action flag", async () => {
  const service = createService({
    store: memoryStore(["https://example.com"]),
    browser: fakeBrowser(),
    log: () => undefined,
  });
  const result = await service.open("https://example.com/dashboard");
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
