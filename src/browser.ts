import fs from "node:fs";
import { chromium, type BrowserContext, type Locator, type Page } from "playwright-core";
import type { Config } from "./config.js";
import { createMutex } from "./mutex.js";
import {
  elementIsChallenge,
  elementIsPassword,
  scrubPublicText,
  type ElementFacts,
} from "./policy.js";
import { preparePrivateDir } from "./session-path.js";

export interface PageSignals {
  title: string;
  url: string;
  hasPasswordInput: boolean;
  textSample: string;
}

/** Operations that already hold the browser mutex. Do not call exclusive from these. */
export interface BrowserOps {
  login(url: string): Promise<void>;
  open(url: string): Promise<PageSignals>;
  inspect(): Promise<PageSignals | null>;
  readText(selector?: string): Promise<{ text: string; truncated: boolean }>;
  act(action: "click" | "fill" | "press", selector: string, value?: string): Promise<void>;
  blank(): Promise<void>;
}

export interface BrowserControl {
  profileExists(): boolean;
  isOpen(): boolean;
  exclusive<T>(fn: (ops: BrowserOps) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

export class BrowserPolicyError extends Error {
  readonly reason: "password_field_refused" | "challenge_refused";

  constructor(reason: "password_field_refused" | "challenge_refused", message: string) {
    super(message);
    this.name = "BrowserPolicyError";
    this.reason = reason;
  }
}

const TEXT_SAMPLE_LIMIT = 2000;
const READ_LIMIT = 8000;
const LAUNCH_TIMEOUT_MS = 30_000;
const NAV_TIMEOUT_MS = 20_000;
const LOGIN_NAV_TIMEOUT_MS = 15_000;
const ACTION_TIMEOUT_MS = 8_000;

export function createChromeBrowser(config: Config): BrowserControl {
  let context: BrowserContext | null = null;
  const lock = createMutex();

  function profileExists(): boolean {
    try {
      const st = fs.lstatSync(config.userDataDir);
      return st.isDirectory() && !st.isSymbolicLink();
    } catch {
      return false;
    }
  }

  function isOpen(): boolean {
    return context !== null && context.browser()?.isConnected() === true;
  }

  async function ensureContext(): Promise<BrowserContext> {
    preparePrivateDir(config.userDataDir);
    if (context?.browser()?.isConnected()) return context;
    context = null;
    try {
      context = await chromium.launchPersistentContext(config.userDataDir, {
        channel: "chrome",
        headless: false,
        viewport: null,
        timeout: LAUNCH_TIMEOUT_MS,
        acceptDownloads: false,
        chromiumSandbox: true,
        handleSIGINT: false,
        handleSIGTERM: false,
        handleSIGHUP: false,
        args: ["--disable-sync", "--no-first-run", "--no-default-browser-check"],
      });
    } catch (error) {
      context = null;
      throw new Error(explainLaunchError(error));
    }
    context.setDefaultNavigationTimeout(NAV_TIMEOUT_MS);
    context.setDefaultTimeout(ACTION_TIMEOUT_MS);
    context.on("close", () => {
      context = null;
    });
    try {
      preparePrivateDir(config.userDataDir);
    } catch {
      await context.close().catch(() => undefined);
      context = null;
      throw new Error("Chrome profile directory could not be kept private.");
    }
    return context;
  }

  async function getPage(ctx: BrowserContext): Promise<Page> {
    const existing = ctx.pages().filter((page) => !page.isClosed());
    if (existing.length > 0) return existing[0]!;
    return ctx.newPage();
  }

  async function pageHasPassword(page: Page): Promise<boolean> {
    for (const frame of page.frames()) {
      const count = await frame
        .locator('input[type="password" i]')
        .count()
        .catch(() => 0);
      if (count > 0) return true;
    }
    return false;
  }

  async function signals(page: Page): Promise<PageSignals> {
    const title = await page.title().catch(() => "");
    const hasPasswordInput = await pageHasPassword(page);
    const textSample = await page
      .evaluate((limit) => (document.body?.innerText ?? "").slice(0, limit), TEXT_SAMPLE_LIMIT)
      .catch(() => "");
    return { title, url: page.url(), hasPasswordInput, textSample };
  }

  function requireOpenPage(): Page {
    if (!context || context.browser()?.isConnected() !== true) {
      throw new Error("No browser page is open. Call auth_open or auth_login first.");
    }
    const pages = context.pages().filter((page) => !page.isClosed());
    if (pages.length === 0) {
      throw new Error("No browser page is open. Call auth_open or auth_login first.");
    }
    return pages[0]!;
  }

  async function factsOf(locator: Locator): Promise<ElementFacts | null> {
    if ((await locator.count()) === 0) return null;
    return locator.evaluate((el) => {
      const attr = (name: string): string | null => {
        const value = el.getAttribute(name);
        return value == null ? null : value.slice(0, 200);
      };
      return {
        tag: (el.tagName || "").toLowerCase().slice(0, 40),
        type: attr("type"),
        autocomplete: attr("autocomplete"),
        name: attr("name"),
        id: attr("id"),
        className: attr("class"),
        src: attr("src"),
        title: attr("title"),
        role: attr("role"),
      };
    });
  }

  function refuseSensitive(facts: ElementFacts | null): void {
    if (!facts) return;
    if (elementIsPassword(facts)) {
      throw new BrowserPolicyError(
        "password_field_refused",
        "Refusing to touch a password field. Type the password yourself in the Chrome window.",
      );
    }
    if (elementIsChallenge(facts)) {
      throw new BrowserPolicyError(
        "challenge_refused",
        "Refusing to interact with a CAPTCHA or challenge widget. Finish it in the Chrome window.",
      );
    }
  }

  const ops: BrowserOps = {
    async login(url: string) {
      const page = await getPage(await ensureContext());
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: LOGIN_NAV_TIMEOUT_MS }).catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        if (!/timeout/i.test(message)) throw error;
      });
    },
    async open(url: string) {
      const page = await getPage(await ensureContext());
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: NAV_TIMEOUT_MS });
      return signals(page);
    },
    async inspect() {
      if (!context || context.browser()?.isConnected() !== true) return null;
      const pages = context.pages().filter((page) => !page.isClosed());
      if (pages.length === 0) return null;
      return signals(pages[0]!);
    },
    async readText(selector?: string) {
      const page = requireOpenPage();
      if (!selector) {
        const text = await page.evaluate(
          (limit) => (document.body?.innerText ?? "").slice(0, limit + 1),
          READ_LIMIT,
        );
        return trimText(text, READ_LIMIT);
      }
      const locator = page.locator(selector).first();
      const facts = await factsOf(locator);
      if (!facts) throw new Error("Selector did not match any element.");
      refuseSensitive(facts);
      const text = await locator.innerText({ timeout: ACTION_TIMEOUT_MS });
      return trimText(text, READ_LIMIT);
    },
    async act(action, selector, value) {
      const page = requireOpenPage();
      const locator = page.locator(selector).first();
      const facts = await factsOf(locator);
      if (!facts) throw new Error("Selector did not match any element.");
      refuseSensitive(facts);
      if (action === "click") {
        await locator.click({ timeout: ACTION_TIMEOUT_MS });
        return;
      }
      if (action === "fill") {
        await locator.fill(value ?? "", { timeout: ACTION_TIMEOUT_MS });
        return;
      }
      await locator.press(value ?? "", { timeout: ACTION_TIMEOUT_MS });
    },
    async blank() {
      if (!context || context.browser()?.isConnected() !== true) return;
      const pages = context.pages().filter((page) => !page.isClosed());
      const page = pages[0];
      if (!page) return;
      await page.goto("about:blank", { timeout: 5000 }).catch(() => undefined);
    },
  };

  return {
    profileExists,
    isOpen,
    exclusive<T>(fn: (ops: BrowserOps) => Promise<T>): Promise<T> {
      return lock(() => fn(ops));
    },
    close() {
      return lock(async () => {
        const ctx = context;
        context = null;
        if (ctx) await ctx.close().catch(() => undefined);
        try {
          if (fs.existsSync(config.userDataDir)) preparePrivateDir(config.userDataDir);
        } catch {
          // Closing must not fail just because a later chmod lost a race.
        }
      });
    },
  };
}

function trimText(text: string, limit: number): { text: string; truncated: boolean } {
  if (text.length <= limit) return { text, truncated: false };
  return { text: text.slice(0, limit), truncated: true };
}

function explainLaunchError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const first = scrubPublicText(message);
  if (/singleton|already in use|ProcessSingleton|profile directory/i.test(message)) {
    return `Chrome is already running with this profile. Close that Chrome window and retry. ${first}`;
  }
  return `Failed to open Chrome. ${first}`;
}
