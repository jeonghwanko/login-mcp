import fs from "node:fs";
import { chromium, type BrowserContext, type Page } from "playwright-core";
import type { Config } from "./config.js";

export interface PageSignals {
  title: string;
  url: string;
  hasPasswordInput: boolean;
  textSample: string;
}

export interface BrowserControl {
  profileExists(): boolean;
  isOpen(): boolean;
  login(url: string): Promise<void>;
  open(url: string): Promise<PageSignals>;
  inspect(): Promise<PageSignals | null>;
  readText(selector?: string): Promise<{ text: string; truncated: boolean }>;
  act(action: "click" | "fill" | "press", selector: string, value?: string): Promise<void>;
  close(): Promise<void>;
}

const TEXT_SAMPLE_LIMIT = 2000;
const READ_LIMIT = 8000;

export function createChromeBrowser(config: Config): BrowserControl {
  let context: BrowserContext | null = null;
  let chain: Promise<void> = Promise.resolve();

  function lock<T>(fn: () => Promise<T>): Promise<T> {
    const run = chain.then(fn, fn);
    chain = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  function profileExists(): boolean {
    return fs.existsSync(config.userDataDir);
  }

  function isOpen(): boolean {
    return context !== null && context.browser()?.isConnected() === true;
  }

  async function ensureContext(): Promise<BrowserContext> {
    if (context?.browser()?.isConnected()) return context;
    context = null;
    try {
      context = await chromium.launchPersistentContext(config.userDataDir, {
        channel: "chrome",
        headless: false,
        viewport: null,
      });
    } catch (error) {
      context = null;
      throw new Error(explainLaunchError(error));
    }
    context.on("close", () => {
      context = null;
    });
    return context;
  }

  async function getPage(ctx: BrowserContext): Promise<Page> {
    const existing = ctx.pages().filter((page) => !page.isClosed());
    if (existing.length > 0) return existing[0]!;
    return ctx.newPage();
  }

  async function signals(page: Page): Promise<PageSignals> {
    const title = await page.title().catch(() => "");
    const hasPasswordInput = await page
      .locator('input[type="password"]')
      .count()
      .then((count) => count > 0)
      .catch(() => false);
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

  return {
    profileExists,
    isOpen,
    login(url: string) {
      return lock(async () => {
        const page = await getPage(await ensureContext());
        await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 }).catch((error: unknown) => {
          const message = error instanceof Error ? error.message : String(error);
          if (!/timeout/i.test(message)) throw error;
        });
      });
    },
    open(url: string) {
      return lock(async () => {
        const page = await getPage(await ensureContext());
        await page.goto(url, { waitUntil: "domcontentloaded", timeout: 20000 });
        return signals(page);
      });
    },
    inspect() {
      return lock(async () => {
        if (!context || context.browser()?.isConnected() !== true) return null;
        const pages = context.pages().filter((page) => !page.isClosed());
        if (pages.length === 0) return null;
        return signals(pages[0]!);
      });
    },
    readText(selector?: string) {
      return lock(async () => {
        const page = requireOpenPage();
        if (!selector) {
          const text = await page.evaluate(
            (limit) => (document.body?.innerText ?? "").slice(0, limit + 1),
            READ_LIMIT,
          );
          return trimText(text, READ_LIMIT);
        }
        const locator = page.locator(selector).first();
        if ((await locator.count()) === 0) {
          throw new Error("Selector did not match any element.");
        }
        const text = await locator.innerText({ timeout: 8000 });
        return trimText(text, READ_LIMIT);
      });
    },
    act(action, selector, value) {
      return lock(async () => {
        const page = requireOpenPage();
        const locator = page.locator(selector).first();
        if (action === "click") {
          await locator.click({ timeout: 8000 });
          return;
        }
        if (action === "fill") {
          await locator.fill(value ?? "", { timeout: 8000 });
          return;
        }
        await locator.press(value ?? "", { timeout: 8000 });
      });
    },
    close() {
      return lock(async () => {
        const ctx = context;
        context = null;
        if (ctx) await ctx.close().catch(() => undefined);
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
  const first = message.split("\n")[0] ?? message;
  if (/singleton|already in use|ProcessSingleton|profile directory/i.test(message)) {
    return `Chrome is already running with this profile. Close that Chrome window and retry. ${first}`;
  }
  return `Failed to open Chrome. ${first}`;
}
