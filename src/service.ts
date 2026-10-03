import type { BrowserControl, PageSignals } from "./browser.js";
import type { OriginStore } from "./origins.js";
import {
  PolicyError,
  assertOrigin,
  looksLikeChallengeWidget,
  looksLikeLoginOrChallenge,
  looksLikePasswordField,
  originOfUrl,
  parseHttpUrl,
} from "./policy.js";

export interface ToolText {
  text: string;
  isError?: boolean;
}

export interface Status {
  profileExists: boolean;
  browserOpen: boolean;
  origins: string[];
}

export interface Service {
  status(): Promise<ToolText>;
  login(url: string): Promise<ToolText>;
  confirm(origin: string): Promise<ToolText>;
  open(url: string): Promise<ToolText>;
  read(input: { url?: string; selector?: string }): Promise<ToolText>;
  act(input: { action: string; selector: string; value?: string }): Promise<ToolText>;
}

const LOGIN_INSTRUCTIONS =
  "Complete login in the Chrome window, including any 2FA or CAPTCHA. This server will not type your password or solve a challenge. When you are done, call auth_confirm with the site origin (for example https://example.com).";

const SELECTOR_LIMIT = 500;
const VALUE_LIMIT = 2000;

export function createService(deps: {
  store: OriginStore;
  browser: BrowserControl;
  log?: (line: string) => void;
}): Service {
  const log = deps.log ?? ((line: string) => console.error(line));

  function ok(body: unknown): ToolText {
    return { text: JSON.stringify(body, null, 2) };
  }

  function fail(body: unknown): ToolText {
    return { text: JSON.stringify(body, null, 2), isError: true };
  }

  function policyFailure(error: unknown): ToolText {
    const message = error instanceof Error ? error.message : String(error);
    const reason = error instanceof PolicyError ? "invalid_url" : "browser_error";
    return fail({ ok: false, reason, message });
  }

  function browserFailure(error: unknown, secret?: string): ToolText {
    const raw = error instanceof Error ? error.message : String(error);
    const first = (raw.split("\n")[0] ?? raw).slice(0, 300);
    const message = secret && secret.length > 0 ? first.split(secret).join("[redacted]") : first;
    log(`[login-mcp] browser_error ${message}`);
    return fail({ ok: false, reason: "browser_error", message });
  }

  async function requireConfirmed(url: string): Promise<ToolText | string> {
    let origin: string;
    try {
      parseHttpUrl(url);
      origin = originOfUrl(url);
    } catch (error) {
      return policyFailure(error);
    }
    if (!(await deps.store.has(origin))) {
      return fail({
        ok: false,
        reason: "origin_not_confirmed",
        origin,
        human_action_required: true,
        message: `Origin ${origin} is not confirmed. Finish login in Chrome and call auth_confirm.`,
      });
    }
    return origin;
  }

  return {
    async status() {
      log("[login-mcp] auth_status");
      try {
        const status: Status = {
          profileExists: deps.browser.profileExists(),
          browserOpen: deps.browser.isOpen(),
          origins: await deps.store.list(),
        };
        return ok(status);
      } catch (error) {
        return browserFailure(error);
      }
    },

    async login(url: string) {
      log(`[login-mcp] auth_login url=${safeUrl(url)}`);
      try {
        parseHttpUrl(url);
      } catch (error) {
        return policyFailure(error);
      }
      try {
        await deps.browser.login(url);
      } catch (error) {
        return browserFailure(error);
      }
      return ok({
        opened: true,
        url,
        instructions: LOGIN_INSTRUCTIONS,
      });
    },

    async confirm(origin: string) {
      log("[login-mcp] auth_confirm");
      let valid: string;
      try {
        valid = assertOrigin(origin);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return fail({ ok: false, reason: "invalid_origin", message });
      }
      try {
        const origins = await deps.store.confirm(valid);
        return ok({ origin: valid, origins });
      } catch (error) {
        return browserFailure(error);
      }
    },

    async open(url: string) {
      log(`[login-mcp] auth_open url=${safeUrl(url)}`);
      const confirmed = await requireConfirmed(url);
      if (typeof confirmed !== "string") return confirmed;
      let page: PageSignals;
      try {
        page = await deps.browser.open(url);
      } catch (error) {
        return browserFailure(error);
      }
      const humanActionRequired = looksLikeLoginOrChallenge(page);
      return ok({
        title: page.title,
        url: page.url,
        human_action_required: humanActionRequired,
        message: humanActionRequired
          ? "The page looks like a login or challenge. Stop and let a human finish it in the Chrome window. Do not type a password."
          : undefined,
      });
    },

    async read(input) {
      log(`[login-mcp] auth_read url=${input.url ? safeUrl(input.url) : ""} selector=${input.selector ?? ""}`);
      if (input.selector !== undefined && !validSelector(input.selector)) {
        return fail({ ok: false, reason: "invalid_selector", message: "Selector must be 1-500 characters." });
      }
      let page: PageSignals | null = null;
      if (input.url) {
        const confirmed = await requireConfirmed(input.url);
        if (typeof confirmed !== "string") return confirmed;
        try {
          page = await deps.browser.open(input.url);
        } catch (error) {
          return browserFailure(error);
        }
      } else {
        try {
          page = await deps.browser.inspect();
        } catch (error) {
          return browserFailure(error);
        }
        if (!page) {
          return fail({
            ok: false,
            reason: "no_page",
            message: "No browser page is open. Call auth_open or pass a confirmed url.",
          });
        }
        const gate = await gateCurrentPage(deps.store, page);
        if (gate) return gate;
      }
      let read: { text: string; truncated: boolean };
      try {
        read = await deps.browser.readText(input.selector);
      } catch (error) {
        return browserFailure(error);
      }
      const humanActionRequired = page ? looksLikeLoginOrChallenge(page) : false;
      return ok({
        url: page?.url,
        selector: input.selector ?? null,
        text: read.text,
        truncated: read.truncated,
        human_action_required: humanActionRequired,
      });
    },

    async act(input) {
      log(`[login-mcp] auth_act action=${input.action} selector=${input.selector}`);
      if (input.action !== "click" && input.action !== "fill" && input.action !== "press") {
        return fail({
          ok: false,
          reason: "invalid_action",
          message: 'Action must be "click", "fill", or "press".',
        });
      }
      if (!validSelector(input.selector)) {
        return fail({ ok: false, reason: "invalid_selector", message: "Selector must be 1-500 characters." });
      }
      if (input.value !== undefined && input.value.length > VALUE_LIMIT) {
        return fail({ ok: false, reason: "invalid_value", message: "Value is too long." });
      }
      if ((input.action === "fill" || input.action === "press") && (input.value === undefined || input.value.length === 0)) {
        return fail({
          ok: false,
          reason: "missing_value",
          message: `${input.action} requires a non-empty value.`,
        });
      }
      if (looksLikePasswordField(input.selector, input.value)) {
        return fail({
          ok: false,
          reason: "password_field_refused",
          human_action_required: true,
          message: "Refusing to touch a password field. Type the password yourself in the Chrome window.",
        });
      }
      if (looksLikeChallengeWidget(input.selector, input.value)) {
        return fail({
          ok: false,
          reason: "challenge_refused",
          human_action_required: true,
          message: "Refusing to interact with a CAPTCHA or challenge widget. Finish it in the Chrome window.",
        });
      }
      let page: PageSignals | null;
      try {
        page = await deps.browser.inspect();
      } catch (error) {
        return browserFailure(error, input.value);
      }
      if (!page) {
        return fail({
          ok: false,
          reason: "no_page",
          message: "No browser page is open. Call auth_open first.",
        });
      }
      const gate = await gateCurrentPage(deps.store, page);
      if (gate) return gate;
      if (looksLikeLoginOrChallenge(page)) {
        return fail({
          ok: false,
          reason: "challenge_refused",
          human_action_required: true,
          message: "The current page looks like a login or challenge. Stopping so a human can finish it. No action was performed.",
        });
      }
      try {
        await deps.browser.act(input.action, input.selector, input.value);
      } catch (error) {
        return browserFailure(error, input.value);
      }
      return ok({ ok: true, action: input.action, selector: input.selector });
    },
  };
}

async function gateCurrentPage(store: OriginStore, page: PageSignals): Promise<ToolText | null> {
  let origin: string;
  try {
    origin = originOfUrl(page.url);
  } catch {
    return {
      text: JSON.stringify(
        {
          ok: false,
          reason: "origin_not_confirmed",
          human_action_required: true,
          message: "The current page is not an http(s) page on a confirmed origin.",
        },
        null,
        2,
      ),
      isError: true,
    };
  }
  if (!(await store.has(origin))) {
    return {
      text: JSON.stringify(
        {
          ok: false,
          reason: "origin_not_confirmed",
          origin,
          human_action_required: true,
          message: `Origin ${origin} is not confirmed. Finish login in Chrome and call auth_confirm.`,
        },
        null,
        2,
      ),
      isError: true,
    };
  }
  return null;
}

function validSelector(selector: string): boolean {
  return selector.length > 0 && selector.length <= SELECTOR_LIMIT;
}

function safeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.username || parsed.password) return "[rejected-credential-url]";
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return "[invalid-url]";
  }
}
