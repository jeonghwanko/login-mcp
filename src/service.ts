import { BrowserPolicyError, type BrowserControl, type PageSignals } from "./browser.js";
import type { OriginStore } from "./origins.js";
import {
  PolicyError,
  assertOrigin,
  looksLikeChallengeWidget,
  looksLikeLoginOrChallenge,
  looksLikePasswordField,
  originOfUrl,
  parseHttpUrl,
  redactUrl,
  scrubPublicText,
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

const CHALLENGE_MESSAGE =
  "The page looks like a login or challenge. Page text was not returned. Stop and let a human finish it in the Chrome window. Do not type a password.";

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
    return fail({ ok: false, reason, message: scrubPublicText(message) });
  }

  function browserFailure(error: unknown, secret?: string): ToolText {
    if (error instanceof BrowserPolicyError) {
      return fail({
        ok: false,
        reason: error.reason,
        human_action_required: true,
        message: error.message,
      });
    }
    const raw = error instanceof Error ? error.message : String(error);
    const message = scrubPublicText(raw, secret ? [secret] : []);
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
      return originNotConfirmed(origin);
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
      let safe = "[invalid-url]";
      try {
        safe = safeUrl(parseHttpUrl(url).href);
      } catch (error) {
        return policyFailure(error);
      }
      log(`[login-mcp] auth_login url=${safe}`);
      try {
        await deps.browser.exclusive(async (ops) => {
          await ops.login(url);
        });
      } catch (error) {
        return browserFailure(error);
      }
      return ok({
        opened: true,
        url: redactUrl(url),
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
        return fail({ ok: false, reason: "invalid_origin", message: scrubPublicText(message) });
      }
      try {
        const origins = await deps.store.confirm(valid);
        return ok({ origin: valid, origins });
      } catch (error) {
        return browserFailure(error);
      }
    },

    async open(url: string) {
      const confirmed = await requireConfirmed(url);
      if (typeof confirmed !== "string") return confirmed;
      log(`[login-mcp] auth_open url=${safeUrl(url)}`);
      try {
        return await deps.browser.exclusive(async (ops) => {
          let page: PageSignals;
          try {
            page = await ops.open(url);
          } catch (error) {
            return browserFailure(error);
          }
          const gate = await finalOriginGate(deps.store, page.url);
          if (gate) {
            await ops.blank().catch(() => undefined);
            return gate;
          }
          const humanActionRequired = looksLikeLoginOrChallenge(page);
          return ok({
            title: oneLine(page.title, 300),
            url: redactUrl(page.url),
            human_action_required: humanActionRequired,
            message: humanActionRequired
              ? "The page looks like a login or challenge. Stop and let a human finish it in the Chrome window. Do not type a password."
              : undefined,
          });
        });
      } catch (error) {
        return browserFailure(error);
      }
    },

    async read(input) {
      if (input.selector !== undefined && !validSelector(input.selector)) {
        return fail({ ok: false, reason: "invalid_selector", message: "Selector must be 1-500 characters." });
      }
      if (input.selector && looksLikePasswordField(input.selector)) {
        return fail({
          ok: false,
          reason: "password_field_refused",
          human_action_required: true,
          message: "Refusing to read a password field.",
        });
      }
      if (input.selector && looksLikeChallengeWidget(input.selector)) {
        return fail({
          ok: false,
          reason: "challenge_refused",
          human_action_required: true,
          message: "Refusing to read a CAPTCHA or challenge widget.",
        });
      }
      if (input.url) {
        const confirmed = await requireConfirmed(input.url);
        if (typeof confirmed !== "string") return confirmed;
      }
      log(`[login-mcp] auth_read url=${input.url ? safeUrl(input.url) : ""} selector=${oneLine(input.selector ?? "", 200)}`);
      try {
        return await deps.browser.exclusive(async (ops) => {
          let page: PageSignals | null = null;
          if (input.url) {
            try {
              page = await ops.open(input.url);
            } catch (error) {
              return browserFailure(error);
            }
          } else {
            try {
              page = await ops.inspect();
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
          }
          const gate = await finalOriginGate(deps.store, page.url);
          if (gate) {
            await ops.blank().catch(() => undefined);
            return gate;
          }
          if (looksLikeLoginOrChallenge(page)) {
            return challengeResult(page.url);
          }
          let read: { text: string; truncated: boolean };
          try {
            read = await ops.readText(input.selector);
          } catch (error) {
            return browserFailure(error);
          }
          const after = await ops.inspect();
          if (!after) {
            return fail({
              ok: false,
              reason: "no_page",
              message: "The page closed before it could be read.",
            });
          }
          const afterGate = await finalOriginGate(deps.store, after.url);
          if (afterGate) {
            await ops.blank().catch(() => undefined);
            return afterGate;
          }
          if (looksLikeLoginOrChallenge(after)) {
            return challengeResult(after.url);
          }
          return ok({
            url: redactUrl(after.url),
            selector: input.selector ?? null,
            text: read.text,
            truncated: read.truncated,
            human_action_required: false,
          });
        });
      } catch (error) {
        return browserFailure(error);
      }
    },

    async act(input) {
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
      log(`[login-mcp] auth_act action=${input.action} selector=${oneLine(input.selector, 200)}`);
      try {
        return await deps.browser.exclusive(async (ops) => {
          let page: PageSignals | null;
          try {
            page = await ops.inspect();
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
          const gate = await finalOriginGate(deps.store, page.url);
          if (gate) return gate;
          if (looksLikeLoginOrChallenge(page)) {
            return fail({
              ok: false,
              reason: "challenge_refused",
              human_action_required: true,
              message:
                "The current page looks like a login or challenge. Stopping so a human can finish it. No action was performed.",
            });
          }
          try {
            await ops.act(input.action as "click" | "fill" | "press", input.selector, input.value);
          } catch (error) {
            return browserFailure(error, input.value);
          }
          const after = await ops.inspect();
          if (after) {
            const left = await finalOriginGate(deps.store, after.url);
            if (left) return left;
            if (looksLikeLoginOrChallenge(after)) {
              return fail({
                ok: false,
                reason: "challenge_refused",
                human_action_required: true,
                message:
                  "The page now looks like a login or challenge. Stopping so a human can finish it.",
              });
            }
          }
          return ok({ ok: true, action: input.action, selector: input.selector });
        });
      } catch (error) {
        return browserFailure(error, input.value);
      }
    },
  };
}

function originNotConfirmed(origin: string): ToolText {
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

async function finalOriginGate(store: OriginStore, pageUrl: string): Promise<ToolText | null> {
  let origin: string;
  try {
    origin = originOfUrl(pageUrl);
  } catch {
    return {
      text: JSON.stringify(
        {
          ok: false,
          reason: "origin_not_confirmed",
          human_action_required: true,
          message: "Navigation ended on a page this server will not read. Refusing to continue.",
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
          message: `Navigation left the confirmed origins and ended on ${origin}. Refusing to read or continue.`,
        },
        null,
        2,
      ),
      isError: true,
    };
  }
  return null;
}

function challengeResult(pageUrl: string): ToolText {
  return {
    text: JSON.stringify(
      {
        url: redactUrl(pageUrl),
        human_action_required: true,
        message: CHALLENGE_MESSAGE,
      },
      null,
      2,
    ),
  };
}

function validSelector(selector: string): boolean {
  return selector.length > 0 && selector.length <= SELECTOR_LIMIT;
}

function oneLine(value: string, limit: number): string {
  return value.replace(/[\r\n]/g, " ").slice(0, limit);
}

function safeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.username || parsed.password) return "[rejected-credential-url]";
    return `${parsed.origin}${parsed.pathname}`.slice(0, 200);
  } catch {
    return "[invalid-url]";
  }
}
