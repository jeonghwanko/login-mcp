import { BrowserPolicyError, type BrowserControl, type PageSignals } from "./browser.js";
import { HumanSignalError, type HumanSignals } from "./human-signal.js";
import type { OriginStore, SiteRecord } from "./origins.js";
import {
  PolicyError,
  assertOrigin,
  assertPinnedHost,
  defaultResolveHost,
  looksLikeChallengeWidget,
  looksLikeLoginOrChallenge,
  looksLikePasswordField,
  parseHttpUrl,
  redactUrl,
  scrubPublicText,
  type HostResolver,
} from "./policy.js";
import { assertSiteId, resolveSitePaths, SitePathError } from "./site-path.js";

export interface ToolText {
  text: string;
  isError?: boolean;
}

export interface SiteStatus {
  site: string;
  origins: string[];
  lastUsed: string | null;
  profileExists: boolean;
}

export interface Status {
  browserOpen: boolean;
  openSite: string | null;
  sites: SiteStatus[];
}

export interface Service {
  status(site?: string): Promise<ToolText>;
  login(site: string, url: string): Promise<ToolText>;
  confirm(site: string, origin: string, workOrigin?: string): Promise<ToolText>;
  open(site: string, url: string): Promise<ToolText>;
  read(site: string, input: { url?: string; selector?: string }): Promise<ToolText>;
  act(site: string, input: { action: string; selector: string; value?: string }): Promise<ToolText>;
}

const LOGIN_INSTRUCTIONS =
  "Complete login in the Chrome window, including any 2FA or CAPTCHA. This server will not type your password or solve a challenge. Then click 이 사이트 허용 on the local confirmation tab, or run login-mcp confirm in a terminal and type the code shown in that tab. Within 10 minutes, call auth_confirm with this site id and origin. You may also pass the work origin the human entered.";

const SESSION_EXPIRED =
  "The session expired. A human must log in again in the Chrome window. Page text was not returned. Do not type a password.";

const SELECTOR_LIMIT = 500;
const VALUE_LIMIT = 2000;

export function createService(deps: {
  store: OriginStore;
  browser: BrowserControl;
  human: HumanSignals;
  dataDir?: string;
  log?: (line: string) => void;
  resolveHost?: HostResolver;
}): Service {
  const log = deps.log ?? ((line: string) => console.error(line));
  const resolve = deps.resolveHost ?? defaultResolveHost;

  function ok(body: unknown): ToolText {
    return { text: JSON.stringify(body, null, 2) };
  }

  function fail(body: unknown): ToolText {
    return { text: JSON.stringify(body, null, 2), isError: true };
  }

  function policyFailure(error: unknown, secret?: string): ToolText {
    const message = error instanceof Error ? error.message : String(error);
    const reason =
      error instanceof SitePathError
        ? "invalid_site"
        : error instanceof HumanSignalError
          ? "human_signal_required"
          : error instanceof PolicyError
            ? "invalid_url"
            : "browser_error";
    return fail({
      ok: false,
      reason,
      human_action_required: reason === "human_signal_required" ? true : undefined,
      message: scrubPublicText(message, secret ? [secret] : []),
    });
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
    if (error instanceof SitePathError || error instanceof HumanSignalError || error instanceof PolicyError) {
      return policyFailure(error, secret);
    }
    const raw = error instanceof Error ? error.message : String(error);
    const message = scrubPublicText(raw, secret ? [secret] : []);
    log(`[login-mcp] browser_error ${message}`);
    return fail({ ok: false, reason: "browser_error", message });
  }

  function guardSite(site: string): ToolText | string {
    try {
      const id = assertSiteId(site);
      if (deps.dataDir) resolveSitePaths(deps.dataDir, id);
      return id;
    } catch (error) {
      return policyFailure(error);
    }
  }

  async function screen(input: string): Promise<URL | ToolText> {
    try {
      const url = parseHttpUrl(input);
      await assertPinnedHost(url.hostname, resolve);
      return url;
    } catch (error) {
      return policyFailure(error);
    }
  }

  async function requireConfirmed(site: string, url: string): Promise<ToolText | string> {
    const parsed = await screen(url);
    if (!(parsed instanceof URL)) return parsed;
    if (!(await deps.store.has(site, parsed.origin))) return originNotConfirmed(parsed.origin);
    return parsed.origin;
  }

  function toStatus(record: SiteRecord): SiteStatus {
    return {
      site: record.site,
      origins: record.origins,
      lastUsed: record.lastUsed,
      profileExists: deps.browser.profileExists(record.site),
    };
  }

  return {
    async status(site?: string) {
      log("[login-mcp] auth_status");
      let filter: string | undefined;
      if (site !== undefined && site.length > 0) {
        const id = guardSite(site);
        if (typeof id !== "string") return id;
        filter = id;
      }
      try {
        const listed = await deps.store.list();
        const sites = listed.filter((record) => (filter ? record.site === filter : true)).map(toStatus);
        if (filter && sites.length === 0 && deps.browser.profileExists(filter)) {
          sites.push({ site: filter, origins: [], lastUsed: null, profileExists: true });
        }
        const status: Status = {
          browserOpen: deps.browser.isOpen(),
          openSite: deps.browser.openSite(),
          sites,
        };
        return ok(status);
      } catch (error) {
        return browserFailure(error);
      }
    },

    async login(site: string, url: string) {
      const id = guardSite(site);
      if (typeof id !== "string") return id;
      const parsed = await screen(url);
      if (!(parsed instanceof URL)) return parsed;
      let confirmUrl: string | null = null;
      try {
        confirmUrl = await deps.human.beginLogin(id, parsed.origin);
      } catch (error) {
        return browserFailure(error);
      }
      log(`[login-mcp] auth_login site=${id} url=${safeUrl(parsed.href)}`);
      try {
        await deps.browser.exclusive(id, async (ops) => {
          await ops.login(parsed.href, confirmUrl ?? undefined);
        });
        await deps.store.touch(id);
      } catch (error) {
        return browserFailure(error, confirmUrl ?? undefined);
      }
      return ok({
        opened: true,
        site: id,
        url: redactUrl(parsed.href),
        instructions: LOGIN_INSTRUCTIONS,
      });
    },

    async confirm(site: string, origin: string, workOrigin?: string) {
      const id = guardSite(site);
      if (typeof id !== "string") return id;
      log(`[login-mcp] auth_confirm site=${id}`);
      let primary: string;
      const requested: string[] = [];
      try {
        primary = assertOrigin(origin);
        await assertPinnedHost(new URL(primary).hostname, resolve);
        requested.push(primary);
        if (workOrigin !== undefined && workOrigin.trim().length > 0) {
          const extra = assertOrigin(workOrigin);
          await assertPinnedHost(new URL(extra).hostname, resolve);
          requested.push(extra);
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return fail({ ok: false, reason: "invalid_origin", message: scrubPublicText(message) });
      }
      let approved: string[];
      try {
        approved = await deps.human.assertRecent(id, requested);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return fail({
          ok: false,
          reason: "human_signal_required",
          human_action_required: true,
          message: scrubPublicText(
            message ||
              "A human must allow this site in the Chrome tab (이 사이트 허용) or with login-mcp confirm. The allow signal is missing or older than 10 minutes.",
          ),
        });
      }
      try {
        const origins = await deps.store.confirm(id, approved);
        await deps.store.touch(id);
        return ok({ site: id, origin: primary, workOrigin: requested[1] ?? null, origins });
      } catch (error) {
        return browserFailure(error);
      }
    },

    async open(site: string, url: string) {
      const id = guardSite(site);
      if (typeof id !== "string") return id;
      const confirmed = await requireConfirmed(id, url);
      if (typeof confirmed !== "string") return confirmed;
      log(`[login-mcp] auth_open site=${id} url=${safeUrl(url)}`);
      try {
        return await deps.browser.exclusive(id, async (ops) => {
          let page: PageSignals;
          try {
            page = await ops.open(url);
          } catch (error) {
            return browserFailure(error);
          }
          const gate = await finalOriginGate(deps.store, id, page.url, resolve);
          if (gate) {
            await ops.blank().catch(() => undefined);
            return gate;
          }
          const humanActionRequired = looksLikeLoginOrChallenge(page);
          await deps.store.touch(id);
          return ok({
            title: humanActionRequired ? undefined : oneLine(page.title, 300),
            url: redactUrl(page.url),
            human_action_required: humanActionRequired,
            message: humanActionRequired ? SESSION_EXPIRED : undefined,
          });
        });
      } catch (error) {
        return browserFailure(error);
      }
    },

    async read(site: string, input) {
      const id = guardSite(site);
      if (typeof id !== "string") return id;
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
        const confirmed = await requireConfirmed(id, input.url);
        if (typeof confirmed !== "string") return confirmed;
      }
      log(`[login-mcp] auth_read site=${id} url=${input.url ? safeUrl(input.url) : ""} selector=${oneLine(input.selector ?? "", 200)}`);
      try {
        return await deps.browser.exclusive(id, async (ops) => {
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
          const gate = await finalOriginGate(deps.store, id, page.url, resolve);
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
          const afterGate = await finalOriginGate(deps.store, id, after.url, resolve);
          if (afterGate) {
            await ops.blank().catch(() => undefined);
            return afterGate;
          }
          if (looksLikeLoginOrChallenge(after)) {
            return challengeResult(after.url);
          }
          await deps.store.touch(id);
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

    async act(site: string, input) {
      const id = guardSite(site);
      if (typeof id !== "string") return id;
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
      log(`[login-mcp] auth_act site=${id} action=${input.action} selector=${oneLine(input.selector, 200)}`);
      try {
        return await deps.browser.exclusive(id, async (ops) => {
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
          const gate = await finalOriginGate(deps.store, id, page.url, resolve);
          if (gate) {
            await ops.blank().catch(() => undefined);
            return gate;
          }
          if (looksLikeLoginOrChallenge(page)) {
            return fail({
              ok: false,
              reason: "challenge_refused",
              human_action_required: true,
              message: SESSION_EXPIRED,
            });
          }
          try {
            await ops.act(input.action as "click" | "fill" | "press", input.selector, input.value);
          } catch (error) {
            return browserFailure(error, input.value);
          }
          const after = await ops.inspect();
          if (after) {
            const left = await finalOriginGate(deps.store, id, after.url, resolve);
            if (left) {
              await ops.blank().catch(() => undefined);
              return left;
            }
            if (looksLikeLoginOrChallenge(after)) {
              return fail({
                ok: false,
                reason: "challenge_refused",
                human_action_required: true,
                message: SESSION_EXPIRED,
              });
            }
          }
          await deps.store.touch(id);
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
        message: `Origin ${origin} is not confirmed for this site. Finish login in Chrome, allow the site, and call auth_confirm.`,
      },
      null,
      2,
    ),
    isError: true,
  };
}

async function finalOriginGate(
  store: OriginStore,
  site: string,
  pageUrl: string,
  resolve: HostResolver,
): Promise<ToolText | null> {
  let origin: string;
  try {
    const url = parseHttpUrl(pageUrl);
    await assertPinnedHost(url.hostname, resolve);
    origin = url.origin;
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
  if (!(await store.has(site, origin))) {
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
        message: SESSION_EXPIRED,
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
