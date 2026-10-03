#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createChromeBrowser } from "./browser.js";
import { createProfileVault, sealLeftoverProfiles } from "./vault.js";
import { getConfig } from "./config.js";
import { confirmFromTerminal, createHumanSignals } from "./human-signal.js";
import { createFileStore } from "./origins.js";
import { assertPinnedHost, defaultResolveHost } from "./policy.js";
import { createService, type ToolText } from "./service.js";

const INSTRUCTIONS =
  "Reuse a human-completed Chrome login for one site id at a time. Profiles are not shared across sites. Never type, store, or request passwords. Never export cookies or storage. The 이 사이트 허용 button records the human allow signal and confirms the login and work origins immediately. auth_confirm remains for the terminal confirm command and only works for 10 minutes after that signal. If a tool returns human_action_required, stop and let the human finish in the open Chrome window. Do not solve CAPTCHA, 2FA, or bot checks. If a navigation is refused because it left the confirmed origins, do not retry it or ask for the page text.";

const siteField = z
  .string()
  .describe("Site id: 1-64 characters of a-z, 0-9, underscore, or hyphen. Each site has its own Chrome profile.");

function toContent(result: ToolText) {
  return {
    content: [{ type: "text" as const, text: result.text }],
    isError: result.isError ?? false,
  };
}

function argValue(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  return args[index + 1];
}

async function runCliConfirm(args: string[]): Promise<void> {
  const config = getConfig();
  await confirmFromTerminal({
    dataDir: config.dataDir,
    site: argValue(args, "--site"),
    origin: argValue(args, "--origin"),
    workOrigin: argValue(args, "--work-origin"),
    isTTY: Boolean(process.stdin.isTTY),
    stdin: process.stdin,
    stdout: process.stderr,
  });
  console.error("[login-mcp] human allow signal recorded");
}

async function main(): Promise<void> {
  if (process.argv[2] === "confirm") {
    await runCliConfirm(process.argv.slice(3));
    return;
  }

  const config = getConfig();
  if (process.env.LOGIN_MCP_USER_DATA_DIR) {
    console.error("[login-mcp] LOGIN_MCP_USER_DATA_DIR is ignored. Profiles live under data/sites/<site>/profile.");
  }
  if (!config.encryptionKey) {
    console.error(
      "[login-mcp] LOGIN_MCP_KEY is unset. This process will not generate or write a key. Leave it unset unless the operator set LOGIN_MCP_KEY in the MCP process environment. Profiles stay mode 0700/0600. SIGKILL cannot run the close hook; the next start seals a leftover plaintext profile.",
    );
  }
  sealLeftoverProfiles(createProfileVault(config.encryptionKey), config.dataDir);
  const browser = createChromeBrowser({
    dataDir: config.dataDir,
    encryptionKey: config.encryptionKey,
  });
  const store = createFileStore(config.dataDir);
  const human = createHumanSignals({
    dataDir: config.dataDir,
    serve: true,
    openTabUrls: () => browser.listOpenTabUrls(),
    onButtonAllow: async (site, origins) => {
      for (const origin of origins) {
        await assertPinnedHost(new URL(origin).hostname, defaultResolveHost);
      }
      await store.confirm(site, origins);
      await store.touch(site, new Date(), undefined, { confirmed: true });
      console.error(`[login-mcp] allow confirmed site=${site} origins=${origins.join(",")}`);
    },
  });
  const service = createService({
    store,
    browser,
    human,
    dataDir: config.dataDir,
    log: (line) => console.error(line),
  });

  const server = new McpServer(
    { name: "login-mcp", version: "0.1.0" },
    { instructions: INSTRUCTIONS },
  );

  server.registerTool(
    "auth_status",
    {
      description:
        "One line per site: site id, confirmed login and work origins, last used time, last confirmed time, session age, and session ok or needs_login. needs_login means the last open saw a login page. Age makes a stale ok visible. Returns no cookies, tokens, or URL query secrets.",
      inputSchema: {
        site: siteField.optional().describe("Optional site id. Omit to list every site."),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ site }) => toContent(await service.status(site)),
  );

  server.registerTool(
    "auth_login",
    {
      description:
        "Open a visible Chrome window for one site id so a human can log in. Also opens a local tab that lists the login origin and work origin, then the button 이 사이트 허용. That button confirms those origins. Returns immediately. Does not type credentials or return the confirmation code.",
      inputSchema: {
        site: siteField,
        url: z.string().describe("Absolute http(s) URL of the login page the human will complete."),
      },
    },
    async ({ site, url }) => toContent(await service.login(site, url)),
  );

  server.registerTool(
    "auth_confirm",
    {
      description:
        "Record origins for one site after a human allow signal from the last 10 minutes. The 이 사이트 허용 button already confirms origins; use this after the terminal confirm command. Refuses if that signal is missing. Optional workOrigin must be part of the same human signal. Does not read cookies.",
      inputSchema: {
        site: siteField,
        origin: z.string().describe("Login origin the human allowed, exactly like https://auth.example.com, with no path."),
        workOrigin: z
          .string()
          .optional()
          .describe("Optional work origin the human allowed for this site, such as https://www.example.com."),
      },
    },
    async ({ site, origin, workOrigin }) => toContent(await service.confirm(site, origin, workOrigin)),
  );

  server.registerTool(
    "auth_open",
    {
      description:
        "Open a URL in that site's Chrome profile. The origin must already be human-confirmed for the site (login origin or a work origin). Re-resolves every A/AAAA and pins Chrome to one address from that checked set, then fails closed if the connected address is outside the set. Returns human_action_required and no page text when the page looks like a login or challenge, or when the final origin is not a confirmed login or work origin. Blocks subresource requests to link-local or metadata hosts.",
      inputSchema: {
        site: siteField,
        url: z.string().describe("Absolute http(s) URL on a confirmed origin for this site."),
      },
    },
    async ({ site, url }) => toContent(await service.open(site, url)),
  );

  server.registerTool(
    "auth_read",
    {
      description:
        "Read visible text from this site's current page, or navigate first when url is set and its origin is human-confirmed for the site. Re-resolves DNS on every call. Refuses unconfirmed origins. Truncates long text. Never returns cookies or storage.",
      inputSchema: {
        site: siteField,
        url: z.string().optional().describe("Optional absolute http(s) URL on a confirmed origin for this site."),
        selector: z.string().optional().describe("Optional Playwright selector whose visible text to read."),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ site, url, selector }) => toContent(await service.read(site, { url, selector })),
  );

  server.registerTool(
    "auth_act",
    {
      description:
        "Perform one click, fill, or press on this site's current page. Re-resolves DNS on every call. Refuses unconfirmed origins, password fields, and challenge widgets. fill and press require value. Does not solve CAPTCHA or 2FA.",
      inputSchema: {
        site: siteField,
        action: z.enum(["click", "fill", "press"]).describe("The single action to perform."),
        selector: z.string().describe("Playwright selector for the element. Password fields are refused."),
        value: z
          .string()
          .optional()
          .describe("Text for fill, or key for press. Never a password. Required for fill and press."),
      },
    },
    async ({ site, action, selector, value }) =>
      toContent(await service.act(site, { action, selector, value })),
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[login-mcp] listening on stdio");

  let shuttingDown = false;
  const shutdown = () => {
    if (shuttingDown) return;
    shuttingDown = true;
    const timer = setTimeout(() => {
      console.error("[login-mcp] shutdown timed out");
      process.exit(1);
    }, 60_000);
    void human
      .close()
      .catch(() => undefined)
      .then(() => browser.close())
      .finally(() => {
        clearTimeout(timer);
        process.exit(0);
      });
  };
  server.server.onclose = () => {
    shutdown();
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error: unknown) => {
  let message = error instanceof Error ? error.message : String(error);
  const key = process.env.LOGIN_MCP_KEY;
  if (key) message = message.split(key).join("[redacted]");
  console.error(`[login-mcp] fatal ${message}`);
  process.exit(1);
});
