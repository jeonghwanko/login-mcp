#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { createChromeBrowser } from "./browser.js";
import { getConfig } from "./config.js";
import { createFileStore } from "./origins.js";
import { createService, type ToolText } from "./service.js";

const INSTRUCTIONS =
  "Reuse a human-completed Chrome login. Never type, store, or request passwords. Never export cookies or storage. If a tool returns human_action_required, stop and let the human finish in the open Chrome window. Do not solve CAPTCHA, 2FA, or bot checks.";

function toContent(result: ToolText) {
  return {
    content: [{ type: "text" as const, text: result.text }],
    isError: result.isError ?? false,
  };
}

async function main(): Promise<void> {
  const config = getConfig();
  const browser = createChromeBrowser(config);
  const service = createService({
    store: createFileStore(config.originsFile),
    browser,
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
        "Report whether the local Chrome profile exists, whether Chrome is open under this server, and which site origins the human has confirmed. Returns origins only, never cookies or tokens.",
      annotations: { readOnlyHint: true },
    },
    async () => toContent(await service.status()),
  );

  server.registerTool(
    "auth_login",
    {
      description:
        "Open a visible Chrome window at a URL using the persistent local profile so a human can log in. Returns immediately and does not type credentials, wait for login, or store a password.",
      inputSchema: {
        url: z.string().describe("Absolute http(s) URL of the login page the human will complete."),
      },
    },
    async ({ url }) => toContent(await service.login(url)),
  );

  server.registerTool(
    "auth_confirm",
    {
      description:
        "Record that the human finished login for one origin. Pass only the origin, such as https://example.com. Does not read cookies.",
      inputSchema: {
        origin: z.string().describe("Confirmed site origin, exactly like https://example.com, with no path."),
      },
    },
    async ({ origin }) => toContent(await service.confirm(origin)),
  );

  server.registerTool(
    "auth_open",
    {
      description:
        "Open a URL in the persistent Chrome profile. The origin must already be confirmed. Returns the title, final URL, and human_action_required when the page looks like a login or challenge. Does not try to log in.",
      inputSchema: {
        url: z.string().describe("Absolute http(s) URL on a confirmed origin."),
      },
    },
    async ({ url }) => toContent(await service.open(url)),
  );

  server.registerTool(
    "auth_read",
    {
      description:
        "Read visible text from the current page, or navigate first when url is set and its origin is confirmed. Optional selector reads that element's inner text. Truncates long text. Never returns cookies or storage.",
      inputSchema: {
        url: z.string().optional().describe("Optional absolute http(s) URL on a confirmed origin."),
        selector: z.string().optional().describe("Optional Playwright selector whose visible text to read."),
      },
      annotations: { readOnlyHint: true },
    },
    async ({ url, selector }) => toContent(await service.read({ url, selector })),
  );

  server.registerTool(
    "auth_act",
    {
      description:
        "Perform one click, fill, or press on the current page. Refuses unconfirmed origins, password fields, and challenge widgets. fill and press require value. Does not solve CAPTCHA or 2FA.",
      inputSchema: {
        action: z.enum(["click", "fill", "press"]).describe("The single action to perform."),
        selector: z.string().describe("Playwright selector for the element. Password fields are refused."),
        value: z
          .string()
          .optional()
          .describe("Text for fill, or key for press. Never a password. Required for fill and press."),
      },
    },
    async ({ action, selector, value }) => toContent(await service.act({ action, selector, value })),
  );

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[login-mcp] listening on stdio");

  server.server.onclose = () => {
    void browser.close();
  };

  const shutdown = () => {
    void browser.close().finally(() => {
      process.exit(0);
    });
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`[login-mcp] fatal ${message}`);
  process.exit(1);
});
