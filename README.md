# login-mcp

Local Auth MCP that reuses a human-completed browser session. Never stores passwords.

A person logs into a site once in a local Chrome window. Later, an agent calls MCP tools to open that same browser, read pages, and click or type as that user. The agent never receives the password, and this server never stores one.

## Security model

- Passwords, tokens, and other credentials are not collected, typed, or written to disk by this server.
- There is no tool that exports cookies, `localStorage`, or `sessionStorage`.
- Login, CAPTCHA, 2FA, and bot checks are left to the human. If a page looks like a login or challenge, tools return `human_action_required` and stop. This server does not try to solve them.
- There is no stealth mode and no fingerprint evasion. Chrome runs visibly with Playwright's normal settings and `channel: "chrome"`.
- The session lives only in a Chrome user-data directory on this machine (`data/chrome-profile` by default). That directory contains session cookies. Treat it as a secret. It is gitignored. Do not copy it into a repo, a ticket, or a log.
- Confirmed sites are stored as origins only (`https://example.com`) in `data/origins.json`, also gitignored.
- `auth_act` refuses selectors that look like password fields (`type=password`, or `name` / `id` / `autocomplete` containing `password`) and refuses actions on origins the human has not confirmed.
- Only `http` and `https` URLs are allowed. URLs with embedded usernames or passwords are rejected.

This is for the account holder reusing their own session on their own computer. It is not a credential manager and it does not grant access the human does not already have.

## Requirements

- Node.js 20 or newer
- Google Chrome installed locally (the `google-chrome` executable on `PATH`)

Playwright drives that installed Chrome. It does not download a bundled browser.

## Install

```bash
npm install
npm run build
npm test
```

## Cursor MCP config

stdio transport. Point the host at the built entrypoint:

```json
{
  "mcpServers": {
    "login-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/login-mcp/dist/index.js"]
    }
  }
}
```

Logs go to stderr. stdout is reserved for MCP.

## Tool flow

1. `auth_status` — profile on disk, whether Chrome is open, confirmed origins. No cookies.
2. `auth_login` with `{ "url": "https://example.com/login" }` — opens a visible Chrome window and returns immediately. Complete login yourself, including any 2FA or CAPTCHA. The server does not type credentials and does not wait for you.
3. `auth_confirm` with `{ "origin": "https://example.com" }` — records that you finished login for that origin.
4. `auth_open` with `{ "url": "https://example.com/dashboard" }` — reuses the same profile. Returns the page title, final URL, and `human_action_required`.
5. `auth_read` with optional `{ "url": "...", "selector": "main" }` — visible text only, truncated. Refuses origins you have not confirmed.
6. `auth_act` with `{ "action": "click", "selector": "a[href='/settings']" }` — one click, fill, or key press. `fill` and `press` take `value`. Password fields and challenge widgets are refused.

If a result contains `"human_action_required": true`, stop and use the open Chrome window. Do not retry with a guessed password.

## Paths

| Variable | Default |
| --- | --- |
| `LOGIN_MCP_DATA_DIR` | `./data` |
| `LOGIN_MCP_USER_DATA_DIR` | `$LOGIN_MCP_DATA_DIR/chrome-profile` |
| `LOGIN_MCP_ORIGINS_FILE` | `$LOGIN_MCP_DATA_DIR/origins.json` |

Override these in tests or if you want the profile outside the repo. Never point them at a directory you commit.

## Troubleshooting

Chrome locks the user-data directory. If launch fails with a message that Chrome is already running with this profile, close every Chrome window using `data/chrome-profile` and call the tool again. Do not delete the profile if you want to keep the session.

## Development

```bash
npm test
npm run build
npm start
```

`npm start` waits on stdin for an MCP client. Stop it with Ctrl+C.
