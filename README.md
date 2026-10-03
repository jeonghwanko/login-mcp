# login-mcp

Local Auth MCP that reuses a human-completed browser session. Never stores passwords.

A person logs into a site once in a local Chrome window. Later, an agent calls MCP tools to open that same browser, read pages, and click or type as that user. The agent never receives the password, and this server never stores one.

## Security model

- This server never asks for, types, or stores a password. It also never returns cookies, `localStorage`, `sessionStorage`, or Playwright `storageState`.
- The session **is** the Chrome profile on disk (`data/chrome-profile` by default). Chrome writes session cookies there. That is equivalent to a password. It is not a separate encrypted vault: there is no passphrase, KDF, or ciphertext around the profile, because Chrome has to read those files to reuse the login. Treat the directory as a secret. It is gitignored. Do not copy it into a repo, a ticket, or a log.
- The profile directory is created mode `0700` and must not be a symlink. The daily system Chrome profile (`~/.config/google-chrome` and the usual platform paths) is refused. Confirmed origins are stored only in `data/origins.json` (mode `0600`), written via a random temp file so a symlink cannot be followed.
- One profile is shared by every site. Chrome still isolates cookies by origin. The agent may only open and read origins it has confirmed. A navigation that **redirects** off that allowlist is not read; the tab is sent to `about:blank` instead. Confirm both `https://example.com` and `https://www.example.com` if a site uses both.
- Login, CAPTCHA, 2FA, and bot checks are left to the human. On a page that looks like a login or challenge, `auth_read` does not return page text. `auth_act` refuses password fields (selector text **and** the live element's `type` / `name` / `id` / `autocomplete`, including inside frames) and challenge widgets. This is not a bypass, and the heuristics are not perfect.
- Link-local addresses, `0.0.0.0/8`, and well-known cloud metadata hosts are refused. `localhost` and ordinary private LAN hosts are allowed so you can sign in to a local app. Only `http` and `https` URLs are allowed. URLs with embedded usernames or passwords are rejected. Tool results strip URL userinfo and fragments, and redact query values whose names look like tokens or codes.
- There is no stealth mode and no fingerprint evasion. Chrome runs visibly (`channel: "chrome"`) with the Chromium sandbox on, downloads disabled, and sync disabled. Launch and navigation have timeouts. Ctrl+C closes Chrome and exits even if shutdown hangs.
- `auth_confirm` records an origin the agent supplies. It is an allowlist, not cryptographic proof that a human clicked something. Approve the tool in the MCP host if you want a human gate.

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

Chrome locks the user-data directory. If launch fails with a message that Chrome is already running with this profile, close every Chrome window using `data/chrome-profile` and call the tool again. Do not delete the profile if you want to keep the session. Do not point `LOGIN_MCP_USER_DATA_DIR` at your normal Chrome profile or at a symlink. If a confirmed site redirects to another origin, confirm that origin explicitly before expecting `auth_open` or `auth_read` to succeed.

## Development

```bash
npm test
npm run build
npm start
```

`npm start` waits on stdin for an MCP client. Stop it with Ctrl+C.
