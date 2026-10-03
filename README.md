# login-mcp

Local Auth MCP that reuses a human-completed browser session. Never stores passwords.

A person logs into a site once in a local Chrome window. Later, an agent calls MCP tools to open that same browser, read pages, and click or type as that user. The agent never receives the password, and this server never stores one.

## Site id and human confirm / 사이트와 사람 확인

Each tool takes `site` (a short id such as `wishket`). Chrome user-data directories are separate: `data/sites/<site>/profile`. A login on one site is not sent to another. SSO across sites breaks on purpose.

`auth_confirm` is not an agent allowlist. A person must allow the origin within the last 10 minutes:

1. `auth_login` opens the login URL and a local tab. Click **이 사이트 허용**. Optional work origin (for example `https://auth.wishket.com` and `https://www.wishket.com`) is stored as a pair for that site.
2. Or, in an interactive terminal: `node dist/index.js confirm --site wishket --origin https://auth.wishket.com --work-origin https://www.wishket.com` and type the code shown only in that Chrome tab.

The code and the tab URL are not returned by the MCP tool. A forged `human-signal.json` is ignored (HMAC, key kept in process memory). The signal expires after 10 minutes. `auth_read` and `auth_act` still refuse origins that are not confirmed.

While the server is stopped, each profile directory is mode `0700` (files `0600`). If `LOGIN_MCP_KEY` is set, exit encrypts the profile with scrypt and AES-256-GCM and removes the plaintext directory until the next use by this process. The key is never logged. Without the key there is no ciphertext; `0700` only stops other local users. `SIGKILL` cannot encrypt. The old shared `data/chrome-profile` path is not migrated and is not locked, so an already-open window there is left alone.

---

도구마다 `site`가 필요합니다 (예: `wishket`). Chrome 프로필은 `data/sites/<site>/profile` 로 나뉩니다. 한 사이트 쿠키가 다른 사이트로 가지 않으며, 사이트 간 SSO는 의도적으로 깨집니다.

`auth_confirm`은 에이전트 허용 목록이 아닙니다. 최근 10분 안에 사람이 허용해야 합니다.

1. `auth_login`이 연 로컬 탭에서 **이 사이트 허용**을 누릅니다. 작업 오리진(예: `https://auth.wishket.com` 와 `https://www.wishket.com`)을 그 사이트의 쌍으로 저장할 수 있습니다.
2. 또는 대화형 터미널에서 `node dist/index.js confirm --site wishket --origin https://auth.wishket.com --work-origin https://www.wishket.com` 를 실행하고, Chrome 탭에만 보이는 코드를 입력합니다.

코드와 탭 주소는 MCP 도구 결과에 나오지 않습니다. 위조한 `human-signal.json`은 무시됩니다. 신호는 10분 뒤 만료됩니다. 확인되지 않은 오리진은 `auth_read`와 `auth_act`가 거부합니다.

서버가 꺼지면 프로필은 `0700`(파일 `0600`)입니다. `LOGIN_MCP_KEY`가 있으면 종료 시 scrypt와 AES-256-GCM으로 암호화하고 평문 디렉터리를 지웁니다. 키는 로그에 남기지 않습니다. 키가 없으면 암호문은 없고 `0700`만 적용됩니다. `SIGKILL`은 암호화할 수 없습니다. 예전 `data/chrome-profile`은 옮기거나 잠그지 않습니다.

## Security model

- This server never asks for, types, or stores a password. It also never returns cookies, `localStorage`, `sessionStorage`, or Playwright `storageState`. It does not solve CAPTCHA, 2FA, or bot checks.
- The session **is** the per-site Chrome profile on disk. Treat it as a secret. It is gitignored. Do not copy it into a repo, a ticket, or a log.
- Site ids are one path segment (`a-z`, `0-9`, `_`, `-`). Traversal and symlink profiles are refused. The daily system Chrome profile is refused.
- Confirmed origins live in `data/sites/<site>/origins.json` (mode `0600`). `auth_status` lists site id, those origins, and roughly when the profile was last used. It has no cookie fields.
- Link-local addresses, `0.0.0.0/8`, and cloud-metadata hosts are refused, including numeric encodings. Other hosts must be pinnable DNS names (or a literal address that is already allowed). DNS names are resolved at each call; if any answer is link-local, metadata, or unspecified, the host is refused. This is not a Chrome `--host-resolver-rules` pin, so a rebinding that happens after the check can still race. `localhost` and ordinary private addresses stay allowed for a local app. Only `http` and `https` URLs are allowed.
- A navigation that redirects onto an origin this site has not confirmed is not read; the tab is sent to `about:blank`. If a confirmed site lands on a login or password page, the tool returns `human_action_required` and does not return page text. The message says the session expired and a human must log in again.
- There is no stealth mode and no fingerprint evasion. Chrome runs visibly (`channel: "chrome"`) with the Chromium sandbox on, downloads disabled, and sync disabled.

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
      "args": ["/absolute/path/to/login-mcp/dist/index.js"],
      "env": {
        "LOGIN_MCP_KEY": "set-a-long-secret-here"
      }
    }
  }
}
```

Logs go to stderr. stdout is reserved for MCP. Do not put the key on the command line.

## Tool flow

1. `auth_status` with optional `{ "site": "wishket" }` — each site id, confirmed origins, last use. No cookies.
2. `auth_login` with `{ "site": "wishket", "url": "https://auth.example.com/login" }` — opens a visible Chrome window and returns immediately. Complete login yourself. Click **이 사이트 허용** or run the terminal confirm command. The server does not type credentials.
3. `auth_confirm` with `{ "site": "wishket", "origin": "https://auth.example.com", "workOrigin": "https://www.example.com" }` — records the human-approved pair. Refuses when the human signal is missing or older than 10 minutes.
4. `auth_open` with `{ "site": "wishket", "url": "https://www.example.com/dashboard" }` — that site's profile only.
5. `auth_read` with `{ "site": "wishket", "url": "...", "selector": "main" }` — visible text only. Refuses origins not confirmed for that site.
6. `auth_act` with `{ "site": "wishket", "action": "click", "selector": "a[href='/settings']" }` — one click, fill, or key press. Password fields and challenge widgets are refused.

If a result contains `"human_action_required": true`, stop and use the open Chrome window. Do not retry with a guessed password.

## Paths

| Variable | Default |
| --- | --- |
| `LOGIN_MCP_DATA_DIR` | `./data` |
| `LOGIN_MCP_KEY` | unset (chmod `0700` only; set it to encrypt profiles at rest) |

Profiles are `$LOGIN_MCP_DATA_DIR/sites/<site>/profile`. `LOGIN_MCP_USER_DATA_DIR` is ignored so an older shared profile is not reused. Never point the data directory at a directory you commit, or at a Chrome profile path.

## Troubleshooting

Chrome locks the user-data directory. If launch fails because Chrome is already running with this site's profile, close that window and retry. Do not delete the profile if you want to keep the session. Do not point the data directory at your normal Chrome profile or at a symlink. If a confirmed site redirects to another origin, the human must allow that origin too (the work origin field) before `auth_open` or `auth_read` can succeed.

## Development

```bash
npm test
npm run build
npm start
```

`npm start` waits on stdin for an MCP client. Stop it with Ctrl+C, which closes Chrome and locks profiles.
