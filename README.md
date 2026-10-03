# login-mcp

Local Auth MCP that reuses a human-completed browser session. Never stores passwords.

A person logs into a site once in a local Chrome window. Later, an agent calls MCP tools to open that same browser, read pages, and click or type as that user. The agent never receives the password, and this server never stores one.

## Site id and human confirm / 사이트와 사람 확인

Each tool takes `site` (a short id such as `wishket`). Chrome user-data directories are separate: `data/sites/<site>/profile`. A login on one site is not sent to another. SSO across sites breaks on purpose.

`auth_confirm` is not an agent allowlist. A person must allow the origin within the last 10 minutes:

1. `auth_login` opens the login URL and a local tab. Click **이 사이트 허용**. Optional work origin (for example `https://auth.wishket.com` and `https://www.wishket.com`) is stored as a pair for that site.
2. Or, in an interactive terminal: `node dist/index.js confirm --site wishket --origin https://auth.wishket.com --work-origin https://www.wishket.com` and type the code shown only in that Chrome tab.

The code and the tab URL are not returned by the MCP tool. A forged `human-signal.json` is ignored (HMAC, key kept in process memory). The signal expires after 10 minutes. `auth_read` and `auth_act` still refuse origins that are not confirmed.

If `LOGIN_MCP_KEY` is set, the per-site profile is decrypted only while that site's Chrome is running. It is encrypted again with scrypt and AES-256-GCM as soon as that site's browser closes (switching sites, the window closing, or process shutdown) and the plaintext directory is removed. If the key is unset, there is no ciphertext; the profile stays mode `0700` (files `0600`) at rest, including after the browser closes. The key is never logged. `SIGKILL` cannot run the close hook. On the next start, and again before a site browser is opened, a plaintext leftover is encrypted immediately when the key is set, or chmod'd to `0700`/`0600` when it is not. That pass does not delete the session. A profile whose `SingletonLock` names a live process is left alone. The old shared `data/chrome-profile` path is not migrated, locked, or signaled, so an already-open window there is left alone.

---

도구마다 `site`가 필요합니다 (예: `wishket`). Chrome 프로필은 `data/sites/<site>/profile` 로 나뉩니다. 한 사이트 쿠키가 다른 사이트로 가지 않으며, 사이트 간 SSO는 의도적으로 깨집니다.

`auth_confirm`은 에이전트 허용 목록이 아닙니다. 최근 10분 안에 사람이 허용해야 합니다.

1. `auth_login`이 연 로컬 탭에서 **이 사이트 허용**을 누릅니다. 작업 오리진(예: `https://auth.wishket.com` 와 `https://www.wishket.com`)을 그 사이트의 쌍으로 저장할 수 있습니다.
2. 또는 대화형 터미널에서 `node dist/index.js confirm --site wishket --origin https://auth.wishket.com --work-origin https://www.wishket.com` 를 실행하고, Chrome 탭에만 보이는 코드를 입력합니다.

코드와 탭 주소는 MCP 도구 결과에 나오지 않습니다. 위조한 `human-signal.json`은 무시됩니다. 신호는 10분 뒤 만료됩니다. 확인되지 않은 오리진은 `auth_read`와 `auth_act`가 거부합니다.

`LOGIN_MCP_KEY`가 있으면 그 사이트의 Chrome이 떠 있는 동안에만 프로필을 복호화합니다. 그 브라우저가 닫히면(사이트를 바꾸거나, 창을 닫거나, 프로세스가 종료되면) 바로 scrypt와 AES-256-GCM으로 다시 암호화하고 평문 디렉터리를 지웁니다. 키가 없으면 암호문은 없고, 브라우저가 닫힌 뒤에도 `0700`(파일 `0600`)만 유지합니다. 키는 로그에 남기지 않습니다. `SIGKILL`은 닫힘 훅을 실행할 수 없습니다. 다음 시작 때, 그리고 사이트를 열기 전에, 평문으로 남은 프로필은 키가 있으면 즉시 암호화하고 키가 없으면 `0700`/`0600`만 맞춥니다. 세션은 지우지 않습니다. `SingletonLock`이 살아 있는 프로세스를 가리키면 그 프로필은 그대로 둡니다. 예전 `data/chrome-profile`은 옮기거나 잠그거나 신호를 보내지 않습니다.

## Security model

- This server never asks for, types, or stores a password. It also never returns cookies, `localStorage`, `sessionStorage`, or Playwright `storageState`. It does not solve CAPTCHA, 2FA, or bot checks.
- The session **is** the per-site Chrome profile on disk. Treat it as a secret. It is gitignored. Do not copy it into a repo, a ticket, or a log.
- Site ids are one path segment (`a-z`, `0-9`, `_`, `-`). Traversal and symlink profiles are refused. The daily system Chrome profile is refused.
- Confirmed origins live in `data/sites/<site>/origins.json` (mode `0600`) as a login origin plus optional work origins. `auth_status` is one line per site: site id, those origins, last used time, last confirmed time, session age in milliseconds, and session `ok` or `needs_login`. `needs_login` stays when a login page was actually seen. The age and timestamps sit next to that state so a stale `ok` is visible. It has no cookies, tokens, or URL query secrets.
- Link-local addresses, `0.0.0.0/8`, and cloud-metadata hosts are refused, including numeric encodings. Other hosts must be pinnable DNS names (or a literal address that is already allowed). `auth_open`, `auth_read`, and `auth_act` resolve those names again on every call, not only at `auth_confirm`. Resolution records every A and AAAA answer (and getaddrinfo, so `localhost` still works). If any answer is link-local, metadata, or unspecified, the host is refused. Chromium `--host-resolver-rules` `MAP` accepts only one replacement, so each DNS name is mapped to one address from that full set (lowest IPv4, else lowest IPv6; IPv6 literals are bracketed). The mapped address must be a member of the recorded set. After navigation, a connected address outside that set fails closed and the tab is blanked. If several addresses were resolved and the connected address cannot be checked, the call fails closed instead of trusting one arbitrary IP. The other checked addresses stay in the allow set; they are not discarded. A navigation restarts Chrome onto the new pin when the answers change. An in-page read or act does not continue on a stale pin: the page is closed and the profile is locked again. `localhost` and ordinary private addresses stay allowed for a local app. Only `http` and `https` URLs are allowed.
- Navigation may stay on that site's confirmed login origin and work origins only. A navigation that crosses to an unconfirmed origin is not read; the tab is sent to `about:blank` and the tool returns `human_action_required`. That includes a final URL on a CDN, IdP, or redirect origin that was not confirmed. Subresource requests to link-local, metadata, or unspecified hosts are blocked. Other third-party hosts are not pinned. If a confirmed site lands on a login or password page, the tool returns `human_action_required` and does not return page text. The message says the session expired and a human must log in again. `auth_confirm` still requires the recent human allow signal.
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

1. `auth_status` with optional `{ "site": "wishket" }` — one line per site: site id, confirmed origins, last used time, last confirmed time, session age, and session `ok` or `needs_login`. No cookies, tokens, or query secrets.
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
| `LOGIN_MCP_KEY` | unset (chmod `0700`/`0600` only; set it to encrypt a profile while its browser is closed) |

Profiles are `$LOGIN_MCP_DATA_DIR/sites/<site>/profile`. `LOGIN_MCP_USER_DATA_DIR` is ignored so an older shared profile is not reused. Never point the data directory at a directory you commit, or at a Chrome profile path.

## Troubleshooting

Chrome locks the user-data directory. If launch fails because Chrome is already running with this site's profile, close that window and retry. Do not delete the profile if you want to keep the session. Do not point the data directory at your normal Chrome profile or at a symlink. If a confirmed site redirects to another origin, the human must allow that origin too (the work origin field) before `auth_open` or `auth_read` can succeed.

## Development

```bash
npm test
npm run build
npm start
```

`npm start` waits on stdin for an MCP client. Stop it with Ctrl+C, which closes Chrome and locks profiles. `SIGKILL` skips that hook. The next start seals a leftover plaintext profile (encrypt when `LOGIN_MCP_KEY` is set, otherwise chmod `0700`/`0600`) without deleting the session. Do not kill or migrate a Chrome window that is already using `data/chrome-profile`.
