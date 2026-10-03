import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { getConfig } from "../src/config.ts";
import { createFileStore } from "../src/origins.ts";

test("config honors the data directory and does not take a shared profile path", () => {
  const config = getConfig(
    {
      LOGIN_MCP_DATA_DIR: "/tmp/login-mcp-data",
      LOGIN_MCP_KEY: "test-key",
      LOGIN_MCP_USER_DATA_DIR: "/tmp/should-be-ignored",
    },
    "/work",
  );
  assert.equal(config.dataDir, "/tmp/login-mcp-data");
  assert.equal(config.encryptionKey, "test-key");
  assert.equal("userDataDir" in config, false);

  const defaults = getConfig({}, "/work");
  assert.equal(defaults.dataDir, path.join("/work", "data"));
  assert.equal(defaults.encryptionKey, null);
});

test("confirm writes origins only and ignores junk already in the file", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "login-mcp-"));
  const file = path.join(dir, "sites", "demo", "origins.json");
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(
    file,
    JSON.stringify({
      origins: ["https://already.example", "not-an-origin", "https://evil.example/secret"],
      cookies: [{ name: "sid", value: "nope" }],
    }),
  );
  const store = createFileStore(dir);
  const origins = await store.confirm("demo", ["https://new.example"]);
  assert.deepEqual(origins, ["https://already.example", "https://new.example"]);
  assert.equal(await store.has("demo", "https://new.example"), true);
  assert.equal(await store.has("demo", "https://evil.example"), false);

  const again = await store.confirm("demo", ["https://new.example"]);
  assert.deepEqual(again, origins);

  const written = await fs.readFile(file, "utf8");
  assert.equal(written.includes("cookie"), false);
  assert.equal(written.includes("nope"), false);
  assert.equal(written.includes("secret"), false);
  const parsed = JSON.parse(written) as {
    origins: string[];
    loginOrigin: string | null;
    workOrigins: string[];
  };
  assert.deepEqual(Object.keys(parsed).sort(), ["loginOrigin", "origins", "workOrigins"]);
  assert.equal(parsed.loginOrigin, "https://new.example");
  assert.deepEqual(parsed.workOrigins, ["https://already.example"]);
  assert.deepEqual(parsed.origins, ["https://already.example", "https://new.example"]);
});

test("invalid origin is not written", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "login-mcp-"));
  const file = path.join(dir, "sites", "demo", "origins.json");
  const store = createFileStore(dir);
  await assert.rejects(() => store.confirm("demo", ["https://example.com/path"]));
  await assert.rejects(() => fs.stat(file));
});

test("origins file is private and parallel confirms are not lost", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "login-mcp-"));
  const file = path.join(dir, "sites", "demo", "origins.json");
  const store = createFileStore(dir);
  await Promise.all([
    store.confirm("demo", ["https://a.example"]),
    store.confirm("demo", ["https://b.example"]),
    store.confirm("demo", ["https://c.example"]),
  ]);
  const listed = await store.list();
  assert.equal(listed.length, 1);
  const record = listed[0]!;
  assert.equal(record.site, "demo");
  assert.deepEqual(record.origins, ["https://a.example", "https://b.example", "https://c.example"]);
  assert.equal(record.lastUsed, null);
  assert.equal(record.session, "ok");
  assert.ok(record.loginOrigin);
  assert.equal(record.origins.includes(record.loginOrigin), true);
  assert.deepEqual([record.loginOrigin, ...record.workOrigins].sort(), record.origins);
  const st = await fs.stat(file);
  assert.equal(st.mode & 0o077, 0);
});

test("confirm replaces a symlinked origins file instead of writing through it", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "login-mcp-"));
  const siteDir = path.join(dir, "sites", "demo");
  await fs.mkdir(siteDir, { recursive: true });
  const outside = path.join(dir, "outside.json");
  await fs.writeFile(outside, JSON.stringify({ origins: ["https://bank.example"] }));
  const file = path.join(siteDir, "origins.json");
  await fs.symlink(outside, file);
  const store = createFileStore(dir);
  await assert.rejects(() => store.list(), /symlink/);
  await store.confirm("demo", ["https://a.example"]);
  assert.equal(await fs.readFile(outside, "utf8"), JSON.stringify({ origins: ["https://bank.example"] }));
  const st = await fs.lstat(file);
  assert.equal(st.isSymbolicLink(), false);
  assert.match(await fs.readFile(file, "utf8"), /a\.example/);
  assert.equal((await fs.readFile(file, "utf8")).includes("bank"), false);
});

test("refuses an oversized origins file", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "login-mcp-"));
  const file = path.join(dir, "sites", "demo", "origins.json");
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, "x".repeat(300 * 1024));
  const store = createFileStore(dir);
  await assert.rejects(() => store.list(), /too large/);
});

test("config refuses the system Chrome profile and a profile directory as data", () => {
  assert.throws(
    () =>
      getConfig(
        {
          LOGIN_MCP_DATA_DIR: path.join(os.homedir(), ".config", "google-chrome"),
        },
        "/work",
      ),
    /system Chrome profile/,
  );
  assert.throws(
    () =>
      getConfig(
        {
          LOGIN_MCP_DATA_DIR: path.join("/tmp", "chrome-profile"),
        },
        "/work",
      ),
    /Chrome profile directory/,
  );
});

test("meta stores session without cookies or query secrets", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "login-mcp-"));
  const store = createFileStore(dir);
  await store.confirm("demo", ["https://auth.example", "https://www.example"]);
  await store.touch("demo", new Date("2026-10-03T00:00:00.000Z"), "needs_login");
  const listed = await store.list();
  assert.equal(listed[0]?.loginOrigin, "https://auth.example");
  assert.deepEqual(listed[0]?.workOrigins, ["https://www.example"]);
  assert.equal(listed[0]?.session, "needs_login");
  assert.equal(listed[0]?.lastUsed, "2026-10-03T00:00:00.000Z");
  const meta = await fs.readFile(path.join(dir, "sites", "demo", "meta.json"), "utf8");
  assert.equal(meta.includes("cookie"), false);
  assert.equal(meta.includes("?"), false);
  await store.touch("demo", new Date("2026-10-03T01:00:00.000Z"));
  assert.equal((await store.list())[0]?.session, "needs_login");
});
