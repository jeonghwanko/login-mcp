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
  const parsed = JSON.parse(written) as { origins: string[] };
  assert.deepEqual(Object.keys(parsed), ["origins"]);
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
  assert.deepEqual(await store.list(), [
    {
      site: "demo",
      origins: ["https://a.example", "https://b.example", "https://c.example"],
      lastUsed: null,
    },
  ]);
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
