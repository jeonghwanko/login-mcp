import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { getConfig } from "../src/config.ts";
import { createFileStore } from "../src/origins.ts";

test("config honors path overrides", () => {
  const config = getConfig(
    {
      LOGIN_MCP_DATA_DIR: "/tmp/login-mcp-data",
      LOGIN_MCP_USER_DATA_DIR: "/tmp/login-mcp-profile",
      LOGIN_MCP_ORIGINS_FILE: "/tmp/login-mcp-origins.json",
    },
    "/work",
  );
  assert.equal(config.dataDir, "/tmp/login-mcp-data");
  assert.equal(config.userDataDir, "/tmp/login-mcp-profile");
  assert.equal(config.originsFile, "/tmp/login-mcp-origins.json");

  const defaults = getConfig({}, "/work");
  assert.equal(defaults.dataDir, path.join("/work", "data"));
  assert.equal(defaults.userDataDir, path.join("/work", "data", "chrome-profile"));
  assert.equal(defaults.originsFile, path.join("/work", "data", "origins.json"));
});

test("confirm writes origins only and ignores junk already in the file", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "login-mcp-"));
  const file = path.join(dir, "origins.json");
  await fs.writeFile(
    file,
    JSON.stringify({
      origins: ["https://already.example", "not-an-origin", "https://evil.example/secret"],
      cookies: [{ name: "sid", value: "nope" }],
    }),
  );
  const store = createFileStore(file);
  const origins = await store.confirm("https://new.example");
  assert.deepEqual(origins, ["https://already.example", "https://new.example"]);
  assert.equal(await store.has("https://new.example"), true);
  assert.equal(await store.has("https://evil.example"), false);

  const again = await store.confirm("https://new.example");
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
  const file = path.join(dir, "nested", "origins.json");
  const store = createFileStore(file);
  await assert.rejects(() => store.confirm("https://example.com/path"));
  await assert.rejects(() => fs.stat(file));
});

test("origins file is private and parallel confirms are not lost", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "login-mcp-"));
  const file = path.join(dir, "origins.json");
  const store = createFileStore(file);
  await Promise.all([
    store.confirm("https://a.example"),
    store.confirm("https://b.example"),
    store.confirm("https://c.example"),
  ]);
  assert.deepEqual(await store.list(), ["https://a.example", "https://b.example", "https://c.example"]);
  const st = await fs.stat(file);
  assert.equal(st.mode & 0o077, 0);
});

test("confirm replaces a symlinked origins file instead of writing through it", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "login-mcp-"));
  const outside = path.join(dir, "outside.json");
  await fs.writeFile(outside, JSON.stringify({ origins: ["https://bank.example"] }));
  const file = path.join(dir, "origins.json");
  await fs.symlink(outside, file);
  const store = createFileStore(file);
  await assert.rejects(() => store.list(), /symlink/);
  await store.confirm("https://a.example");
  assert.equal(await fs.readFile(outside, "utf8"), JSON.stringify({ origins: ["https://bank.example"] }));
  const st = await fs.lstat(file);
  assert.equal(st.isSymbolicLink(), false);
  assert.match(await fs.readFile(file, "utf8"), /a\.example/);
  assert.equal((await fs.readFile(file, "utf8")).includes("bank"), false);
});

test("refuses an oversized origins file", async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "login-mcp-"));
  const file = path.join(dir, "origins.json");
  await fs.writeFile(file, "x".repeat(300 * 1024));
  const store = createFileStore(file);
  await assert.rejects(() => store.list(), /too large/);
});

test("config refuses the system Chrome profile", () => {
  assert.throws(
    () =>
      getConfig(
        {
          LOGIN_MCP_USER_DATA_DIR: path.join(os.homedir(), ".config", "google-chrome"),
        },
        "/work",
      ),
    /system Chrome profile/,
  );
});
