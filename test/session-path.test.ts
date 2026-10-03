import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { preparePrivateDir } from "../src/session-path.ts";

test("preparePrivateDir forces mode 0700 and refuses a symlink", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "login-mcp-dir-"));
  const profile = path.join(dir, "chrome-profile");
  preparePrivateDir(profile);
  const st = fs.statSync(profile);
  assert.equal(st.isDirectory(), true);
  assert.equal(st.mode & 0o077, 0);

  const link = path.join(dir, "linked-profile");
  fs.symlinkSync(profile, link);
  assert.throws(() => preparePrivateDir(link), /symlink/);
});

test("preparePrivateDir refuses a shared temp root", () => {
  assert.throws(() => preparePrivateDir(os.tmpdir()), /dedicated directory|system Chrome profile|filesystem root/);
});
