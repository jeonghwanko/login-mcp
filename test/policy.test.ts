import assert from "node:assert/strict";
import test from "node:test";
import {
  PolicyError,
  assertOrigin,
  looksLikeChallengeWidget,
  looksLikeLoginOrChallenge,
  looksLikePasswordField,
  parseHttpUrl,
} from "../src/policy.ts";

test("accepts http(s) origins and rejects paths, credentials, and other schemes", () => {
  assert.equal(assertOrigin("https://example.com"), "https://example.com");
  assert.equal(assertOrigin("  http://localhost:3000  "), "http://localhost:3000");
  assert.equal(parseHttpUrl("https://example.com/dashboard?tab=1").origin, "https://example.com");

  for (const bad of [
    "https://example.com/login",
    "https://example.com/",
    "https://example.com?x=1",
    "https://user:secret@example.com",
    "javascript:alert(1)",
    "file:///tmp/x",
    "not a url",
    "",
  ]) {
    assert.throws(() => assertOrigin(bad), PolicyError);
  }

  assert.throws(() => parseHttpUrl("https://user:secret@example.com/login"), /credentials/);
  assert.throws(() => parseHttpUrl("ftp://example.com"), /http/);
});

test("refuses password-like selectors and field descriptors, not ordinary controls", () => {
  for (const selector of [
    'input[type="password"]',
    "input[type=password]",
    "#password",
    ".password",
    "#current-password",
    '[name="password"]',
    "[name=user_password]",
    '[id="password"]',
    '[autocomplete="current-password"]',
    '[autocomplete="new-password"]',
    'input[autocomplete*="password"]',
  ]) {
    assert.equal(looksLikePasswordField(selector), true, selector);
  }
  assert.equal(looksLikePasswordField('input[name="q"]', "type=password"), true);
  assert.equal(looksLikePasswordField("input[name=note]", "autocomplete=current-password"), true);

  assert.equal(looksLikePasswordField('button[type="submit"]'), false);
  assert.equal(looksLikePasswordField("a[href='/forgot-password']"), false);
  assert.equal(looksLikePasswordField('input[name="q"]', "hello"), false);
  assert.equal(looksLikePasswordField("main"), false);
});

test("detects login pages and challenge widgets without treating ordinary pages as challenges", () => {
  assert.equal(
    looksLikeLoginOrChallenge({
      url: "https://example.com/dashboard",
      hasPasswordInput: false,
      textSample: "Welcome back",
    }),
    false,
  );
  assert.equal(
    looksLikeLoginOrChallenge({
      url: "https://example.com/login",
      hasPasswordInput: false,
      textSample: "Welcome",
    }),
    true,
  );
  assert.equal(
    looksLikeLoginOrChallenge({
      url: "https://example.com/settings",
      hasPasswordInput: true,
      textSample: "Account",
    }),
    true,
  );
  assert.equal(
    looksLikeLoginOrChallenge({
      url: "https://example.com/app",
      hasPasswordInput: false,
      textSample: "Please verify you are human",
    }),
    true,
  );
  assert.equal(looksLikeChallengeWidget("iframe[title='reCAPTCHA']"), true);
  assert.equal(looksLikeChallengeWidget("button.save"), false);
});
