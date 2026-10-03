import assert from "node:assert/strict";
import test from "node:test";
import {
  PolicyError,
  assertAddressInResolvedSet,
  assertNavigationPeer,
  assertObservedPeer,
  assertOrigin,
  assertPinnedHost,
  canonicalIp,
  defaultResolveHost,
  hostResolverRules,
  mappedPinAddress,
  requestTargetsBlockedHost,
  elementIsChallenge,
  elementIsPassword,
  looksLikeChallengeWidget,
  looksLikeLoginOrChallenge,
  looksLikePasswordField,
  parseHttpUrl,
  redactUrl,
  scrubPublicText,
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

test("refuses link-local and metadata hosts, including normalized address forms", () => {
  for (const bad of [
    "http://169.254.169.254/latest/meta-data/",
    "http://2852039166/",
    "http://0xA9.0xFE.0xA9.0xFE/",
    "http://[::ffff:169.254.169.254]/",
    "http://[fe80::1]/",
    "http://[::]/",
    "http://0.0.0.0/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/",
    "http://[fd00:ec2::254]/",
  ]) {
    assert.throws(() => parseHttpUrl(bad), PolicyError);
    assert.throws(() => assertOrigin(new URL(bad).origin), PolicyError);
  }
  assert.equal(parseHttpUrl("http://127.0.0.1:3000/").origin, "http://127.0.0.1:3000");
  assert.equal(assertOrigin("http://localhost:3000"), "http://localhost:3000");
  assert.equal(parseHttpUrl("http://10.0.0.5/").origin, "http://10.0.0.5");
  assert.equal(parseHttpUrl("http://[::1]/").origin, "http://[::1]");
});

test("redacts credential query values and fragments, not ordinary query keys", () => {
  const redacted = redactUrl("https://user:secret@example.com/cb?code=secret-token&tab=1#access_token=zzz");
  assert.equal(redacted.includes("secret-token"), false);
  assert.equal(redacted.includes("user:secret"), false);
  assert.equal(redacted.includes("access_token"), false);
  assert.match(redacted, /tab=1/);
  assert.equal(redactUrl("https://example.com/dashboard"), "https://example.com/dashboard");
});

test("scrubbed errors keep the failure and drop urls and typed secrets", () => {
  const text = scrubPublicText(
    'page.goto: Timeout 20000ms exceeded.\nnavigating to "https://example.com/cb?code=secret-token"',
    ["super-secret-value"],
  );
  assert.equal(text.includes("secret-token"), false);
  assert.equal(text.includes("super-secret-value"), false);
  assert.match(text, /Timeout/);
  assert.equal(text.includes("\n"), false);
});

test("element facts catch password and challenge nodes selectors can hide", () => {
  assert.equal(
    elementIsPassword({
      tag: "input",
      type: "password",
      autocomplete: null,
      name: "q",
      id: null,
      className: null,
      src: null,
      title: null,
      role: null,
    }),
    true,
  );
  assert.equal(
    elementIsPassword({
      tag: "input",
      type: "text",
      autocomplete: "current-password",
      name: "x",
      id: null,
      className: null,
      src: null,
      title: null,
      role: null,
    }),
    true,
  );
  assert.equal(
    elementIsChallenge({
      tag: "iframe",
      type: null,
      autocomplete: null,
      name: null,
      id: "widget",
      className: null,
      src: "https://challenges.cloudflare.com/turnstile/v0",
      title: null,
      role: null,
    }),
    true,
  );
  assert.equal(
    elementIsPassword({
      tag: "button",
      type: "submit",
      autocomplete: null,
      name: "go",
      id: null,
      className: "primary",
      src: null,
      title: null,
      role: null,
    }),
    false,
  );
});


test("pins DNS names and rejects rebinding onto link-local, metadata, or unspecified addresses", async () => {
  let called = false;
  await assertPinnedHost("10.0.0.5", async () => {
    called = true;
    return ["127.0.0.1"];
  });
  assert.equal(called, false);
  await assertPinnedHost("127.0.0.1", async () => {
    throw new Error("should not resolve a literal");
  });

  await assertPinnedHost("example.com", async () => ["93.184.216.34"]);
  await assertPinnedHost("localhost", async () => ["127.0.0.1", "::1"]);

  for (const answers of [
    ["169.254.169.254"],
    ["0.0.0.0"],
    ["::"],
    ["fe80::1"],
    ["100.100.100.200"],
    ["93.184.216.34", "169.254.169.254"],
    ["::ffff:169.254.169.254"],
  ]) {
    await assert.rejects(() => assertPinnedHost("rebind.example", async () => answers), PolicyError);
  }

  await assert.rejects(() => assertPinnedHost("intranet", async () => ["10.1.1.1"]), /pinnable DNS name/);
  await assert.rejects(() => assertPinnedHost("bad_host.example", async () => ["10.1.1.1"]), /pinnable DNS name/);
  await assert.rejects(
    () =>
      assertPinnedHost("missing.example", async () => {
        throw new Error("ENOTFOUND missing.example");
      }),
    /could not be resolved/,
  );
});

test("host resolver rules reject metadata addresses and pin one checked address", () => {
  assert.throws(
    () => hostResolverRules([{ hostname: "evil.example", addresses: ["169.254.169.254"] }]),
    PolicyError,
  );
  assert.throws(
    () => hostResolverRules([{ hostname: "evil.example", addresses: ["93.184.216.34", "169.254.169.254"] }]),
    /link-local|metadata|unspecified/,
  );
  for (const bad of ["0.0.0.0", "::", "fe80::1", "100.100.100.200", "::ffff:169.254.169.254"]) {
    assert.throws(
      () => hostResolverRules([{ hostname: "evil.example", addresses: [bad] }]),
      PolicyError,
      bad,
    );
  }
  const many = ["203.0.113.9", "93.184.216.34", "2001:db8::2"];
  assert.equal(
    hostResolverRules([{ hostname: "Example.COM", addresses: many }]),
    "MAP example.com 93.184.216.34",
  );
  assert.equal(mappedPinAddress(many), "93.184.216.34");
  assert.doesNotThrow(() => assertAddressInResolvedSet("93.184.216.34", many));
  assert.doesNotThrow(() => assertAddressInResolvedSet("2001:0db8:0:0:0:0:0:2", many));
  assert.throws(() => assertAddressInResolvedSet("198.51.100.4", many), /not in the resolved set/);
  assert.doesNotThrow(() => assertObservedPeer(many, "203.0.113.9"));
  assert.doesNotThrow(() => assertObservedPeer(many, "2001:db8::2"));
  assert.throws(() => assertObservedPeer(many, "198.51.100.4"), /not in the resolved set/);
  assert.throws(() => assertObservedPeer(many, null), /could not be checked/);
  assert.doesNotThrow(() => assertObservedPeer(["93.184.216.34"], null));
  assert.throws(
    () => assertNavigationPeer([{ hostname: "example.com", addresses: many }], "https://example.com/app", "198.51.100.4"),
    /not in the resolved set/,
  );
  assert.doesNotThrow(() =>
    assertNavigationPeer([{ hostname: "example.com", addresses: many }], "https://cdn.example/app.js", "198.51.100.8"),
  );
  assert.equal(
    hostResolverRules([{ hostname: "v6.example", addresses: ["2001:db8::2"] }]),
    "MAP v6.example [2001:db8::2]",
  );
  assert.equal(hostResolverRules([{ hostname: "10.0.0.5", addresses: ["10.0.0.5"] }]), "");
  assert.equal(
    hostResolverRules([
      { hostname: "b.example", addresses: ["203.0.113.8"] },
      { hostname: "a.example", addresses: ["203.0.113.7", "2001:db8::1"] },
    ]),
    "MAP a.example 203.0.113.7, MAP b.example 203.0.113.8",
  );
});

test("DNS pin keeps every checked address and blocks metadata subresources only", async () => {
  assert.equal(canonicalIp("2001:0db8:0000::0002"), "2001:db8::2");
  assert.equal(canonicalIp("::1"), "::1");
  assert.equal(canonicalIp("::"), "::");
  assert.equal(canonicalIp("93.184.216.34"), "93.184.216.34");
  const answers = await defaultResolveHost("localhost");
  assert.ok(answers.includes("127.0.0.1") || answers.includes("::1"));
  assert.equal(answers.some((address) => address === "169.254.169.254"), false);

  assert.equal(requestTargetsBlockedHost("https://cdn.example/app.js"), false);
  assert.equal(requestTargetsBlockedHost("https://accounts.example/oauth"), false);
  assert.equal(requestTargetsBlockedHost("about:blank"), false);
  assert.equal(requestTargetsBlockedHost("http://169.254.169.254/latest/meta-data"), true);
  assert.equal(requestTargetsBlockedHost("http://metadata.google.internal/computeMetadata/v1/"), true);
  assert.equal(requestTargetsBlockedHost("http://[fe80::1]/"), true);
  assert.equal(requestTargetsBlockedHost("http://0.0.0.0/"), true);
  assert.equal(requestTargetsBlockedHost("http://[::]/"), true);
  assert.equal(requestTargetsBlockedHost("http://127.0.0.1/allow"), false);
});
