import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const HTTP_PROTOCOLS = new Set(["http:", "https:"]);

const TYPE_PASSWORD = /type\s*=\s*["']?password\b/i;
const AUTOCOMPLETE_PASSWORD =
  /autocomplete\s*=\s*["']?(?:[^"'\]\s]*password|current-password|new-password)\b/i;
const NAME_OR_ID_PASSWORD =
  /(?:^|[^\w-])(?:name|id)\s*=\s*["']?[^"'=\s\]]*(?:password|passwd)\b/i;
const HASH_OR_CLASS_PASSWORD = /(?:#|\.)[\w-]*password[\w-]*(?=$|[^\w-])/i;
const ATTR_PASSWORD =
  /\[(?:name|id|autocomplete)\s*[*~|^$]?=\s*["'][^"']*password[^"']*["']\]/i;
const INPUT_PASSWORD =
  /(?:input|textarea)[^\n]*password|password[^\n]*(?:input|textarea)/i;

const CHALLENGE_WIDGET =
  /recaptcha|hcaptcha|turnstile|cf-turnstile|g-recaptcha|captcha-challenge|arkose|funcaptcha/i;

const LOGIN_URL = [
  /\/(?:login|log-in|signin|sign-in|sign_in|session\/new)(?:\/|$|\?|#)/i,
  /\/(?:challenge|checkpoint|captcha|two-factor|2fa|mfa)(?:\/|$|\?|#)/i,
  /[?&](?:captcha|challenge)=/i,
];

const LOGIN_TEXT = [
  "verify you are human",
  "verify you're human",
  "are you a robot",
  "complete the captcha",
  "unusual traffic",
  "checking your browser",
  "security check",
  "two-factor",
  "two factor",
  "2-step verification",
  "enter your password",
];

const METADATA_HOSTS = new Set([
  "metadata.google.internal",
  "metadata.goog",
  "instance-data",
  "instance-data.ec2.internal",
]);

/** Query names whose values are credentials or login codes. */
const SENSITIVE_QUERY =
  /(?:^|[._-])(?:access|refresh|id|auth|session|api|client)?[._-]?(?:token|password|passwd|secret|session|jwt|otp|sid|code|ticket|assertion|credential)(?:$|[._-])/i;

const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g;
const URL_IN_TEXT = /\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/gi;

const BLOCKED_HOST = "Refusing a link-local, unspecified, or cloud-metadata host.";

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

export interface ElementFacts {
  tag: string;
  type: string | null;
  autocomplete: string | null;
  name: string | null;
  id: string | null;
  className: string | null;
  src: string | null;
  title: string | null;
  role: string | null;
}

export function parseHttpUrl(input: string): URL {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new PolicyError("URL must be an absolute http(s) URL.");
  }
  if (!HTTP_PROTOCOLS.has(url.protocol)) {
    throw new PolicyError("Only http and https URLs are allowed.");
  }
  if (url.username || url.password) {
    throw new PolicyError("URLs must not contain credentials.");
  }
  assertAllowedHost(url);
  return url;
}

export function assertOrigin(input: string): string {
  const trimmed = input.trim();
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new PolicyError("Origin must be a URL origin like https://example.com.");
  }
  if (!HTTP_PROTOCOLS.has(url.protocol)) {
    throw new PolicyError("Origin must use http or https.");
  }
  if (url.username || url.password) {
    throw new PolicyError("Origin must not contain credentials.");
  }
  assertAllowedHost(url);
  if (trimmed !== url.origin) {
    throw new PolicyError(
      `Origin must be exactly the origin, with no path, query, or hash. Expected ${url.origin}.`,
    );
  }
  return url.origin;
}

export function originOfUrl(input: string): string {
  return parseHttpUrl(input).origin;
}

function assertAllowedHost(url: URL): void {
  const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (
    METADATA_HOSTS.has(host) ||
    host.endsWith(".metadata.google.internal") ||
    host.endsWith(".metadata.goog")
  ) {
    throw new PolicyError(BLOCKED_HOST);
  }
  if (isBlockedAddress(host)) {
    throw new PolicyError(BLOCKED_HOST);
  }
}

function isBlockedAddress(host: string): boolean {
  const v4 = parseIPv4(host);
  if (v4) return isBlockedIPv4(v4);
  const hextets = parseIPv6(host);
  if (!hextets) return false;
  if (hextets.every((part) => part === 0)) return true;
  const first = hextets[0] ?? 0;
  if ((first & 0xffc0) === 0xfe80) return true;
  if (
    hextets[0] === 0xfd00 &&
    hextets[1] === 0x0ec2 &&
    hextets[2] === 0 &&
    hextets[3] === 0 &&
    hextets[4] === 0 &&
    hextets[5] === 0 &&
    hextets[6] === 0 &&
    hextets[7] === 0x0254
  ) {
    return true;
  }
  if (hextets.slice(0, 5).every((part) => part === 0) && hextets[5] === 0xffff) {
    const hi = hextets[6] ?? 0;
    const lo = hextets[7] ?? 0;
    return isBlockedIPv4([(hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255]);
  }
  return false;
}

function isBlockedIPv4(parts: number[]): boolean {
  const a = parts[0] ?? 0;
  const b = parts[1] ?? 0;
  const c = parts[2] ?? 0;
  const d = parts[3] ?? 0;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b === 100 && c === 100 && d === 200) return true;
  return false;
}

function parseIPv4(host: string): number[] | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!match) return null;
  const parts = match.slice(1).map((part) => Number(part));
  if (parts.some((part) => !Number.isInteger(part) || part > 255)) return null;
  return parts;
}

function parseIPv6(host: string): number[] | null {
  if (host.includes(".")) return null;
  const halves = host.split("::");
  if (halves.length > 2) return null;
  const parseSide = (side: string): number[] | null => {
    if (side.length === 0) return [];
    const out: number[] = [];
    for (const bit of side.split(":")) {
      if (!/^[0-9a-f]{1,4}$/i.test(bit)) return null;
      out.push(parseInt(bit, 16));
    }
    return out;
  };
  const left = parseSide(halves[0] ?? "");
  if (!left) return null;
  if (halves.length === 1) return left.length === 8 ? left : null;
  const right = parseSide(halves[1] ?? "");
  if (!right) return null;
  const missing = 8 - left.length - right.length;
  if (missing < 0) return null;
  return [...left, ...Array<number>(missing).fill(0), ...right];
}

function isPasswordDescriptor(value: string): boolean {
  return (
    TYPE_PASSWORD.test(value) ||
    AUTOCOMPLETE_PASSWORD.test(value) ||
    NAME_OR_ID_PASSWORD.test(value) ||
    HASH_OR_CLASS_PASSWORD.test(value) ||
    ATTR_PASSWORD.test(value) ||
    INPUT_PASSWORD.test(value)
  );
}

export function looksLikePasswordField(selector: string, value?: string): boolean {
  if (isPasswordDescriptor(selector)) return true;
  if (value !== undefined && isPasswordDescriptor(value)) return true;
  return false;
}

export function looksLikeChallengeWidget(selector: string, value?: string): boolean {
  if (CHALLENGE_WIDGET.test(selector)) return true;
  if (value !== undefined && CHALLENGE_WIDGET.test(value)) return true;
  return false;
}

function hasPasswordToken(value: string): boolean {
  return /(?:^|[^a-z0-9])(?:password|passwd|passcode|pwd)(?:[^a-z0-9]|$)/i.test(value);
}

export function elementIsPassword(facts: ElementFacts): boolean {
  const type = (facts.type ?? "").trim().toLowerCase();
  if (type === "password") return true;
  const autocomplete = (facts.autocomplete ?? "").toLowerCase();
  if (autocomplete.includes("password")) return true;
  if (hasPasswordToken(facts.name ?? "") || hasPasswordToken(facts.id ?? "")) return true;
  return false;
}

export function elementIsChallenge(facts: ElementFacts): boolean {
  const blob = [facts.id, facts.className, facts.src, facts.title, facts.name, facts.role]
    .filter((part): part is string => Boolean(part))
    .join(" ");
  return CHALLENGE_WIDGET.test(blob);
}

export function looksLikeLoginOrChallenge(input: {
  url: string;
  hasPasswordInput: boolean;
  textSample: string;
}): boolean {
  if (input.hasPasswordInput) return true;
  if (LOGIN_URL.some((pattern) => pattern.test(input.url))) return true;
  const text = input.textSample.toLowerCase();
  if (LOGIN_TEXT.some((marker) => text.includes(marker))) return true;
  if (text.includes("just a moment") && text.includes("cloudflare")) return true;
  return false;
}

export function redactUrl(input: string): string {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return "[invalid-url]";
  }
  url.username = "";
  url.password = "";
  url.hash = "";
  for (const key of [...url.searchParams.keys()]) {
    if (SENSITIVE_QUERY.test(key)) url.searchParams.set(key, "redacted");
  }
  return url.toString();
}

/** Drop secrets, credential URLs, and JWTs before a string is logged or returned. */
export function scrubPublicText(input: string, secrets: readonly string[] = []): string {
  let text = input;
  for (const secret of secrets) {
    if (secret.length === 0) continue;
    text = text.split(secret).join("[redacted]");
    const encoded = encodeURIComponent(secret);
    if (encoded !== secret) text = text.split(encoded).join("[redacted]");
  }
  text = text.replace(JWT, "[redacted-jwt]");
  text = text.replace(URL_IN_TEXT, (match) => {
    const trimmed = match.replace(/[),.;]+$/g, "");
    const suffix = match.slice(trimmed.length);
    return redactUrl(trimmed) + suffix;
  });
  const line = (text.split("\n")[0] ?? text).replace(/[\r\n]/g, " ");
  return line.slice(0, 300);
}


const DNS_LABEL = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$/;

export type HostResolver = (hostname: string) => Promise<readonly string[]>;

export function hostLabel(hostname: string): string {
  let host = hostname.toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (host.endsWith(".")) host = host.slice(0, -1);
  return host;
}

/** Names we will look up and reject if any answer is link-local, metadata, or unspecified. */
export function isPinnableDnsName(hostname: string): boolean {
  const host = hostLabel(hostname);
  if (host === "localhost") return true;
  if (host.length === 0 || host.length > 253 || !host.includes(".")) return false;
  return host.split(".").every((label) => DNS_LABEL.test(label));
}

export function assertResolvedAddress(address: string): void {
  const trimmed = address.trim().toLowerCase();
  if (isIP(trimmed) === 0) throw new PolicyError(BLOCKED_HOST);
  const literal = trimmed.includes(":") ? `http://[${trimmed}]/` : `http://${trimmed}/`;
  parseHttpUrl(literal);
}

export interface HostPin {
  hostname: string;
  addresses: readonly string[];
}

/**
 * IP literals are checked directly. DNS names must resolve, and every answer
 * must be a pinned-safe address. One link-local, metadata, or unspecified
 * answer rejects the host (DNS rebinding). Returns the checked addresses.
 */
export async function resolvePinnedHost(
  hostname: string,
  resolve: HostResolver,
): Promise<readonly string[]> {
  const host = hostLabel(hostname);
  if (isIP(host) !== 0) {
    assertResolvedAddress(host);
    return [host];
  }
  if (!isPinnableDnsName(host)) {
    throw new PolicyError("Refusing a host that is not a pinnable DNS name.");
  }
  let answers: readonly string[];
  try {
    answers = await resolve(host);
  } catch {
    throw new PolicyError("Refusing a host that could not be resolved and pinned.");
  }
  if (answers.length === 0) {
    throw new PolicyError("Refusing a host that could not be resolved and pinned.");
  }
  const checked: string[] = [];
  for (const answer of answers) {
    try {
      assertResolvedAddress(answer);
    } catch {
      throw new PolicyError(
        "Refusing a host that resolves to a link-local, metadata, or unspecified address.",
      );
    }
    checked.push(answer.trim().toLowerCase());
  }
  return checked;
}

export async function assertPinnedHost(hostname: string, resolve: HostResolver): Promise<void> {
  await resolvePinnedHost(hostname, resolve);
}

/**
 * Chromium --host-resolver-rules value. MAP accepts one replacement, so each
 * DNS name is pinned to one checked address (lowest IPv4, else lowest IPv6).
 * Every address is rejected first if it is link-local, metadata, or unspecified.
 * IPv6 replacements are bracketed so the last colon is not parsed as a port.
 */
export function hostResolverRules(pins: readonly HostPin[]): string {
  const rules: string[] = [];
  const items = pins
    .map((pin) => ({ hostname: hostLabel(pin.hostname), addresses: pin.addresses }))
    .sort((a, b) => a.hostname.localeCompare(b.hostname));
  for (const pin of items) {
    if (isIP(pin.hostname) !== 0) {
      assertResolvedAddress(pin.hostname);
      continue;
    }
    if (!isPinnableDnsName(pin.hostname)) {
      throw new PolicyError("Refusing a host that is not a pinnable DNS name.");
    }
    if (pin.addresses.length === 0) {
      throw new PolicyError("Refusing a host that could not be resolved and pinned.");
    }
    const checked: string[] = [];
    for (const address of pin.addresses) {
      assertResolvedAddress(address);
      checked.push(address.trim().toLowerCase());
    }
    const chosen = choosePinAddress(checked);
    rules.push(`MAP ${pin.hostname} ${formatResolverAddress(chosen)}`);
  }
  return rules.join(", ");
}

function choosePinAddress(addresses: readonly string[]): string {
  const unique = [...new Set(addresses)];
  const v4 = unique.filter((address) => isIP(address) === 4).sort(compareIPv4);
  if (v4.length > 0) return v4[0]!;
  const v6 = unique.filter((address) => isIP(address) === 6).sort();
  if (v6.length === 0) {
    throw new PolicyError("Refusing a host that could not be resolved and pinned.");
  }
  return v6[0]!;
}

function compareIPv4(a: string, b: string): number {
  const left = a.split(".").map((part) => Number(part));
  const right = b.split(".").map((part) => Number(part));
  for (let i = 0; i < 4; i += 1) {
    const diff = (left[i] ?? 0) - (right[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function formatResolverAddress(address: string): string {
  if (address.includes(":")) return `[${address.replace(/^\[|\]$/g, "")}]`;
  return address;
}

export async function defaultResolveHost(hostname: string): Promise<string[]> {
  const records = await lookup(hostLabel(hostname), { all: true, verbatim: true });
  return records.map((record) => record.address);
}

export async function screenHttpUrl(
  input: string,
  resolve: HostResolver = defaultResolveHost,
): Promise<URL> {
  const url = parseHttpUrl(input);
  await assertPinnedHost(url.hostname, resolve);
  return url;
}
