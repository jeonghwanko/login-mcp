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

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
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
