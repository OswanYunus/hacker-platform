import type { HttpExchange, RawObservation } from "../types.js";

interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  raw: string;
}

function parseSetCookie(headerValue: string): ParsedCookie {
  const parts = headerValue.split(";").map((p) => p.trim());
  const [nameValue, ...attrs] = parts;
  const name = nameValue.split("=")[0];
  const lowerAttrs = attrs.map((a) => a.toLowerCase());
  const sameSiteAttr = attrs.find((a) => a.toLowerCase().startsWith("samesite"));
  return {
    name,
    secure: lowerAttrs.includes("secure"),
    httpOnly: lowerAttrs.includes("httponly"),
    sameSite: sameSiteAttr?.split("=")[1]?.trim(),
    raw: headerValue,
  };
}

/** Heuristic for cookies that plausibly carry session/auth state, so we
 * don't flag every analytics cookie with the same severity as a session
 * token missing HttpOnly. */
function looksLikeSessionCookie(name: string): boolean {
  return /session|sess|auth|token|jwt|sid|login|csrf/i.test(name);
}

export function checkCookies(exchange: HttpExchange): RawObservation[] {
  const setCookieHeaders = collectSetCookieHeaders(exchange.response.headers);
  if (setCookieHeaders.length === 0) return [];

  const isHttps = exchange.request.url.startsWith("https://");
  const observations: RawObservation[] = [];

  for (const raw of setCookieHeaders) {
    const cookie = parseSetCookie(raw);
    const sensitive = looksLikeSessionCookie(cookie.name);

    if (!cookie.secure && isHttps) {
      observations.push(
        makeObservation(exchange, cookie, {
          ruleId: "cookie-missing-secure",
          title: `Cookie "${cookie.name}" set without Secure attribute`,
          severity: sensitive ? "high" : "low",
          confidence: "confirmed",
          cwe: "CWE-614",
          owaspCategory: "WSTG-SESS-02",
          rootCause: `The Set-Cookie header for "${cookie.name}" omits the Secure attribute on an HTTPS response.`,
          impact:
            "The cookie may be sent over an unencrypted HTTP connection if the site is ever reached over HTTP, " +
            "exposing it to network interception.",
          remediation: `Add the Secure attribute to the "${cookie.name}" cookie.`,
        }),
      );
    }

    if (!cookie.httpOnly && sensitive) {
      observations.push(
        makeObservation(exchange, cookie, {
          ruleId: "cookie-missing-httponly",
          title: `Session-like cookie "${cookie.name}" set without HttpOnly`,
          severity: "high",
          confidence: "high",
          cwe: "CWE-1004",
          owaspCategory: "WSTG-SESS-02",
          rootCause: `The Set-Cookie header for "${cookie.name}" omits HttpOnly, and the name suggests it carries session/auth state.`,
          impact: "If a cross-site scripting vulnerability exists anywhere on the site, this cookie can be read and exfiltrated by injected script.",
          remediation: `Add the HttpOnly attribute to "${cookie.name}" unless client-side JavaScript has a specific, documented need to read it.`,
        }),
      );
    }

    if (!cookie.sameSite || cookie.sameSite.toLowerCase() === "none") {
      observations.push(
        makeObservation(exchange, cookie, {
          ruleId: "cookie-weak-samesite",
          title: `Cookie "${cookie.name}" has weak or missing SameSite attribute`,
          severity: sensitive ? "medium" : "info",
          confidence: "high",
          cwe: "CWE-352",
          owaspCategory: "WSTG-SESS-05",
          rootCause: cookie.sameSite
            ? `SameSite=${cookie.sameSite} allows the cookie to be sent on cross-site requests.`
            : `No SameSite attribute was set; browser defaults vary.`,
          impact: sensitive
            ? "A session cookie without SameSite=Lax/Strict increases exposure to cross-site request forgery."
            : "Minor hardening gap; low impact for non-session cookies.",
          remediation: `Set SameSite=Lax (or Strict where the UX allows it) on "${cookie.name}".`,
        }),
      );
    }
  }

  return observations;
}

function collectSetCookieHeaders(headers: Record<string, string>): string[] {
  // Node's fetch Headers merges multiple Set-Cookie into one entry joined
  // by ", " in some runtimes, but splitting naively on comma breaks
  // Expires dates. We handle the common single-cookie case directly and
  // split on ", " only when it's not inside an Expires value.
  const entry = Object.entries(headers).find(([k]) => k.toLowerCase() === "set-cookie");
  if (!entry) return [];
  const value = entry[1];
  // Split on a comma that is followed by a token=value pattern (next cookie),
  // not on commas inside "Expires=Wed, 21 Oct 2026 ...".
  return value.split(/,(?=\s*[^;]+?=)/).map((s) => s.trim());
}

function makeObservation(
  exchange: HttpExchange,
  cookie: ParsedCookie,
  fields: Omit<RawObservation, "affectedEndpoint" | "evidence" | "verification" | "firstSeenStage" | "module" | "references" | "reproduction">,
): RawObservation {
  return {
    ...fields,
    affectedEndpoint: exchange.request.url,
    references: ["https://owasp.org/www-community/controls/SecureCookieAttribute", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"],
    reproduction: `Request ${exchange.request.method} ${exchange.request.url} and inspect the Set-Cookie header for "${cookie.name}".`,
    evidence: [{ description: `Set-Cookie: ${cookie.raw}`, exchangeId: exchange.id }],
    verification: "confirmed",
    firstSeenStage: "passive_analysis",
    module: "session",
  };
}
