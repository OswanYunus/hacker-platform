import type { HttpExchange, RawObservation } from "../types.js";

export function checkUnsafeCaching(exchange: HttpExchange): RawObservation[] {
  const h = lowerKeys(exchange.response.headers);
  const contentType = h["content-type"] || "";
  if (!contentType.includes("text/html") && !contentType.includes("application/json")) return [];
  if (exchange.response.status >= 400) return [];

  const looksAuthenticated =
    !!exchange.request.headers["Cookie"] ||
    !!exchange.request.headers["Authorization"] ||
    !!exchange.actorRole;
  if (!looksAuthenticated) return [];

  const cacheControl = h["cache-control"] || "";
  const hasNoStore = /no-store/i.test(cacheControl);
  const hasPrivate = /private/i.test(cacheControl);

  if (!hasNoStore && !hasPrivate) {
    return [
      {
        ruleId: "cacheable-authenticated-response",
        title: "Authenticated response is cacheable by shared/intermediate caches",
        severity: "medium",
        confidence: "medium",
        cwe: "CWE-525",
        owaspCategory: "WSTG-ATHZ-01",
        affectedEndpoint: exchange.request.url,
        rootCause: `Request was authenticated (cookie/token present) but Cache-Control was "${cacheControl || "(absent)"}", which does not prevent shared caching.`,
        impact: "A shared proxy, CDN, or browser disk cache could serve one user's authenticated response to a different user.",
        remediation: 'Send "Cache-Control: no-store, private" on all responses containing user-specific or sensitive data.',
        references: ["https://owasp.org/www-project-web-security-testing-guide/"],
        evidence: [{ description: `Cache-Control: ${cacheControl || "(absent)"}`, exchangeId: exchange.id }],
        reproduction: `Authenticate, request ${exchange.request.url}, and inspect the Cache-Control header.`,
        verification: "likely",
        firstSeenStage: "passive_analysis",
        module: "session",
      },
    ];
  }
  return [];
}

// Conservative, high-precision patterns only — this is passive discovery of
// secrets the application itself already shipped to the browser, not a
// generic entropy scanner (which produces too many false positives to be
// trustworthy in an automated report).
const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp; severity: RawObservation["severity"] }> = [
  { name: "AWS Access Key ID", pattern: /AKIA[0-9A-Z]{16}/, severity: "critical" },
  { name: "Google API Key", pattern: /AIza[0-9A-Za-z\-_]{35}/, severity: "high" },
  { name: "Stripe Live Secret Key", pattern: /sk_live_[0-9a-zA-Z]{24,}/, severity: "critical" },
  { name: "Slack Token", pattern: /xox[baprs]-[0-9A-Za-z-]{10,}/, severity: "high" },
  { name: "Private Key Block", pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/, severity: "critical" },
  { name: "Generic JWT", pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, severity: "info" },
];

export function checkClientSideSecrets(exchange: HttpExchange): RawObservation[] {
  const contentType = (exchange.response.headers["content-type"] || "").toLowerCase();
  if (!contentType.includes("javascript") && !contentType.includes("text/html") && !contentType.includes("json")) return [];
  const body = exchange.response.body ?? "";
  if (!body) return [];

  const observations: RawObservation[] = [];
  for (const { name, pattern, severity } of SECRET_PATTERNS) {
    const match = body.match(pattern);
    if (match) {
      observations.push({
        ruleId: `client-side-secret-${name.toLowerCase().replace(/\s+/g, "-")}`,
        title: `Possible ${name} exposed in client-delivered content`,
        severity,
        confidence: name === "Generic JWT" ? "low" : "medium",
        cwe: "CWE-312",
        owaspCategory: "WSTG-CONF-05",
        affectedEndpoint: exchange.request.url,
        rootCause: `Content served to the browser matches the pattern for a ${name}.`,
        impact:
          severity === "info"
            ? "JWTs are expected in some client contexts; confirm it is short-lived and scoped appropriately."
            : "Secrets shipped to the client are visible to anyone who views source, regardless of authentication on the page itself.",
        remediation: "Move the secret server-side, rotate it, and issue narrowly-scoped, short-lived tokens to the client instead.",
        references: ["https://owasp.org/www-project-web-security-testing-guide/"],
        // Evidence intentionally redacts the matched secret value itself.
        evidence: [{ description: `Pattern "${name}" matched in response body (value redacted from report).`, exchangeId: exchange.id }],
        reproduction: `Fetch ${exchange.request.url} and search the response body for a ${name}-shaped token.`,
        verification: "likely",
        firstSeenStage: "passive_analysis",
        module: "client-side",
      });
    }
  }
  return observations;
}

function lowerKeys(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = v;
  return out;
}
