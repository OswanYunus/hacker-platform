import type { HttpExchange, RawObservation } from "../types.js";

/**
 * Checks response headers against the OWASP Secure Headers Project
 * baseline. Only flags a header as missing on HTML document responses —
 * flagging every single JS/CSS/image asset would flood the findings list
 * with noise that doesn't change the fix (the fix is applied once, at
 * the server/middleware level).
 */
export function checkSecurityHeaders(exchange: HttpExchange): RawObservation[] {
  const { response, request } = exchange;
  const contentType = (response.headers["content-type"] || "").toLowerCase();
  const isHtmlDocument = contentType.includes("text/html");
  const observations: RawObservation[] = [];

  if (response.status >= 400) return observations;

  const h = lowerKeys(response.headers);

  // CORS misconfiguration matters on any response (HTML or JSON API), so
  // it is checked before the HTML-only gate below applies to the rest.
  if (h["access-control-allow-origin"] === "*" && h["access-control-allow-credentials"] === "true") {
    observations.push(
      makeObservation(exchange, {
        ruleId: "cors-wildcard-with-credentials",
        title: "CORS allows any origin with credentials",
        severity: "critical",
        confidence: "confirmed",
        cwe: "CWE-942",
        owaspCategory: "WSTG-CLNT-07",
        rootCause:
          "The response sends Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.",
        impact:
          "Any website can read authenticated responses from this endpoint on behalf of a logged-in victim, " +
          "effectively bypassing the same-origin policy for this API.",
        remediation:
          "Never combine a wildcard origin with credentialed requests. Reflect a specific, validated origin " +
          "from an allow-list instead of '*' when Allow-Credentials is true.",
        references: ["https://portswigger.net/web-security/cors"],
      }),
    );
  }

  if (!isHtmlDocument) return observations;

  if (!h["strict-transport-security"] && request.url.startsWith("https://")) {
    observations.push(
      makeObservation(exchange, {
        ruleId: "missing-hsts",
        title: "Missing Strict-Transport-Security header",
        severity: "medium",
        confidence: "high",
        cwe: "CWE-319",
        owaspCategory: "OWASP ASVS 14.4 / WSTG-CONF-07",
        rootCause: "The server does not send a Strict-Transport-Security header on HTTPS responses.",
        impact:
          "Browsers may be downgraded to plain HTTP by a network attacker (e.g. on untrusted Wi-Fi), exposing " +
          "session cookies and request contents to interception.",
        remediation:
          "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all HTTPS responses, " +
          "after confirming every subdomain correctly supports HTTPS.",
        references: ["https://owasp.org/www-project-secure-headers/"],
        detail: `Response headers did not include strict-transport-security`,
      }),
    );
  }

  if (!h["x-content-type-options"]) {
    observations.push(
      makeObservation(exchange, {
        ruleId: "missing-x-content-type-options",
        title: "Missing X-Content-Type-Options header",
        severity: "low",
        confidence: "high",
        cwe: "CWE-430",
        owaspCategory: "WSTG-CONF-07",
        rootCause: "The server does not send X-Content-Type-Options: nosniff.",
        impact:
          "Some browsers may MIME-sniff response bodies and execute content as a different type than declared, " +
          "which can enable content-type confusion attacks in combination with user-uploaded content.",
        remediation: "Send 'X-Content-Type-Options: nosniff' on all responses.",
        references: ["https://owasp.org/www-project-secure-headers/"],
      }),
    );
  }

  if (!h["content-security-policy"]) {
    observations.push(
      makeObservation(exchange, {
        ruleId: "missing-csp",
        title: "Missing Content-Security-Policy header",
        severity: "medium",
        confidence: "high",
        cwe: "CWE-1021",
        owaspCategory: "WSTG-CLNT-12",
        rootCause: "The server does not send a Content-Security-Policy header.",
        impact:
          "Without a CSP, the browser applies no additional restriction on script execution or resource loading, " +
          "increasing the impact of any cross-site scripting vulnerability found elsewhere in the application.",
        remediation:
          "Define a Content-Security-Policy appropriate to the app (start with a report-only policy, then " +
          "enforce once violations are understood). At minimum restrict script-src to trusted origins.",
        references: ["https://owasp.org/www-project-secure-headers/", "https://content-security-policy.com/"],
      }),
    );
  }

  if (!h["x-frame-options"] && !cspHasFrameAncestors(h["content-security-policy"])) {
    observations.push(
      makeObservation(exchange, {
        ruleId: "missing-frame-protection",
        title: "Missing clickjacking protection (X-Frame-Options / frame-ancestors)",
        severity: "low",
        confidence: "high",
        cwe: "CWE-1021",
        owaspCategory: "WSTG-CLNT-09",
        rootCause: "Neither X-Frame-Options nor a CSP frame-ancestors directive is present.",
        impact: "The page can be embedded in an attacker-controlled iframe, enabling clickjacking attacks.",
        remediation: "Send 'X-Frame-Options: DENY' (or SAMEORIGIN) or a CSP with frame-ancestors 'none'.",
        references: ["https://owasp.org/www-project-secure-headers/"],
      }),
    );
  }

  return observations;
}

export function checkCorsReflection(exchange: HttpExchange, requestOrigin: string): RawObservation[] {
  const h = lowerKeys(exchange.response.headers);
  const observations: RawObservation[] = [];
  const allowOrigin = h["access-control-allow-origin"];
  if (allowOrigin && allowOrigin !== "*" && allowOrigin.toLowerCase() === requestOrigin.toLowerCase()) {
    // The server reflected an arbitrary, attacker-chosen Origin back verbatim.
    observations.push(
      makeObservation(exchange, {
        ruleId: "cors-origin-reflection",
        title: "CORS policy reflects arbitrary Origin header",
        severity: h["access-control-allow-credentials"] === "true" ? "high" : "medium",
        confidence: "high",
        cwe: "CWE-942",
        owaspCategory: "WSTG-CLNT-07",
        rootCause:
          "The Access-Control-Allow-Origin value exactly echoes a test Origin header that was not on any " +
          "expected allow-list, indicating the server reflects whatever Origin it receives.",
        impact:
          "Any site can issue cross-origin requests to this endpoint and read the response, which is especially " +
          "dangerous if the endpoint returns sensitive data or is reachable with the victim's session.",
        remediation: "Validate the Origin header against an explicit allow-list rather than reflecting it.",
        references: ["https://portswigger.net/web-security/cors"],
        detail: `Sent Origin: ${requestOrigin}; received Access-Control-Allow-Origin: ${allowOrigin}`,
      }),
    );
  }
  return observations;
}

function cspHasFrameAncestors(csp?: string): boolean {
  return !!csp && /frame-ancestors/i.test(csp);
}

function lowerKeys(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = v;
  return out;
}

function makeObservation(
  exchange: HttpExchange,
  fields: Omit<
    RawObservation,
    "affectedEndpoint" | "evidence" | "verification" | "firstSeenStage" | "module" | "reproduction"
  > & {
    detail?: string;
  },
): RawObservation {
  const { detail, ...rest } = fields;
  return {
    ...rest,
    affectedEndpoint: exchange.request.url,
    evidence: [
      {
        description: detail ?? `Observed on ${exchange.request.method} ${exchange.request.url}`,
        exchangeId: exchange.id,
        detail,
      },
    ],
    reproduction: `${exchange.request.method} ${exchange.request.url} and inspect response headers.`,
    verification: "confirmed", // passive header checks are deterministic, not heuristic
    firstSeenStage: "passive_analysis",
    module: "configuration",
  };
}
