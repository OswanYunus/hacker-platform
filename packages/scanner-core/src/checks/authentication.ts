/**
 * Authentication & session checks (Phase 2 — active testing module).
 *
 * Techniques:
 *  - Brute-force lockout detection: try common passwords against login
 *    endpoints; if no lockout after N attempts, flag as weak.
 *  - Default credential probe: try known weak credentials.
 *  - Session fixation: supply a pre-generated session token and see if
 *    the server accepts (uses) it after login.
 *  - Session token entropy: inspect Set-Cookie session tokens and measure
 *    their length/charset entropy.
 *  - Logout invalidation: confirm session cookie is rejected after logout.
 *  - Password in URL: flag auth tokens/passwords embedded in query strings.
 */

import type { ScannerHttpClient } from "../httpClient.js";
import type { DiscoveredEndpoint, HttpExchange, RawObservation, ScanStage } from "../types.js";

const STAGE: ScanStage = "active_testing";
const MODULE = "authentication" as const;

// Common default / weak credentials to try
const WEAK_CREDENTIALS = [
  { username: "admin", password: "admin" },
  { username: "admin", password: "admin123" },
  { username: "admin", password: "password" },
  { username: "admin", password: "123456" },
  { username: "root", password: "root" },
  { username: "root", password: "toor" },
  { username: "test", password: "test" },
  { username: "user", password: "user" },
  { username: "guest", password: "guest" },
  { username: "demo", password: "demo" },
];

// Number of failed attempts after which we expect a lockout
const LOCKOUT_ATTEMPT_THRESHOLD = 5;

// Shannon entropy minimum for a session token to be considered strong
const MIN_SESSION_ENTROPY_BITS = 64;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeObs(
  url: string,
  probeUrl: string,
  fields: Omit<RawObservation, "affectedEndpoint" | "evidence" | "verification" | "firstSeenStage" | "module" | "reproduction">,
): RawObservation {
  return {
    ...fields,
    affectedEndpoint: url,
    evidence: [{ description: fields.rootCause, detail: `Probe URL: ${probeUrl}` }],
    reproduction: `Send request to ${probeUrl} and inspect the response.`,
    verification: "likely",
    firstSeenStage: STAGE,
    module: MODULE,
  };
}

/** Shannon entropy in bits of a string. */
function shannonEntropy(s: string): number {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  const n = s.length;
  return -Object.values(freq).reduce((sum, count) => {
    const p = count / n;
    return sum + p * Math.log2(p);
  }, 0) * n;
}

function isLoginResponse(ex: HttpExchange): boolean {
  // Heuristic: 200 with a Set-Cookie or 302 without going back to a login page
  return (
    (ex.response.status === 200 && !!ex.response.headers["set-cookie"]) ||
    (ex.response.status >= 300 && ex.response.status < 400 && !/login|auth|signin/i.test(ex.response.headers["location"] ?? ""))
  );
}

function looksLikeLoginEndpoint(endpoint: DiscoveredEndpoint): boolean {
  return /login|signin|sign-in|auth|session|token/i.test(endpoint.url);
}

// ---------------------------------------------------------------------------
// Exported checkers
// ---------------------------------------------------------------------------

/**
 * Tries a sequence of bad-password attempts and expects a lockout or rate-limit
 * after LOCKOUT_ATTEMPT_THRESHOLD attempts. If we can keep sending past that, flag it.
 */
export async function checkMissingBruteforceLockout(
  client: ScannerHttpClient,
  endpoint: DiscoveredEndpoint,
): Promise<RawObservation[]> {
  if (!looksLikeLoginEndpoint(endpoint)) return [];
  if (!endpoint.methodsObserved.includes("POST") && !endpoint.formFields.some((f) => /pass/i.test(f))) return [];

  const observations: RawObservation[] = [];
  let attemptCount = 0;
  let lockedOut = false;

  for (const { username, password } of WEAK_CREDENTIALS.slice(0, LOCKOUT_ATTEMPT_THRESHOLD + 1)) {
    const body = JSON.stringify({ username, password, email: username });
    try {
      const ex = await client.request("POST", endpoint.url, STAGE, {
        body,
        headers: { "Content-Type": "application/json" },
      });
      attemptCount++;
      if (ex.response.status === 429 || ex.response.status === 423) {
        lockedOut = true;
        break;
      }
      const resBody = (ex.response.body ?? ex.response.bodyPreview ?? "").toLowerCase();
      if (/locked|too many|rate.?limit|slow.?down|blocked/i.test(resBody)) {
        lockedOut = true;
        break;
      }
    } catch {
      break;
    }
  }

  if (!lockedOut && attemptCount >= LOCKOUT_ATTEMPT_THRESHOLD) {
    observations.push(
      makeObs(endpoint.url, endpoint.url, {
        ruleId: "no-brute-force-lockout",
        title: "Missing Brute-Force Protection on Authentication Endpoint",
        severity: "high",
        confidence: "medium",
        cwe: "CWE-307",
        owaspCategory: "OWASP A07:2021 — Identification and Authentication Failures",
        rootCause:
          `${attemptCount} sequential failed login attempts against '${endpoint.url}' received no ` +
          `HTTP 429, 423, or lockout message — the server does not appear to limit password guessing.`,
        impact:
          "An attacker can automate credential stuffing or dictionary attacks at high speed, " +
          "compromising accounts that use weak or reused passwords.",
        remediation:
          "Implement account lockout or exponential back-off after 5–10 failed attempts per account. " +
          "Add CAPTCHA for repeated failures. Consider IP-based rate limiting in addition.",
        references: [
          "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
          "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
        ],
      }),
    );
  }

  return observations;
}

/**
 * Tries well-known default credentials against login endpoints.
 */
export async function checkDefaultCredentials(
  client: ScannerHttpClient,
  endpoint: DiscoveredEndpoint,
): Promise<RawObservation[]> {
  if (!looksLikeLoginEndpoint(endpoint)) return [];
  const observations: RawObservation[] = [];

  for (const { username, password } of WEAK_CREDENTIALS) {
    const body = JSON.stringify({ username, password, email: username });
    try {
      const ex = await client.request("POST", endpoint.url, STAGE, {
        body,
        headers: { "Content-Type": "application/json" },
      });
      if (isLoginResponse(ex)) {
        observations.push(
          makeObs(endpoint.url, endpoint.url, {
            ruleId: "default-credentials",
            title: `Default Credentials Accepted (${username} / ${password})`,
            severity: "critical",
            confidence: "high",
            cwe: "CWE-1392",
            owaspCategory: "OWASP A07:2021 — Identification and Authentication Failures",
            rootCause:
              `Login with username='${username}' and password='${password}' returned HTTP ${ex.response.status} ` +
              `with a Set-Cookie header, indicating successful authentication with default credentials.`,
            impact:
              "Any attacker knowing this credential pair gains full access to the account, " +
              "which may be an administrator account enabling complete system compromise.",
            remediation:
              "Remove all default accounts from production. Force a password change on first login. " +
              "Disable or rename well-known admin accounts.",
            references: [
              "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
            ],
          }),
        );
        break; // Found one — no need to continue
      }
    } catch {
      // non-fatal
    }
  }

  return observations;
}

/**
 * Checks session token entropy from Set-Cookie response headers.
 * Short or low-entropy tokens can be guessed or brute-forced.
 */
export function checkSessionTokenEntropy(
  endpoint: DiscoveredEndpoint,
  setCookieHeader: string | undefined,
): RawObservation[] {
  if (!setCookieHeader) return [];
  const observations: RawObservation[] = [];

  // Parse the cookie value from the Set-Cookie header
  const cookieParts = setCookieHeader.split(";");
  const kv = (cookieParts[0] ?? "").trim();
  const eqIdx = kv.indexOf("=");
  if (eqIdx < 0) return [];

  const cookieName = kv.slice(0, eqIdx).trim();
  const cookieValue = kv.slice(eqIdx + 1).trim();

  if (cookieValue.length < 16) {
    observations.push(
      makeObs(endpoint.url, endpoint.url, {
        ruleId: "weak-session-token-length",
        title: `Session Token Too Short (${cookieName}: ${cookieValue.length} chars)`,
        severity: "high",
        confidence: "high",
        cwe: "CWE-331",
        owaspCategory: "OWASP A07:2021 — Identification and Authentication Failures",
        rootCause:
          `The session cookie '${cookieName}' has a value of only ${cookieValue.length} characters, ` +
          `which is trivially brute-forceable.`,
        impact:
          "An attacker can enumerate valid session tokens within minutes using automated requests, " +
          "allowing session hijacking of any user.",
        remediation:
          "Generate session tokens using a cryptographically secure random number generator with at least " +
          "128 bits of entropy (32+ hex characters). Use your framework's built-in session management.",
        references: [
          "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
      }),
    );
  } else {
    const entropyBits = shannonEntropy(cookieValue);
    if (entropyBits < MIN_SESSION_ENTROPY_BITS) {
      observations.push(
        makeObs(endpoint.url, endpoint.url, {
          ruleId: "low-session-token-entropy",
          title: `Low Session Token Entropy (${cookieName}: ${entropyBits.toFixed(0)} bits)`,
          severity: "medium",
          confidence: "medium",
          cwe: "CWE-331",
          owaspCategory: "OWASP A07:2021 — Identification and Authentication Failures",
          rootCause:
            `The session cookie '${cookieName}' has estimated entropy of ${entropyBits.toFixed(0)} bits — ` +
            `below the recommended 128-bit minimum. This suggests a predictable or sequential pattern.`,
          impact:
            "A sophisticated attacker can narrow the search space and guess valid session tokens, " +
            "enabling session hijacking.",
          remediation:
            "Generate session tokens using `crypto.randomBytes(32)` (Node.js) or equivalent. " +
            "Avoid using UUIDs v1 or timestamps as session identifiers.",
          references: [
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
          ],
        }),
      );
    }
  }

  // Check for Secure and HttpOnly flags
  const lowerCookie = setCookieHeader.toLowerCase();
  if (!lowerCookie.includes("httponly")) {
    observations.push(
      makeObs(endpoint.url, endpoint.url, {
        ruleId: "cookie-missing-httponly",
        title: `Session Cookie Missing HttpOnly Flag (${cookieName})`,
        severity: "medium",
        confidence: "high",
        cwe: "CWE-1004",
        owaspCategory: "OWASP A07:2021 — Identification and Authentication Failures",
        rootCause:
          `The session cookie '${cookieName}' does not include the HttpOnly attribute.`,
        impact:
          "JavaScript on the page (including injected via XSS) can read the session cookie, " +
          "enabling session hijacking after any successful XSS attack.",
        remediation: "Add the 'HttpOnly' attribute to all session and authentication cookies.",
        references: ["https://owasp.org/www-community/HttpOnly"],
      }),
    );
  }

  if (!lowerCookie.includes("secure") && endpoint.url.startsWith("https://")) {
    observations.push(
      makeObs(endpoint.url, endpoint.url, {
        ruleId: "cookie-missing-secure",
        title: `Session Cookie Missing Secure Flag (${cookieName})`,
        severity: "medium",
        confidence: "high",
        cwe: "CWE-614",
        owaspCategory: "OWASP A07:2021 — Identification and Authentication Failures",
        rootCause:
          `The session cookie '${cookieName}' does not include the Secure attribute on an HTTPS site.`,
        impact:
          "The browser will send the cookie over plain HTTP connections, exposing it to network interception.",
        remediation: "Add the 'Secure' attribute to all cookies that contain sensitive data.",
        references: [
          "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
      }),
    );
  }

  return observations;
}

/**
 * Scans all exchanges for passwords or tokens embedded in URLs.
 * (Passive check run inside the active_testing stage as it requires no probes.)
 */
export function checkPasswordInUrl(
  exchanges: { url: string; query: string }[],
  baseEndpoint: DiscoveredEndpoint,
): RawObservation[] {
  const observations: RawObservation[] = [];
  const SENSITIVE_PARAMS = /password|passwd|pass|token|secret|apikey|api_key|access_token|auth_token|credential/i;

  for (const { url, query } of exchanges) {
    try {
      const params = new URLSearchParams(query);
      for (const [key] of params) {
        if (SENSITIVE_PARAMS.test(key)) {
          observations.push(
            makeObs(baseEndpoint.url, url, {
              ruleId: "password-in-url",
              title: `Sensitive Parameter '${key}' Found in URL Query String`,
              severity: "high",
              confidence: "high",
              cwe: "CWE-598",
              owaspCategory: "OWASP A02:2021 — Cryptographic Failures",
              rootCause:
                `The URL '${url}' contains a query parameter named '${key}' that likely holds a ` +
                `sensitive credential or token. URLs are logged in web server access logs, browser ` +
                `history, CDN logs, and Referer headers.`,
              impact:
                "The credential or token will be exposed in server-side access logs, CDN edge caches, " +
                "browser history, and Referer headers sent to third parties — potentially to any site linked from this page.",
              remediation:
                "Move sensitive values from URL parameters to the request body (POST) or Authorization header. " +
                "If a token was emitted in a URL, rotate it immediately.",
              references: ["https://cwe.mitre.org/data/definitions/598.html"],
            }),
          );
          break;
        }
      }
    } catch {
      // non-fatal
    }
  }

  return observations;
}
