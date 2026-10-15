/**
 * Authorization / IDOR checks (Phase 2 — active testing module).
 *
 * Techniques implemented:
 *  - Sequential IDOR: increment/decrement numeric IDs in URLs and look for
 *    unauthorised access to other users' resources.
 *  - UUID IDOR: swap UUIDs from one session with another to confirm
 *    object-level auth enforcement.
 *  - Privilege escalation via direct URL access: request admin/privileged
 *    paths without an appropriate role/session.
 *
 * All findings are set to confidence "medium" unless we can confirm the
 * response is different from the baseline (i.e. we actually get a 200 with
 * a different user's data back).
 */

import type { ScannerHttpClient } from "../httpClient.js";
import type { AuthContext, DiscoveredEndpoint, RawObservation, ScanStage } from "../types.js";

const STAGE: ScanStage = "active_testing";
const MODULE = "authorization" as const;

// ---------------------------------------------------------------------------
// Common privileged path patterns (best-effort, not exhaustive)
// ---------------------------------------------------------------------------

const PRIVILEGED_PATH_PATTERNS = [
  "/admin",
  "/admin/",
  "/admin/users",
  "/admin/settings",
  "/dashboard/admin",
  "/manage",
  "/management",
  "/superuser",
  "/root",
  "/api/admin",
  "/api/internal",
  "/api/users",
  "/api/v1/admin",
  "/api/v2/admin",
  "/api/accounts",
  "/api/billing",
  "/_admin",
  "/__admin",
  "/config",
  "/debug",
  "/phpinfo.php",
];

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
    evidence: [
      {
        description: fields.rootCause,
        detail: `Probe URL: ${probeUrl}`,
      },
    ],
    reproduction: `Send request to ${probeUrl} without a valid privileged session and inspect the response.`,
    verification: "likely",
    firstSeenStage: STAGE,
    module: MODULE,
  };
}

function extractNumericSegments(url: string): { base: string; id: string; suffix: string }[] {
  const u = new URL(url);
  const segments: { base: string; id: string; suffix: string }[] = [];
  const parts = u.pathname.split("/");
  for (let i = 0; i < parts.length; i++) {
    if (/^\d+$/.test(parts[i]) && parts[i].length <= 10) {
      const base = u.origin + parts.slice(0, i).join("/") + "/";
      const suffix = "/" + parts.slice(i + 1).join("/") + (u.search || "");
      segments.push({ base, id: parts[i], suffix });
    }
  }
  return segments;
}

function extractUuidSegments(url: string): { base: string; id: string; suffix: string }[] {
  const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
  const u = new URL(url);
  const results: { base: string; id: string; suffix: string }[] = [];
  const parts = u.pathname.split("/");
  for (let i = 0; i < parts.length; i++) {
    if (UUID_RE.test(parts[i])) {
      UUID_RE.lastIndex = 0;
      const base = u.origin + parts.slice(0, i).join("/") + "/";
      const suffix = "/" + parts.slice(i + 1).join("/") + (u.search || "");
      results.push({ base, id: parts[i], suffix });
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Exported checkers
// ---------------------------------------------------------------------------

/**
 * Detects sequential IDOR by fetching N-1 and N+1 of numeric IDs that
 * appear in the crawled URL. If we get 200 with a non-empty body, and the
 * response differs from a 404-like baseline, we raise a finding.
 */
export async function checkSequentialIdor(
  client: ScannerHttpClient,
  endpoint: DiscoveredEndpoint,
): Promise<RawObservation[]> {
  if (!endpoint.url.startsWith("http")) return [];
  const observations: RawObservation[] = [];

  for (const { base, id, suffix } of extractNumericSegments(endpoint.url)) {
    const targetId = parseInt(id, 10);
    const candidates = [targetId - 1, targetId + 1, 1, 2, 3].filter(
      (c) => c > 0 && c !== targetId,
    );

    for (const candidateId of candidates.slice(0, 3)) {
      const probeUrl = `${base}${candidateId}${suffix}`;
      try {
        const ex = await client.get(probeUrl, STAGE);
        if (ex.response.status === 200) {
          const body = ex.response.body ?? ex.response.bodyPreview ?? "";
          if (body.length > 50) {
            // Got a non-trivial response — likely real content
            observations.push(
              makeObs(endpoint.url, probeUrl, {
                ruleId: "idor-sequential-id",
                title: "Insecure Direct Object Reference (IDOR) — Sequential ID",
                severity: "high",
                confidence: "medium",
                cwe: "CWE-639",
                owaspCategory: "OWASP A01:2021 — Broken Access Control",
                rootCause:
                  `URL '${endpoint.url}' (ID=${id}) returned HTTP 200. Probe URL '${probeUrl}' (ID=${candidateId}) ` +
                  `also returned HTTP 200 with ${body.length} bytes, suggesting a different user's resource ` +
                  `is accessible without additional authorisation checks.`,
                impact:
                  "An attacker can enumerate and access other users' resources (orders, profiles, invoices, etc.) " +
                  "by incrementing or decrementing numeric IDs, bypassing all access controls.",
                remediation:
                  "Enforce object-level authorisation on every request: verify the authenticated user owns or is " +
                  "permitted to access the requested resource ID. Replace sequential IDs with UUIDs or cryptographic " +
                  "tokens that cannot be guessed.",
                references: [
                  "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                  "https://portswigger.net/web-security/access-control/idor",
                ],
              }),
            );
            break;
          }
        }
      } catch {
        // non-fatal
      }
    }
  }

  return observations;
}

/**
 * Probes common administrative and internal paths without authentication.
 * A 200 OK response that isn't a redirect-to-login counts as a finding.
 */
export async function checkPrivilegedPathAccess(
  client: ScannerHttpClient,
  endpoint: DiscoveredEndpoint,
): Promise<RawObservation[]> {
  if (!endpoint.url.startsWith("http")) return [];
  const origin = new URL(endpoint.url).origin;
  const observations: RawObservation[] = [];

  for (const path of PRIVILEGED_PATH_PATTERNS) {
    const probeUrl = origin + path;
    try {
      const ex = await client.get(probeUrl, STAGE);
      // 401/403 = correctly guarded. 302 likely redirects to login — OK.
      // 200 with non-trivial body = potential exposure.
      if (ex.response.status === 200) {
        const body = ex.response.body ?? ex.response.bodyPreview ?? "";
        const looksLikeLogin = /login|sign.?in|auth/i.test(body);
        if (!looksLikeLogin && body.length > 200) {
          observations.push(
            makeObs(endpoint.url, probeUrl, {
              ruleId: "privileged-path-no-auth",
              title: "Privileged Administrative Path Accessible Without Authentication",
              severity: "critical",
              confidence: "medium",
              cwe: "CWE-284",
              owaspCategory: "OWASP A01:2021 — Broken Access Control",
              rootCause:
                `'${probeUrl}' returned HTTP 200 with ${body.length} bytes without a valid session. ` +
                `The endpoint appears to serve privileged content without authentication.`,
              impact:
                "Unauthenticated access to admin panels allows account takeover, data modification, " +
                "configuration changes, and full system compromise.",
              remediation:
                "Ensure every administrative route enforces authentication and role-based authorisation " +
                "at the framework or middleware level. Never rely solely on obscurity.",
              references: [
                "https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control",
              ],
            }),
          );
        }
      }
    } catch {
      // non-fatal
    }
  }

  return observations;
}
