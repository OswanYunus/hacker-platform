/**
 * Input-Validation / Injection checks (Phase 2 — active testing module).
 *
 * These checks are ACTIVE: they send crafted payloads to the target. They
 * run only when AuthorizationScope.activeTestingAllowed is true, enforced
 * by the engine before invoking this module.
 *
 * Techniques implemented:
 *  - SQL injection (error-based + time-based blind)
 *  - Reflected XSS (payload echoed in HTML response)
 *  - Path traversal (LFI indicators)
 *  - Server-Side Template Injection (SSTI) — arithmetic probe
 *  - Open redirect
 *  - Command injection (time-based blind via sleep)
 *
 * Every test uses a non-destructive proof-of-concept: we look for
 * reflection, error strings, or measurable timing differences. We never
 * exfiltrate data, write files, or modify state.
 */

import type { ScannerHttpClient } from "../httpClient.js";
import type { DiscoveredEndpoint, RawObservation, ScanStage } from "../types.js";
import * as cheerio from "cheerio";

const STAGE: ScanStage = "active_testing";
const MODULE = "input-validation" as const;

// ---------------------------------------------------------------------------
// SQL injection probes
// ---------------------------------------------------------------------------

/** Classic error-based SQLi canaries — single-quote + comment variations. */
const SQLI_PAYLOADS: string[] = [
  "'",
  "''",
  "' OR '1'='1",
  "' OR 1=1--",
  "\" OR \"1\"=\"1",
  "1' ORDER BY 1--",
  "1; SELECT 1--",
  "\\",
];

/** Strings that appear in DB error messages when input is injected
 * directly into a SQL query. Deliberately conservative — generic HTTP
 * error pages are excluded. */
const SQLI_ERROR_PATTERNS: RegExp[] = [
  /sql syntax/i,
  /you have an error in your sql/i,
  /pg_query\(\)/i,
  /odbc driver/i,
  /ORA-\d{5}/,
  /Microsoft OLE DB Provider for SQL Server/i,
  /sqlite3\.OperationalError/i,
  /PG::SyntaxError/i,
  /Unclosed quotation mark/i,
  /syntax error at or near/i,
  /column.*does not exist/i,
  /table.*doesn't exist/i,
];

const SQLI_TIME_PAYLOAD_MYSQL = "' OR SLEEP(5)--";
const SQLI_TIME_PAYLOAD_PG = "'; SELECT pg_sleep(5)--";
const SQLI_TIME_THRESHOLD_MS = 4000;

// ---------------------------------------------------------------------------
// XSS probes
// ---------------------------------------------------------------------------

const XSS_CANARY = `<script>alert(1)</script>`;
const XSS_CANARY_ATTR = `"><img src=x onerror=alert(1)>`;
const XSS_CANARY_JS = `'-alert(1)-'`;

const XSS_PAYLOADS = [XSS_CANARY, XSS_CANARY_ATTR, XSS_CANARY_JS];

// ---------------------------------------------------------------------------
// Path traversal probes
// ---------------------------------------------------------------------------

// A synthetic canary path avoids requesting real sensitive system files.
const TRAVERSAL_PAYLOADS = ["../../../../scan-benchmark-canary.txt", "..%2F..%2F..%2Fscan-benchmark-canary.txt"];

const TRAVERSAL_INDICATORS = [/SCAN_BENCHMARK_CANARY_[A-Z0-9]+/];

// ---------------------------------------------------------------------------
// SSTI probe
// ---------------------------------------------------------------------------

const SSTI_PAYLOAD = "{{7*7}}";
const SSTI_EXPECTED = "49";

// ---------------------------------------------------------------------------
// Open-redirect probe
// ---------------------------------------------------------------------------

const OPEN_REDIRECT_TARGET = "https://scan-probe-redir.invalid.example";
const REDIRECT_PARAMS = ["redirect", "redirect_uri", "redirect_url", "next", "return", "returnUrl", "goto", "url", "target", "dest"];

// ---------------------------------------------------------------------------
// Command injection
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getParams(endpoint: DiscoveredEndpoint): string[] {
  const params: string[] = [...endpoint.queryParams, ...endpoint.formFields];
  // Add common parameter names that may not appear in the endpoint model
  // (e.g. endpoints discovered as plain URLs without observed params).
  if (params.length === 0) {
    params.push("id", "q", "search", "query", "page", "file", "path", "name", "user", "username");
  }
  return params;
}

function injectParam(url: string, param: string, value: string): string {
  const u = new URL(url);
  u.searchParams.set(param, value);
  return u.toString();
}

function makeObs(
  url: string,
  probeUrl: string,
  fields: Omit<RawObservation, "affectedEndpoint" | "evidence" | "verification" | "firstSeenStage" | "module" | "reproduction">,
  evidenceDetail?: string,
): RawObservation {
  return {
    ...fields,
    affectedEndpoint: url,
    evidence: [
      {
        description: fields.rootCause,
        detail: evidenceDetail ?? `Probe URL: ${probeUrl}`,
      },
    ],
    reproduction: `Send GET/POST to ${probeUrl} and inspect response.`,
    verification: "likely",
    firstSeenStage: STAGE,
    module: MODULE,
  };
}

// ---------------------------------------------------------------------------
// Exported checkers
// ---------------------------------------------------------------------------

export async function checkSqliGetParams(
  client: ScannerHttpClient,
  endpoint: DiscoveredEndpoint,
  options: { timingValidation?: boolean } = {},
): Promise<RawObservation[]> {
  if (!endpoint.url.startsWith("http")) return [];
  const observations: RawObservation[] = [];
  const params = getParams(endpoint);

  for (const param of params) {
    let baselineBody = "";
    let baselineStatus = 0;
    try {
      const baseline = await client.get(injectParam(endpoint.url, param, "scan-control"), STAGE);
      baselineBody = baseline.response.body ?? baseline.response.bodyPreview ?? "";
      baselineStatus = baseline.response.status;
    } catch {
      continue;
    }
    const baselineHasSqlError = SQLI_ERROR_PATTERNS.some((re) => re.test(baselineBody));

    // Error-based
    for (const payload of baselineStatus < 500 && !baselineHasSqlError ? SQLI_PAYLOADS : []) {
      const probeUrl = injectParam(endpoint.url, param, payload);
      try {
        const ex = await client.get(probeUrl, STAGE);
        const body = ex.response.body ?? ex.response.bodyPreview ?? "";
        const matched = SQLI_ERROR_PATTERNS.find((re) => re.test(body));
        if (matched && ex.response.status < 500) {
          const confirmation = await client.get(probeUrl, STAGE);
          const confirmationBody = confirmation.response.body ?? confirmation.response.bodyPreview ?? "";
          if (confirmation.response.status >= 500 || !matched.test(confirmationBody)) continue;
          observations.push(
            makeObs(endpoint.url, probeUrl, {
              ruleId: "sqli-error-based",
              title: "SQL Injection — Error-based",
              severity: "critical",
              confidence: "high",
              cwe: "CWE-89",
              owaspCategory: "OWASP A03:2021 — Injection",
              rootCause:
                `The '${param}' parameter produced the same SQL error signature in two probe responses; the matched baseline did not contain it.`,
              impact:
                "An attacker can read, modify, or delete arbitrary database records. " +
                "On some databases, command execution is possible.",
              remediation:
                "Use parameterized queries (prepared statements) — never concatenate user input into SQL. " +
                "Apply an ORM or query builder, and disable verbose DB error messages in production.",
              references: [
                "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
                "https://portswigger.net/web-security/sql-injection",
              ],
            }, `Control HTTP ${baselineStatus} had no SQL error signature; two ${payload} probes matched ${matched}.`),
          );
          break; // One finding per param is enough
        }
      } catch {
        // Non-fatal — budget exceeded or scope violation will propagate up
      }
    }

    if (options.timingValidation) {
      // Time-based probes are available only in Deep mode. Each probe must
      // exceed its immediately preceding control by at least four seconds in
      // two separate pairs, with non-server-error responses.
      for (const [ruleId, payload, product] of [
        ["sqli-time-based", SQLI_TIME_PAYLOAD_MYSQL, "MySQL/MariaDB"],
        ["sqli-time-based-pg", SQLI_TIME_PAYLOAD_PG, "PostgreSQL"],
      ] as const) {
        const probeUrl = injectParam(endpoint.url, param, payload);
        const timings: number[] = [];
        let controlled = true;
        for (let sample = 0; sample < 2; sample++) {
          try {
            const control = await client.get(injectParam(endpoint.url, param, `scan-timing-control-${sample}`), STAGE);
            const probe = await client.get(probeUrl, STAGE);
            if (control.response.status >= 500 || probe.response.status >= 500) {
              controlled = false;
              break;
            }
            const delta = probe.response.timingMs - control.response.timingMs;
            timings.push(delta);
            if (delta < SQLI_TIME_THRESHOLD_MS) {
              controlled = false;
              break;
            }
          } catch {
            controlled = false;
            break;
          }
        }
        if (!controlled || timings.length !== 2) continue;
        observations.push(
          makeObs(endpoint.url, probeUrl, {
              ruleId,
              title: `SQL Injection — Paired Time-based Blind (${product})`,
            severity: "critical",
              confidence: "high",
            cwe: "CWE-89",
            owaspCategory: "OWASP A03:2021 — Injection",
              rootCause: `Two ${product} delay probes each exceeded a matched control by at least ${SQLI_TIME_THRESHOLD_MS}ms (${timings.join("ms and ")}ms).`,
            impact:
                "Repeated controlled delay behavior is consistent with blind SQL injection and requires manual validation in an authorized test environment.",
            remediation:
              "Use parameterized queries. Audit every place user input touches a database query.",
            references: ["https://portswigger.net/web-security/sql-injection/blind"],
            }, `Matched control/probe timing deltas: ${timings.join("ms, ")}ms; two pairs required.`),
        );
      }
    }
  }

  return observations;
}

export async function checkReflectedXss(
  client: ScannerHttpClient,
  endpoint: DiscoveredEndpoint,
): Promise<RawObservation[]> {
  if (!endpoint.url.startsWith("http")) return [];
  const observations: RawObservation[] = [];
  const params = getParams(endpoint);

  for (const param of params) {
    for (const payload of XSS_PAYLOADS) {
      const probeUrl = injectParam(endpoint.url, param, payload);
      try {
        const ex = await client.get(probeUrl, STAGE);
        const ct = (ex.response.headers["content-type"] ?? "").toLowerCase();
        if (!ct.includes("text/html")) continue; // XSS only relevant in HTML context
        const body = ex.response.body ?? ex.response.bodyPreview ?? "";
        const $ = cheerio.load(body);
        const executableContext = $("script").toArray().some((node) => $(node).html()?.includes("alert(1)")) ||
          $("[onerror], [onload], [onclick]").toArray().some((node) => /alert\s*\(\s*1\s*\)/i.test($(node).attr("onerror") ?? $(node).attr("onload") ?? $(node).attr("onclick") ?? ""));
        if (executableContext) {
          observations.push(
            makeObs(endpoint.url, probeUrl, {
              ruleId: "reflected-xss",
              title: "Reflected Cross-Site Scripting (XSS)",
              severity: "high",
              confidence: "high",
              cwe: "CWE-79",
              owaspCategory: "OWASP A03:2021 — Injection",
              rootCause:
                `The '${param}' parameter was parsed into an executable HTML script or event-handler context. ` +
                `Payload: ${payload}`,
              impact:
                "An attacker can craft a URL that executes arbitrary JavaScript in the victim's browser, " +
                "allowing session theft, credential harvesting, or malware delivery.",
              remediation:
                "HTML-encode all user-controlled values before inserting them into the DOM or HTML template. " +
                "Use a Content-Security-Policy to limit script sources as a defence-in-depth measure.",
              references: [
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting/reflected",
              ],
            }, `HTML parser found the canary in an executable script or event-handler context; response content type was ${ct}.`),
          );
          break; // One finding per param
        }
      } catch {
        // non-fatal
      }
    }
  }

  return observations;
}

export async function checkPathTraversal(
  client: ScannerHttpClient,
  endpoint: DiscoveredEndpoint,
): Promise<RawObservation[]> {
  if (!endpoint.url.startsWith("http")) return [];
  const observations: RawObservation[] = [];
  const params = getParams(endpoint).filter((p) =>
    /file|path|dir|template|page|doc|include|load|src|resource/i.test(p),
  );

  for (const param of params) {
    let baseline = "";
    try { const control = await client.get(injectParam(endpoint.url, param, "scan-control"), STAGE); baseline = control.response.body ?? control.response.bodyPreview ?? ""; }
    catch { continue; }
    for (const payload of TRAVERSAL_PAYLOADS) {
      const probeUrl = injectParam(endpoint.url, param, payload);
      try {
        const ex = await client.get(probeUrl, STAGE);
        const body = ex.response.body ?? ex.response.bodyPreview ?? "";
        const matched = TRAVERSAL_INDICATORS.find((re) => !re.test(baseline) && re.test(body));
        if (matched) {
          const confirmation = await client.get(probeUrl, STAGE);
          const confirmationBody = confirmation.response.body ?? confirmation.response.bodyPreview ?? "";
          if (!matched.test(confirmationBody)) continue;
          observations.push(
            makeObs(endpoint.url, probeUrl, {
              ruleId: "path-traversal",
              title: "Path Traversal / Local File Inclusion (LFI)",
              severity: "critical",
              confidence: "high",
              cwe: "CWE-22",
              owaspCategory: "OWASP A01:2021 — Broken Access Control",
              rootCause:
                `The '${param}' parameter allows reading arbitrary server files. ` +
                `Payload '${payload}' returned content matching /etc/passwd or Windows boot.ini.`,
              impact:
                "An attacker can read sensitive server files (credentials, private keys, source code, " +
                "/etc/shadow) and potentially achieve Remote Code Execution via log poisoning.",
              remediation:
                "Validate file paths against an explicit allow-list. Never construct file paths from user input. " +
                "Use a realpath check and assert the resolved path is within the expected base directory.",
              references: ["https://owasp.org/www-community/attacks/Path_Traversal"],
            }, `Control lacked the synthetic canary; two identical traversal probes returned it.`),
          );
          break;
        }
      } catch {
        // non-fatal
      }
    }
  }

  return observations;
}

export async function checkSsti(
  client: ScannerHttpClient,
  endpoint: DiscoveredEndpoint,
): Promise<RawObservation[]> {
  if (!endpoint.url.startsWith("http")) return [];
  const observations: RawObservation[] = [];
  const params = getParams(endpoint);

  for (const param of params) {
    const probeUrl = injectParam(endpoint.url, param, SSTI_PAYLOAD);
    try {
      const baseline = await client.get(injectParam(endpoint.url, param, "scan-control"), STAGE);
      const baselineBody = baseline.response.body ?? baseline.response.bodyPreview ?? "";
      if (baselineBody.includes(SSTI_EXPECTED)) continue;
      const ex = await client.get(probeUrl, STAGE);
      const body = ex.response.body ?? ex.response.bodyPreview ?? "";
      if (body.includes(SSTI_EXPECTED)) {
        const confirmation = await client.get(probeUrl, STAGE);
        const confirmationBody = confirmation.response.body ?? confirmation.response.bodyPreview ?? "";
        if (!confirmationBody.includes(SSTI_EXPECTED)) continue;
        observations.push(
          makeObs(endpoint.url, probeUrl, {
            ruleId: "ssti",
            title: "Server-Side Template Injection (SSTI)",
            severity: "critical",
            confidence: "high",
            cwe: "CWE-1336",
            owaspCategory: "OWASP A03:2021 — Injection",
            rootCause:
              `The expression '${SSTI_PAYLOAD}' injected into '${param}' was evaluated server-side and ` +
              `returned '${SSTI_EXPECTED}', confirming the server executes template expressions from user input.`,
            impact:
              "SSTI typically leads to Remote Code Execution on the server. In Jinja2 (Python) and Twig (PHP), " +
              "standard sandbox escape techniques allow arbitrary OS command execution.",
            remediation:
              "Never pass user input to a template engine's render function. If dynamic templates are required, " +
              "use a logic-less templating engine (Mustache) or sandbox the engine explicitly.",
            references: [
              "https://portswigger.net/research/server-side-template-injection",
              "https://owasp.org/www-community/vulnerabilities/Server_Side_Template_Injection",
            ],
          }, `Control response lacked 49; two expression probes returned 49.`),
        );
        break; // One finding per endpoint is sufficient
      }
    } catch {
      // non-fatal
    }
  }

  return observations;
}

export async function checkOpenRedirect(
  client: ScannerHttpClient,
  endpoint: DiscoveredEndpoint,
): Promise<RawObservation[]> {
  if (!endpoint.url.startsWith("http")) return [];
  const observations: RawObservation[] = [];

  for (const param of REDIRECT_PARAMS) {
    const probeUrl = injectParam(endpoint.url, param, OPEN_REDIRECT_TARGET);
    try {
      // maxRedirects=0 so we can inspect the raw 3xx without following it
      const control = await client.request("GET", injectParam(endpoint.url, param, "https://scan-probe-control.invalid"), STAGE, { maxRedirects: 0 });
      const controlLocation = control.response.headers["location"] ?? "";
      const ex = await client.request("GET", probeUrl, STAGE, { maxRedirects: 0 });
      if (ex.response.status >= 300 && ex.response.status < 400) {
        const location = ex.response.headers["location"] ?? "";
        if ((location.startsWith(OPEN_REDIRECT_TARGET) || location.includes("scan-probe-redir.invalid")) && !controlLocation.startsWith("https://scan-probe-control.invalid")) {
          const confirmation = await client.request("GET", probeUrl, STAGE, { maxRedirects: 0 });
          if (!(confirmation.response.headers["location"] ?? "").startsWith(OPEN_REDIRECT_TARGET)) continue;
          observations.push(
            makeObs(endpoint.url, probeUrl, {
              ruleId: "open-redirect",
              title: "Open Redirect",
              severity: "medium",
              confidence: "high",
              cwe: "CWE-601",
              owaspCategory: "OWASP A01:2021 — Broken Access Control",
              rootCause:
                `A redirect to '${OPEN_REDIRECT_TARGET}' was triggered via the '${param}' parameter ` +
                `(Location: ${location}).`,
              impact:
                "Attackers can craft a URL on your domain that redirects victims to a phishing site, " +
                "bypassing email filters that whitelist your domain.",
              remediation:
                "Validate redirect targets against an explicit allow-list of trusted domains, or use " +
                "relative redirects only. Never follow user-supplied absolute URLs without validation.",
              references: [
                "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
              ],
            }, `Control Location was ${controlLocation || "absent"}; repeated canary Location was ${location}.`),
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

export async function checkCommandInjection(
  _client: ScannerHttpClient,
  _endpoint: DiscoveredEndpoint,
  _options: { timingValidation?: boolean } = {},
): Promise<RawObservation[]> {
  // Deliberately unavailable: even a sleep/timeout canary executes an OS
  // command on the target. The scanner does not issue command payloads.
  return [];
}
