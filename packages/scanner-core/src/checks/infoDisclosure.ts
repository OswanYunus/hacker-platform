import type { HttpExchange, RawObservation } from "../types.js";

const STACK_TRACE_PATTERNS: Array<{ pattern: RegExp; tech: string }> = [
  { pattern: /at [\w.$]+\s*\(.*:\d+:\d+\)/, tech: "Node.js" },
  { pattern: /Traceback \(most recent call last\)/, tech: "Python" },
  { pattern: /#\d+\s+[\w\\]+->[\w]+\(\)/, tech: "PHP" },
  { pattern: /System\.\w+Exception/, tech: ".NET" },
  { pattern: /org\.springframework|java\.lang\.\w+Exception/, tech: "Java/Spring" },
  { pattern: /ActiveRecord::\w+|app\/controllers\/.*\.rb:\d+/, tech: "Ruby on Rails" },
];

const DEBUG_MARKERS = [
  /whoops/i,
  /django.*debug.*true/i,
  /werkzeug/i,
  /x-debug-token/i,
  /"debug"\s*:\s*true/i,
];

export function checkInfoDisclosure(exchange: HttpExchange): RawObservation[] {
  const observations: RawObservation[] = [];
  const h = lowerKeys(exchange.response.headers);
  const body = exchange.response.body ?? exchange.response.bodyPreview ?? "";

  const bannerHeaders = ["server", "x-powered-by", "x-aspnet-version", "x-runtime"];
  for (const header of bannerHeaders) {
    const value = h[header];
    if (value && /\d/.test(value)) {
      // Only flag when a version number is present — a bare "nginx" is far
      // less actionable than "nginx/1.18.0", which maps directly to known CVEs.
      observations.push(
        makeObservation(exchange, {
          ruleId: `version-disclosure-${header}`,
          title: `Server software version disclosed via ${header} header`,
          severity: "low",
          confidence: "high",
          cwe: "CWE-200",
          owaspCategory: "WSTG-INFO-02",
          rootCause: `The ${header} response header includes a specific version string: "${value}".`,
          impact: "An attacker can target known vulnerabilities for this exact software version without additional fingerprinting.",
          remediation: `Suppress or generalize the ${header} header at the server/proxy level.`,
          detail: `${header}: ${value}`,
        }),
      );
    }
  }

  for (const { pattern, tech } of STACK_TRACE_PATTERNS) {
    if (pattern.test(body)) {
      observations.push(
        makeObservation(exchange, {
          ruleId: "stack-trace-disclosure",
          title: `Stack trace disclosed in response (${tech})`,
          severity: "medium",
          confidence: "high",
          cwe: "CWE-209",
          owaspCategory: "WSTG-ERRH-01",
          rootCause: `The response body contains what appears to be a ${tech} stack trace, suggesting unhandled exceptions are rendered directly to clients.`,
          impact: "Stack traces can reveal file paths, internal class/function names, library versions, and sometimes query fragments, aiding further attack.",
          remediation: "Return generic error responses to clients and log detailed exceptions server-side only.",
          detail: "Pattern match against response body (see evidence for context).",
        }),
      );
      break; // one is enough signal per response
    }
  }

  for (const marker of DEBUG_MARKERS) {
    if (marker.test(body) || marker.test(JSON.stringify(h))) {
      observations.push(
        makeObservation(exchange, {
          ruleId: "debug-mode-indicator",
          title: "Application appears to be running with debug mode enabled",
          severity: "high",
          confidence: "medium",
          cwe: "CWE-489",
          owaspCategory: "WSTG-CONF-05",
          rootCause: "Response content matches a known debug/development-mode signature.",
          impact: "Debug modes commonly expose source code, environment variables, request internals, or an interactive console to any visitor.",
          remediation: "Disable debug/development mode before deploying to any environment reachable by untrusted users.",
          detail: `Matched pattern: ${marker}`,
        }),
      );
      break;
    }
  }

  return observations;
}

/** Checks a set of well-known sensitive paths that were requested during
 * discovery (e.g. /.git/config, /.env). Verifies response content to prevent
 * SPA soft-404 false positives (where Nginx returns 200 OK with index.html). */
export function checkExposedFile(exchange: HttpExchange): RawObservation[] {
  const url = new URL(exchange.request.url);
  const path = url.pathname.toLowerCase();
  if (exchange.response.status >= 400) return [];

  const headers = lowerKeys(exchange.response.headers);
  const contentType = (headers["content-type"] ?? "").toLowerCase();
  const rawBody = (exchange.response.body ?? exchange.response.bodyPreview ?? "").trim();

  // If the server returns HTML (SPA soft-404 fallback like try_files $uri /index.html),
  // sensitive non-HTML files (.env, .git, .json, .bak) are NOT actually exposed.
  const isHtml =
    contentType.includes("text/html") ||
    /^<!doctype html/i.test(rawBody) ||
    /^<html[\s>]/i.test(rawBody);

  const sensitivePatterns: Array<{
    match: RegExp;
    title: string;
    severity: RawObservation["severity"];
    verifyContent: (body: string, isHtmlDoc: boolean) => boolean;
  }> = [
    {
      match: /\/\.git\/head$/,
      title: "Exposed .git repository metadata",
      severity: "critical",
      verifyContent: (b, html) => !html && (/^ref:\s*refs\//i.test(b) || /^[0-9a-f]{40}/i.test(b)),
    },
    {
      match: /\/\.git\/config$/,
      title: "Exposed .git repository metadata",
      severity: "critical",
      verifyContent: (b, html) => !html && (b.includes("[core]") || b.includes("repositoryformatversion")),
    },
    {
      match: /\/\.env$/,
      title: "Exposed .env environment file",
      severity: "critical",
      verifyContent: (b, html) => !html && /^[A-Z0-9_]{2,}\s*=/m.test(b),
    },
    {
      match: /\/\.aws\/credentials$/,
      title: "Exposed AWS credentials file",
      severity: "critical",
      verifyContent: (b, html) => !html && (b.includes("[default]") || /aws_access_key_id/i.test(b)),
    },
    {
      match: /\/(wp-config\.php\.bak|config\.php\.bak|web\.config\.bak)$/,
      title: "Exposed backup configuration file",
      severity: "high",
      verifyContent: (b, html) =>
        !html && (/<\?php/i.test(b) || /<configuration>/i.test(b) || /DB_PASSWORD|DB_NAME/i.test(b)),
    },
    {
      match: /\/\.ds_store$/,
      title: "Exposed .DS_Store (reveals directory listing)",
      severity: "low",
      verifyContent: (b, html) => !html && (b.includes("Bud1") || !b.toLowerCase().includes("<html")),
    },
    {
      match: /\/swagger\.json$|\/openapi\.json$/,
      title: "Exposed OpenAPI/Swagger definition",
      severity: "info",
      verifyContent: (b, html) =>
        !html && (b.includes('"openapi"') || b.includes('"swagger"') || b.includes('"paths"')),
    },
  ];

  const observations: RawObservation[] = [];
  for (const { match, title, severity, verifyContent } of sensitivePatterns) {
    if (match.test(path) && verifyContent(rawBody, isHtml)) {
      observations.push(
        makeObservation(exchange, {
          ruleId: `exposed-file-${match.source.slice(0, 20)}`,
          title,
          severity,
          confidence: "high",
          cwe: "CWE-538",
          owaspCategory: "WSTG-CONF-04",
          rootCause: `A request to ${path} returned HTTP ${exchange.response.status} with genuine matching file content rather than an error or SPA fallback.`,
          impact:
            severity === "info"
              ? "Aids accurate API testing; not itself a weakness."
              : "The file contains secrets, credentials, or source code that should never be publicly reachable.",
          remediation:
            "Remove the file from the web root, or add a server rule to deny access to dotfiles and backup extensions.",
        }),
      );
    }
  }
  return observations;
}

function lowerKeys(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = v;
  return out;
}

function makeObservation(
  exchange: HttpExchange,
  fields: Omit<RawObservation, "affectedEndpoint" | "evidence" | "verification" | "firstSeenStage" | "module" | "references" | "reproduction"> & { detail?: string },
): RawObservation {
  const { detail, ...rest } = fields;
  return {
    ...rest,
    affectedEndpoint: exchange.request.url,
    references: ["https://owasp.org/www-project-web-security-testing-guide/"],
    reproduction: `Request ${exchange.request.method} ${exchange.request.url} and review the response.`,
    evidence: [{ description: detail ?? "See response evidence", exchangeId: exchange.id, detail }],
    verification: "confirmed",
    firstSeenStage: "passive_analysis",
    module: "configuration",
  };
}
