import * as cheerio from "cheerio";
import type { HttpExchange, RawObservation } from "../types.js";

type PolicyKind = "privacy" | "terms";

const POLICY_TERMS: Record<PolicyKind, RegExp> = {
  privacy: /privacy|data[- ]protection|personal[- ]data/i,
  terms: /terms|conditions|acceptable[- ]use|user[- ]agreement/i,
};

const POLICY_CONTENT: Record<PolicyKind, RegExp> = {
  privacy: /privacy (policy|notice)|data protection notice|personal data/i,
  terms: /terms (of (service|use)|and conditions)|acceptable use|user agreement/i,
};

const STAGE = "passive_analysis" as const;

/** Reviews only documents fetched inside the configured scan scope. It never
 * submits forms or treats a missing page as a legal-compliance conclusion. */
export function reviewPublicDocuments(
  exchanges: HttpExchange[],
  targetBaseUrls: string[],
): RawObservation[] {
  const html = exchanges.filter((exchange) =>
    (exchange.response.headers["content-type"] ?? "").toLowerCase().includes("html") &&
    Boolean(exchange.response.body),
  );
  const observations: RawObservation[] = [];

  for (const origin of new Set(targetBaseUrls.map((target) => new URL(target).origin))) {
    const sitePages = html.filter((exchange) => safeOrigin(exchange.request.url) === origin);
    const links = new Map<PolicyKind, Set<string>>([
      ["privacy", new Set()],
      ["terms", new Set()],
    ]);

    for (const page of sitePages) {
      const $ = cheerio.load(page.response.body ?? "");
      $("a[href]").each((_, element) => {
        const href = $(element).attr("href");
        const label = `${$(element).text()} ${href ?? ""}`;
        if (!href) return;
        for (const kind of ["privacy", "terms"] as const) {
          if (!POLICY_TERMS[kind].test(label)) continue;
          try {
            const url = new URL(href, page.request.url);
            if (url.origin === origin && (url.protocol === "https:" || url.protocol === "http:")) {
              links.get(kind)!.add(stripFragment(url.toString()));
            }
          } catch {
            // Ignore malformed or non-URL links.
          }
        }
      });
    }

    for (const kind of ["privacy", "terms"] as const) {
      const discovered = exchanges.find((exchange) => {
        if (safeOrigin(exchange.request.url) !== origin || exchange.response.status < 200 || exchange.response.status >= 300) return false;
        const url = exchange.request.url.toLowerCase();
        const pathLooksRelevant = POLICY_TERMS[kind].test(new URL(url).pathname);
        const contentLooksRelevant = POLICY_CONTENT[kind].test(exchange.response.body ?? "");
        const linked = links.get(kind)!.has(stripFragment(exchange.request.url));
        return Boolean((pathLooksRelevant || linked) && contentLooksRelevant) || Boolean(contentLooksRelevant && pathLooksRelevant);
      });

      const title = kind === "privacy" ? "Public privacy notice" : "Public terms of use";
      const found = Boolean(discovered);
      observations.push({
        ruleId: found ? `public-${kind}-document-found` : `public-${kind}-document-not-discovered`,
        title: found ? `${title} discovered` : `${title} not discovered in scanned pages`,
        severity: "info",
        confidence: found ? "high" : "low",
        owaspCategory: "Governance and transparency",
        affectedEndpoint: discovered?.request.url ?? origin,
        rootCause: found
          ? `A publicly reachable ${kind === "privacy" ? "privacy notice" : "terms document"} was linked or found at ${discovered!.request.url}.`
          : `The scan did not find a matching public ${kind === "privacy" ? "privacy notice" : "terms document"} among the pages and common document paths it could reach. This does not prove that no document exists.`,
        impact: found
          ? "A public document gives visitors a place to review the site's stated policies. This automated check does not assess legal sufficiency."
          : "Visitors and reviewers may have difficulty locating the site's stated policies. Legal requirements depend on the service and jurisdiction.",
        remediation: found
          ? "Review the document manually for accuracy, ownership, and coverage. This scan checks availability only, not legal compliance."
          : `If the site publishes a ${kind === "privacy" ? "privacy notice" : "terms of use"}, link it from a public page and keep it reachable without an account.`,
        references: ["https://owasp.org/www-project-web-security-testing-guide/"],
        verification: "unverified",
        firstSeenStage: STAGE,
        module: "governance",
        reproduction: `Open ${discovered?.request.url ?? `${origin}/(common ${kind} document paths)`} and review the public content.`,
        evidence: [{
          description: found ? "Public policy document response" : "Policy document discovery result",
          detail: discovered ? `HTTP ${discovered.response.status} at ${discovered.request.url}` : `Reviewed ${sitePages.length} reachable HTML page(s) and common document paths.`,
        }],
      });
    }

    observations.push(...reviewPasswordForms(sitePages, origin));

    const apiSpec = exchanges.find((exchange) => {
      if (safeOrigin(exchange.request.url) !== origin || exchange.response.status < 200 || exchange.response.status >= 300) return false;
      const path = new URL(exchange.request.url).pathname.toLowerCase();
      const body = exchange.response.body ?? "";
      return /openapi|swagger|api-docs|v3\/api-docs/.test(path) &&
        (/"openapi"\s*:|"swagger"\s*:|openapi:\s*3\./i.test(body));
    });
    if (apiSpec) {
      observations.push({
        ruleId: "public-api-specification-discovered",
        title: "Public API specification discovered",
        severity: "info",
        confidence: "high",
        owaspCategory: "API security",
        affectedEndpoint: apiSpec.request.url,
        rootCause: `A machine-readable API specification was publicly reachable at ${apiSpec.request.url}.`,
        impact: "An API specification can help reviewers map routes and authentication expectations. Public availability is not a vulnerability by itself.",
        remediation: "Confirm the specification is intended to be public, contains no secrets or internal hostnames, and accurately describes authentication and authorization requirements.",
        references: ["https://owasp.org/www-project-api-security/"],
        verification: "unverified",
        firstSeenStage: STAGE,
        module: "governance",
        reproduction: `Review ${apiSpec.request.url} for unintended internal routes or sensitive examples.`,
        evidence: [{ description: "Machine-readable API specification response", detail: `HTTP ${apiSpec.response.status} at ${apiSpec.request.url}` }],
      });
    }

    const securityTxt = exchanges.find((exchange) => {
      const path = safePath(exchange.request.url);
      return safeOrigin(exchange.request.url) === origin &&
        (path === "/.well-known/security.txt" || path === "/security.txt") &&
        exchange.response.status >= 200 && exchange.response.status < 300 &&
        /^contact\s*:/im.test(exchange.response.body ?? "");
    });
    observations.push({
      ruleId: securityTxt ? "public-security-contact-found" : "public-security-contact-not-discovered",
      title: securityTxt ? "Public security reporting contact discovered" : "No security.txt contact discovered",
      severity: "info",
      confidence: securityTxt ? "high" : "low",
      owaspCategory: "Governance and transparency",
      affectedEndpoint: securityTxt?.request.url ?? origin,
      rootCause: securityTxt
        ? `A security.txt file with a Contact field is reachable at ${securityTxt.request.url}.`
        : "The scan did not find a reachable security.txt file with a Contact field at the well-known or root path.",
      impact: securityTxt
        ? "A published reporting address can help researchers report security issues to the site owner."
        : "Researchers may not find a clear, machine-readable route to report security issues.",
      remediation: securityTxt
        ? "Confirm the contact route is monitored and the file reflects current disclosure instructions."
        : "Consider publishing a security.txt file with a monitored Contact address and disclosure policy.",
      references: ["https://www.rfc-editor.org/rfc/rfc9116"],
      verification: "unverified",
      firstSeenStage: STAGE,
      module: "governance",
      reproduction: `Check ${origin}/.well-known/security.txt and ${origin}/security.txt.`,
      evidence: [{
        description: securityTxt ? "security.txt includes a Contact field" : "No reachable security.txt Contact field found",
        detail: securityTxt ? `HTTP ${securityTxt.response.status} at ${securityTxt.request.url}` : "Both well-known and root paths were checked when allowed by scope.",
      }],
    });
  }

  return observations;
}

function reviewPasswordForms(pages: HttpExchange[], origin: string): RawObservation[] {
  const findings: RawObservation[] = [];
  for (const page of pages) {
    const $ = cheerio.load(page.response.body ?? "");
    $("form").each((formIndex, form) => {
      const passwordFields = $(form).find('input[type="password"]');
      if (passwordFields.length === 0) return;
      const action = $(form).attr("action") || page.request.url;
      const endpoint = new URL(action, page.request.url);
      if (endpoint.origin !== origin) return;

      const concerns: string[] = [];
      passwordFields.each((_, field) => {
        const minLength = Number($(field).attr("minlength") ?? 0);
        const pattern = $(field).attr("pattern") ?? "";
        if (minLength > 0 && minLength < 8) concerns.push("the field advertises a minimum length below 8");
        if (minLength === 0 && !pattern) concerns.push("the field publishes no minimum length or pattern");
        if (!pattern || !/(\[\^|\\W|\\D)/i.test(pattern)) concerns.push("the special-character requirement is not clear in the visible pattern");
      });
      if (concerns.length === 0) return;

      findings.push({
        ruleId: "password-policy-not-discoverable-in-form",
        title: "Password requirements are not clear in the public form",
        severity: "info",
        confidence: "low",
        cwe: "CWE-521",
        owaspCategory: "OWASP A07:2021 — Identification and Authentication Failures",
        affectedEndpoint: page.request.url,
        rootCause: `The password field in form ${formIndex + 1} ${Array.from(new Set(concerns)).join("; ")}. The server-side policy cannot be confirmed from the page alone.`,
        impact: "Visitors may not know the account password requirements, and browser-side constraints do not prove that the server enforces the same policy.",
        remediation: "Document password rules beside the field and enforce them on the server. Verify policy with an owner-provided test account and written authorization; do not guess passwords against real accounts.",
        references: ["https://owasp.org/www-project-authentication-cheat-sheet/"],
        verification: "unverified",
        firstSeenStage: STAGE,
        module: "authentication",
        reproduction: `Open ${page.request.url} and inspect the password input's minlength and pattern attributes.`,
        evidence: [{ description: "Public form password-policy signals", detail: Array.from(new Set(concerns)).join("; ") }],
      });
    });
  }
  return findings;
}

function safeOrigin(value: string): string | null {
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

function safePath(value: string): string | null {
  try {
    return new URL(value).pathname;
  } catch {
    return null;
  }
}

function stripFragment(value: string): string {
  const url = new URL(value);
  url.hash = "";
  return url.toString();
}
