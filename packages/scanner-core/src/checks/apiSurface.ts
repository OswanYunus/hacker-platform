import type { HttpExchange, RawObservation, AuthorizationScope } from "../types.js";
import { validateScope } from "../scope.js";

export interface ApiSpecRoute {
  url: string;
  securityDeclared: boolean;
}

/** Extract only documented GET routes from JSON OpenAPI/Swagger documents.
 * Every returned URL is checked against the operator's authorized scope. */
export function discoverApiSpecGetRoutes(
  exchanges: HttpExchange[],
  scope: AuthorizationScope,
  limit = 120,
): ApiSpecRoute[] {
  const routes = new Map<string, ApiSpecRoute>();
  for (const exchange of exchanges) {
    if (exchange.response.status < 200 || exchange.response.status >= 300) continue;
    const path = safePath(exchange.request.url);
    if (!path || !/(openapi|swagger|api-docs|v\d+\/api-docs)/i.test(path)) continue;

    let spec: any;
    try {
      spec = JSON.parse(exchange.response.body ?? "");
    } catch {
      continue;
    }
    if (!spec || typeof spec.paths !== "object" || !("openapi" in spec || "swagger" in spec)) continue;

    const defaultOrigin = new URL(exchange.request.url).origin;
    const rootServers = Array.isArray(spec.servers) ? spec.servers : [];
    for (const [routePath, pathItem] of Object.entries<any>(spec.paths)) {
      if (!pathItem || typeof pathItem !== "object" || !routePath.startsWith("/")) continue;
      const operation = pathItem.get;
      if (!operation || typeof operation !== "object") continue;

      const security = operation.security ?? pathItem.security ?? spec.security;
      const securityDeclared = Array.isArray(security) && security.length > 0;
      const servers = Array.isArray(operation.servers)
        ? operation.servers
        : Array.isArray(pathItem.servers)
          ? pathItem.servers
          : rootServers;
      const serverUrls = servers.length > 0 ? servers.map((server: any) => server?.url).filter((url: unknown): url is string => typeof url === "string") : [defaultOrigin];

      for (const serverUrl of serverUrls) {
        if (serverUrl.includes("{")) continue; // Server variables need owner-specific values.
        try {
          const base = new URL(serverUrl, exchange.request.url);
          const routeUrl = new URL(routePath.replace(/\{[^/{}]+\}/g, "scan-probe"), base).toString();
          if (!validateScope(routeUrl, scope).inScope) continue;
          routes.set(routeUrl, { url: routeUrl, securityDeclared });
          if (routes.size >= limit) return [...routes.values()];
        } catch {
          // Ignore malformed or templated server entries.
        }
      }
    }
  }
  return [...routes.values()];
}

/** Raise a finding only when a documented protected GET route returns the
 * exact same non-trivial content to the configured test role and anonymously. */
export function compareAnonymousAccess(
  authenticated: HttpExchange,
  anonymous: HttpExchange,
): RawObservation[] {
  const body = normalizeBody(authenticated.response.body ?? "");
  const anonymousBody = normalizeBody(anonymous.response.body ?? "");
  if (
    authenticated.response.status < 200 || authenticated.response.status >= 300 ||
    anonymous.response.status < 200 || anonymous.response.status >= 300 ||
    body.length < 64 || body !== anonymousBody
  ) return [];

  const url = authenticated.request.url;
  return [{
    ruleId: "documented-api-route-anonymous-access",
    title: "Documented protected API route is accessible without authentication",
    severity: "high",
    confidence: "high",
    cwe: "CWE-862",
    owaspCategory: "OWASP API1:2023 — Broken Object Level Authorization",
    affectedEndpoint: url,
    rootCause: `The API specification marks this GET route as protected, but an anonymous request returned the same non-trivial response as the configured test role (${body.length} normalized characters).`,
    impact: "Anonymous visitors may be able to read data or functionality that the API contract expects to require authentication.",
    remediation: "Enforce authentication and authorization on the server for this route. Re-test with separate owner-provided test accounts and confirm anonymous requests receive 401 or 403.",
    references: ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
    verification: "likely",
    firstSeenStage: "active_testing",
    module: "api",
    reproduction: `Send an unauthenticated GET request to ${url} and compare its response with the authorized test-role response.`,
    evidence: [{
      description: "Authenticated and anonymous GET responses matched",
      detail: `Authenticated HTTP ${authenticated.response.status}; anonymous HTTP ${anonymous.response.status}; normalized response length ${body.length}. Response content is not copied into the finding.`,
    }],
  }];
}

function normalizeBody(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function safePath(value: string): string | null {
  try {
    return new URL(value).pathname;
  } catch {
    return null;
  }
}
