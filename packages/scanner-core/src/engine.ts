import { ScannerHttpClient, BudgetExceededError, RequestCancelledError, ScopeViolationError } from "./httpClient.js";
import { crawl } from "./crawler.js";
import { checkSecurityHeaders, checkCorsReflection } from "./checks/headers.js";
import { checkCookies } from "./checks/cookies.js";
import { checkInfoDisclosure, checkExposedFile } from "./checks/infoDisclosure.js";
import { checkUnsafeCaching, checkClientSideSecrets } from "./checks/cachingAndSecrets.js";
import {
  checkSqliGetParams,
  checkReflectedXss,
  checkPathTraversal,
  checkSsti,
  checkOpenRedirect,
  checkCommandInjection,
} from "./checks/injection.js";
import {
  checkSequentialIdor,
  checkPrivilegedPathAccess,
} from "./checks/authorization.js";
import {
  checkSessionTokenEntropy,
  checkPasswordInUrl,
} from "./checks/authentication.js";
import { correlateFindings } from "./correlation.js";
import { prioritize } from "./riskScoring.js";
import { validateScope } from "./scope.js";
import { detectTechnologies } from "./techDetection.js";
import { reviewPublicDocuments } from "./checks/governance.js";
import { compareAnonymousAccess, discoverApiSpecGetRoutes, type ApiSpecRoute } from "./checks/apiSurface.js";
import { effectiveProfile, type ScanCapabilityReport } from "./profiles.js";
import type { HttpExchange, RawObservation, ScanEvent, ScanResult, ScanRunConfig, ScanStage } from "./types.js";

/** Common sensitive paths probed during discovery. Passive from the
 * scanner's point of view: it only observes how the server already
 * responds to these well-known paths, it does not attempt to exploit
 * anything found there. */
const SENSITIVE_PATH_PROBES = [
  "/.git/config",
  "/.git/HEAD",
  "/.env",
  "/.aws/credentials",
  "/wp-config.php.bak",
  "/config.php.bak",
  "/.DS_Store",
  "/swagger.json",
  "/openapi.json",
  "/openapi.yaml",
  "/api/openapi.json",
  "/api-docs",
  "/swagger/v1/swagger.json",
  "/v3/api-docs",
  "/.well-known/security.txt",
  "/security.txt",
  "/privacy-policy",
  "/privacy",
  "/privacy-notice",
  "/terms-of-service",
  "/terms-and-conditions",
  "/terms",
  "/acceptable-use",
  "/robots.txt",
  "/sitemap.xml",
];

export function discoveryProbePaths(activeTestingAllowed: boolean): string[] {
  return activeTestingAllowed ? [...SENSITIVE_PATH_PROBES] : [];
}

export class ScanCancelledError extends Error {}

export interface EngineHandle {
  cancel: () => void;
}

export async function runScan(
  config: ScanRunConfig,
  emit: (event: ScanEvent) => void,
  handle?: EngineHandle,
): Promise<ScanResult> {
  const startedAt = new Date().toISOString();
  const stageDurations: Partial<Record<ScanStage, number>> = {};
  let cancelled = false;
  const capabilities = effectiveProfile(config.profile, config.scope.activeTestingAllowed, config.scope);
  const executionScope = { ...config.scope, maxTotalRequests: capabilities.maxRequests, maxScanDurationSeconds: capabilities.maxDurationSeconds };

  const checkCancelled = () => {
    if (cancelled) throw new ScanCancelledError();
  };

  const allExchanges: HttpExchange[] = [];
  let apiRoutesAttempted = 0;
  const client = new ScannerHttpClient({
    scope: executionScope,
    auth: config.authContext,
    requestTimeoutMs: Math.min(15_000, executionScope.maxScanDurationSeconds * 1000),
    onExchange: (ex) => {
      allExchanges.push(ex);
      emit({ type: "request_issued", method: ex.request.method, url: ex.request.url, stage: ex.stage, at: new Date().toISOString() });
    },
  });
  if (handle) handle.cancel = () => {
    cancelled = true;
    client.cancel();
  };

  const runStage = async <T>(stage: ScanStage, fn: () => Promise<T>): Promise<T> => {
    checkCancelled();
    emit({ type: "stage_started", stage, at: new Date().toISOString() });
    const t0 = Date.now();
    try {
      const result = await fn();
      stageDurations[stage] = Date.now() - t0;
      emit({ type: "stage_completed", stage, at: new Date().toISOString(), durationMs: stageDurations[stage] });
      return result;
    } catch (e) {
      stageDurations[stage] = Date.now() - t0;
      throw e;
    }
  };

  try {
    const capabilityReport: ScanCapabilityReport = {
      profile: config.profile,
      effectiveBudgets: { maxPages: capabilities.maxPages, maxDepth: capabilities.maxDepth, maxRequests: capabilities.maxRequests, maxDurationSeconds: capabilities.maxDurationSeconds },
      capabilities: {
        crawl: { status: "ran" },
        passiveConfigurationChecks: { status: "ran" },
        fixedPathDiscovery: capabilities.fixedPathDiscovery ? { status: "ran" } : { status: "skipped", reason: config.scope.activeTestingAllowed ? "Disabled by selected profile." : "Active testing is disabled by authorization scope." },
        apiSpecRouteRequests: capabilities.apiRouteRequests ? { status: "ran" } : { status: "skipped", reason: config.scope.activeTestingAllowed ? "Disabled by selected profile." : "Active testing is disabled by authorization scope." },
        injectionAndAccessChecks: capabilities.activeChecks ? { status: "ran" } : { status: "skipped", reason: config.scope.activeTestingAllowed ? "Disabled by selected profile." : "Active testing is disabled by authorization scope." },
        authenticatedApiComparison: capabilities.authComparison && !!config.authContext ? { status: "ran" } : { status: "skipped", reason: !config.scope.activeTestingAllowed ? "Active testing is disabled by authorization scope." : !config.authContext ? "No test identity configured." : "Disabled by selected profile." },
        pairedTimingValidation: capabilities.pairedTimingValidation ? { status: "ran" } : { status: "skipped", reason: config.profile !== "deep" ? "Available only in Deep profile." : "Active testing is disabled by authorization scope." },
        commandInjectionValidation: { status: "unavailable", reason: "No safe non-command-executing live validator is implemented; command payloads are never sent." },
        multiIdentityObjectAuthorization: { status: "unavailable", reason: "Current configuration supports one test identity and anonymous comparison only." },
        javascriptRuntimeDiscovery: { status: "unavailable", reason: "No browser runtime is configured." },
        dependencyVulnerabilityAnalysis: { status: "unavailable", reason: "No dependency inventory or advisory database is configured." },
        adaptiveFollowUp: { status: "unavailable", reason: "No adaptive planner is configured; checks are deterministic." },
        independentVerification: { status: "unavailable", reason: "Current validators provide reproducible evidence but no independent verifier." },
      },
      notAssessed: ["multi-identity object access control", "JavaScript runtime behavior", "dependency vulnerabilities", "adaptive follow-up investigation", "independent verification"],
    };
    // 1. Scope validation
    await runStage("scope_validation", async () => {
      for (const base of config.targetBaseUrls) {
        const v = validateScope(base, config.scope);
        if (!v.inScope) {
          throw new Error(`Target ${base} is not covered by the project's authorized scope: ${v.reason}`);
        }
      }
    });

    // 2. Target discovery — confirm reachability of each declared target
    await runStage("target_discovery", async () => {
      for (const base of config.targetBaseUrls) {
        await client.get(base, "target_discovery");
      }
    });

    // 3 + 4. Crawling + endpoint discovery
    const limits = capabilities;
    const crawlResult = await runStage("crawling", () =>
      crawl(client, {
        startUrls: config.targetBaseUrls,
        scope: executionScope,
        maxPages: limits.maxPages,
        maxDepth: limits.maxDepth,
        onPageCrawled: (ep) => emit({ type: "endpoint_discovered", endpoint: ep, at: new Date().toISOString() }),
      }),
    );

    const authenticatedApiRoutes: Array<{ route: ApiSpecRoute; exchange: HttpExchange }> = [];
    await runStage("endpoint_discovery", async () => {
      // Fixed-path enumeration sends requests to routes that were not
      // discovered through ordinary crawling. Treat it as active testing.
      const hosts = new Set(config.targetBaseUrls.map((u) => new URL(u).origin));
      const discoveryPaths = discoveryProbePaths(capabilities.fixedPathDiscovery);
      if (discoveryPaths.length === 0) {
        emit({ type: "scan_log", level: "info", message: "Fixed-path enumeration skipped because active testing is disabled.", at: new Date().toISOString() });
      } else {
        for (const origin of hosts) {
          for (const path of discoveryPaths) {
            const url = origin + path;
            if (!validateScope(url, config.scope).inScope) continue;
            try {
              await client.get(url, "endpoint_discovery");
            } catch (e) {
              if (e instanceof BudgetExceededError) return;
              if (e instanceof ScopeViolationError) continue;
            }
          }
        }
      }

      const apiRoutes = discoverApiSpecGetRoutes(allExchanges, config.scope, limits.maxPages);
      if (!capabilities.apiRouteRequests) {
        emit({
          type: "scan_log",
          level: "info",
          message: `OpenAPI declared ${apiRoutes.length} in-scope GET route(s); route requests and authenticated comparisons skipped because active testing is disabled.`,
          at: new Date().toISOString(),
        });
        return;
      }
      let discovered = 0;
      for (const route of apiRoutes) {
        checkCancelled();
        apiRoutesAttempted++;
        try {
          const exchange = await client.get(route.url, "endpoint_discovery");
          discovered++;
          const parsed = new URL(route.url);
          emit({
            type: "endpoint_discovered",
            endpoint: {
              url: route.url,
              methodsObserved: ["GET"],
              statusCodesObserved: [exchange.response.status],
              queryParams: Array.from(parsed.searchParams.keys()),
              formFields: [],
              requiresAuth: exchange.response.status === 401 || exchange.response.status === 403,
              sourceType: "openapi",
              contentType: exchange.response.headers["content-type"],
            },
            at: new Date().toISOString(),
          });
          if (route.securityDeclared) authenticatedApiRoutes.push({ route, exchange });
        } catch (e) {
          if (e instanceof BudgetExceededError) break;
          if (!(e instanceof ScopeViolationError)) {
            emit({ type: "scan_log", level: "warn", message: `Could not inspect documented GET route ${route.url}: ${(e as Error).message}`, at: new Date().toISOString() });
          }
        }
      }
      emit({ type: "scan_log", level: "info", message: `OpenAPI discovery inspected ${discovered} in-scope GET route(s) from published API specifications.`, at: new Date().toISOString() });
    });

    // 5. Technology identification
    const technologies = await runStage("technology_identification", async () =>
      detectTechnologies(allExchanges),
    );
    for (const t of technologies) emit({ type: "technology_detected", technology: t, at: new Date().toISOString() });

    // 6. Passive analysis
    const rawObservations: RawObservation[] = [];
    await runStage("passive_analysis", async () => {
      rawObservations.push(...reviewPublicDocuments(allExchanges, config.targetBaseUrls));
      for (const ex of allExchanges) {
        rawObservations.push(
          ...checkSecurityHeaders(ex),
          ...checkCookies(ex),
          ...checkInfoDisclosure(ex),
          ...checkExposedFile(ex),
          ...checkUnsafeCaching(ex),
          ...checkClientSideSecrets(ex),
        );
      }
      // CORS reflection probe: one cheap extra request per distinct origin,
      // only if active testing is allowed (it sends a non-default header).
      if (capabilities.activeChecks) {
        for (const base of config.targetBaseUrls) {
          try {
            const probeOrigin = "https://scan-probe.invalid.example";
            const ex = await client.request("GET", base, "active_testing", {
              headers: { Origin: probeOrigin },
            });
            rawObservations.push(...checkCorsReflection(ex, probeOrigin));
          } catch {
            /* non-fatal */
          }
        }
      } else {
        emit({ type: "scan_log", level: "info", message: "CORS reflection probe skipped by the selected profile or authorization scope.", at: new Date().toISOString() });
      }
    });

    // 7. Compare owner-provided test-role access with anonymous access to
    // API routes whose published specification declares authentication.
    await runStage("auth_session_analysis", async () => {
      if (!config.authContext || !capabilities.authComparison) {
        emit({
          type: "scan_log",
          level: "info",
          message: "No owner-provided test role configured; authenticated-versus-anonymous API checks skipped.",
          at: new Date().toISOString(),
        });
      } else {
        if (!config.scope.activeTestingAllowed) {
          emit({ type: "scan_log", level: "info", message: "Authenticated API comparison skipped because active testing is disabled in the authorized scope.", at: new Date().toISOString() });
          return;
        }
        let compared = 0;
        for (const { route, exchange } of authenticatedApiRoutes) {
          if (!config.authContext || !route.securityDeclared) continue;
          checkCancelled();
          try {
            const anonymous = await client.request("GET", route.url, "auth_session_analysis", { anonymous: true });
            compared++;
            rawObservations.push(...compareAnonymousAccess(exchange, anonymous));
          } catch (e) {
            if (e instanceof BudgetExceededError) break;
          }
        }
        emit({
          type: "scan_log",
          level: "info",
          message: `Compared ${compared} documented protected API GET route(s) using the supplied test role and an anonymous request.`,
          at: new Date().toISOString(),
        });
      }
    });

    // 8. Active security tests — gated on scope.activeTestingAllowed.
    // Injection, authorization/IDOR, and non-credential session checks.
    await runStage("active_testing", async () => {
      if (!capabilities.activeChecks) {
        emit({
          type: "scan_log",
          level: "info",
          message: "Active testing is disabled for this project's scope. Passive-only results follow.",
          at: new Date().toISOString(),
        });
        return;
      }

      emit({
        type: "scan_log",
        level: "info",
        message: `Active testing enabled — running injection, authorization, and non-credential session checks against ${crawlResult.endpoints.length} endpoints.`,
        at: new Date().toISOString(),
      });

      // --- Password in URL (passive observation, run in active stage) ---
      const urlExchanges = allExchanges.map((ex) => {
        const u = new URL(ex.request.url);
        return { url: ex.request.url, query: u.search.slice(1) };
      });
      if (crawlResult.endpoints.length > 0) {
        rawObservations.push(...checkPasswordInUrl(urlExchanges, crawlResult.endpoints[0]));
      }

      // --- Per-endpoint probes ---
      const checkedAdminOrigins = new Set<string>();
      for (const endpoint of crawlResult.endpoints) {
        checkCancelled();

        // Session token checks on every exchange that set a cookie
        for (const ex of allExchanges) {
          const sc = ex.response.headers["set-cookie"];
          if (sc) {
            rawObservations.push(...checkSessionTokenEntropy(endpoint, sc));
          }
        }

        // Authorization probes
        const endpointOrigin = new URL(endpoint.url).origin;
        if (!checkedAdminOrigins.has(endpointOrigin)) {
          checkedAdminOrigins.add(endpointOrigin);
          rawObservations.push(...(await checkPrivilegedPathAccess(client, endpoint)));
        }
        rawObservations.push(...(await checkSequentialIdor(client, endpoint)));

        // Injection probes
        rawObservations.push(
          ...(await checkSqliGetParams(client, endpoint, { timingValidation: capabilities.pairedTimingValidation })),
          ...(await checkReflectedXss(client, endpoint)),
          ...(await checkPathTraversal(client, endpoint)),
          ...(await checkSsti(client, endpoint)),
          ...(await checkOpenRedirect(client, endpoint)),
          ...(await checkCommandInjection(client, endpoint, { timingValidation: capabilities.pairedTimingValidation })),
        );

        // Credential guessing and lockout-triggering checks are deliberately
        // excluded. The scanner audits published password policy signals and
        // leaves server enforcement to an owner-provided test account.
      }

      emit({
        type: "scan_log",
        level: "info",
        message: `Active testing complete — ${rawObservations.length} raw signals collected so far.`,
        at: new Date().toISOString(),
      });
    });

    // 9 + 10. Finding verification + risk scoring
    const findings = await runStage("finding_verification", async () => correlateFindings(rawObservations));
    const prioritized = await runStage("risk_scoring", async () => prioritize(findings));
    for (const f of prioritized) emit({ type: "finding_raised", finding: f, at: new Date().toISOString() });

    // 11. Report generation is handled by the API layer (it has access to
    // project/org metadata the engine deliberately doesn't know about).
    await runStage("report_generation", async () => {});

    const completedAt = new Date().toISOString();
    const ran = (key: string, didRun: boolean, reason: string) => {
      capabilityReport.capabilities[key] = didRun ? { status: "ran" } : { status: "skipped", reason };
    };
    const fixedPathSet = new Set(SENSITIVE_PATH_PROBES);
    ran("fixedPathDiscovery", capabilities.fixedPathDiscovery && allExchanges.some((exchange) => {
      try { return exchange.stage === "endpoint_discovery" && fixedPathSet.has(new URL(exchange.request.url).pathname); } catch { return false; }
    }), "No in-scope fixed path requests were issued (profile, scope, or request budget may have skipped them).");
    ran("apiSpecRouteRequests", capabilities.apiRouteRequests && apiRoutesAttempted > 0, "No in-scope GET routes were available from published API specifications.");
    ran("injectionAndAccessChecks", capabilities.activeChecks && crawlResult.endpoints.length > 0, "No active check requests ran because the profile, scope, or discovery results did not permit them.");
    ran("authenticatedApiComparison", capabilities.authComparison && allExchanges.some((exchange) => exchange.stage === "auth_session_analysis"), "No documented protected GET route was available for anonymous comparison.");
    ran("pairedTimingValidation", capabilities.pairedTimingValidation && allExchanges.some((exchange) => /SLEEP|pg_sleep/i.test(exchange.request.url)), "No eligible timing probe ran; a relevant parameter or request budget may have been unavailable.");
    emit({ type: "scan_completed", at: completedAt, findingCount: prioritized.length, requestCount: client.totalRequests });

    return {
      scanId: config.scanId,
      startedAt,
      completedAt,
      endpoints: crawlResult.endpoints,
      technologies,
      findings: prioritized,
      requestCount: client.totalRequests,
      stageDurationsMs: stageDurations,
      stopReason: crawlResult.stopReason === "budget_exceeded" ? "request_limit" : "completed",
      capabilityReport,
    };
  } catch (e) {
    const at = new Date().toISOString();
    if (e instanceof ScanCancelledError || e instanceof RequestCancelledError) {
      emit({ type: "scan_cancelled", at });
      return {
        scanId: config.scanId,
        startedAt,
        completedAt: at,
        endpoints: [],
        technologies: [],
        findings: prioritize(correlateFindings([])),
        requestCount: client.totalRequests,
        stageDurationsMs: stageDurations,
        stopReason: "cancelled",
      };
    }
    if (e instanceof BudgetExceededError) {
      const findings = prioritize(correlateFindings([]));
      emit({ type: "scan_completed", at, findingCount: findings.length, requestCount: client.totalRequests });
      return {
        scanId: config.scanId,
        startedAt,
        completedAt: at,
        endpoints: [],
        technologies: [],
        findings,
        requestCount: client.totalRequests,
        stageDurationsMs: stageDurations,
        stopReason: "duration_limit",
      };
    }
    emit({ type: "scan_failed", at, reason: (e as Error).message });
    throw e;
  }
}
