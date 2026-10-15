import { ScannerHttpClient, BudgetExceededError, ScopeViolationError } from "./httpClient.js";
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
  checkVerbTampering,
  checkMassAssignment,
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
import type { HttpExchange, RawObservation, ScanEvent, ScanResult, ScanRunConfig, ScanStage } from "./types.js";

const PROFILE_LIMITS: Record<string, { maxPages: number; maxDepth: number }> = {
  quick: { maxPages: 25, maxDepth: 2 },
  standard: { maxPages: 100, maxDepth: 3 },
  deep: { maxPages: 400, maxDepth: 6 },
  ci: { maxPages: 50, maxDepth: 2 },
};

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
  if (handle) handle.cancel = () => (cancelled = true);

  const checkCancelled = () => {
    if (cancelled) throw new ScanCancelledError();
  };

  const allExchanges: HttpExchange[] = [];
  const client = new ScannerHttpClient({
    scope: config.scope,
    auth: config.authContext,
    onExchange: (ex) => {
      allExchanges.push(ex);
      emit({ type: "request_issued", method: ex.request.method, url: ex.request.url, at: new Date().toISOString() });
    },
  });

  const runStage = async <T>(stage: ScanStage, fn: () => Promise<T>): Promise<T> => {
    checkCancelled();
    emit({ type: "stage_started", stage, at: new Date().toISOString() });
    const t0 = Date.now();
    try {
      const result = await fn();
      stageDurations[stage] = Date.now() - t0;
      emit({ type: "stage_completed", stage, at: new Date().toISOString() });
      return result;
    } catch (e) {
      stageDurations[stage] = Date.now() - t0;
      throw e;
    }
  };

  try {
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
    const limits = PROFILE_LIMITS[config.profile] ?? PROFILE_LIMITS.standard;
    const crawlResult = await runStage("crawling", () =>
      crawl(client, {
        startUrls: config.targetBaseUrls,
        scope: config.scope,
        maxPages: limits.maxPages,
        maxDepth: limits.maxDepth,
        onPageCrawled: (ep) => emit({ type: "endpoint_discovered", endpoint: ep, at: new Date().toISOString() }),
      }),
    );

    await runStage("endpoint_discovery", async () => {
      // Probe well-known sensitive paths per discovered host, within budget.
      const hosts = new Set(config.targetBaseUrls.map((u) => new URL(u).origin));
      for (const origin of hosts) {
        for (const path of SENSITIVE_PATH_PROBES) {
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
      if (config.scope.activeTestingAllowed) {
        for (const base of config.targetBaseUrls) {
          try {
            const probeOrigin = "https://scan-probe.invalid.example";
            const ex = await client.request("GET", base, "passive_analysis", {
              headers: { Origin: probeOrigin },
            });
            rawObservations.push(...checkCorsReflection(ex, probeOrigin));
          } catch {
            /* non-fatal */
          }
        }
      }
    });

    // 7. Auth/session analysis — Phase 2 capability. Documented interface:
    // when config.authContext is present, a future AuthenticationScanner /
    // SessionScanner pair will compare authenticated vs anonymous
    // responses here. Phase 1 intentionally does not claim results it
    // cannot yet produce.
    await runStage("auth_session_analysis", async () => {
      if (!config.authContext) {
        emit({
          type: "scan_log",
          level: "info",
          message: "No authentication configured for this scan; authenticated-session analysis skipped.",
          at: new Date().toISOString(),
        });
      } else {
        emit({
          type: "scan_log",
          level: "info",
          message: "Authenticated context present. Role-comparison authorization testing is a Phase 2 capability and did not run in this scan.",
          at: new Date().toISOString(),
        });
      }
    });

    // 8. Active security tests — gated on scope.activeTestingAllowed.
    // Phase 2: injection, authorization/IDOR, authentication/session checks.
    await runStage("active_testing", async () => {
      if (!config.scope.activeTestingAllowed) {
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
        rawObservations.push(
          ...(await checkPrivilegedPathAccess(client, endpoint)),
          ...(await checkSequentialIdor(client, endpoint)),
          ...(await checkVerbTampering(client, endpoint)),
          ...(await checkMassAssignment(client, endpoint)),
        );

        // Injection probes
        rawObservations.push(
          ...(await checkSqliGetParams(client, endpoint)),
          ...(await checkReflectedXss(client, endpoint)),
          ...(await checkPathTraversal(client, endpoint)),
          ...(await checkSsti(client, endpoint)),
          ...(await checkOpenRedirect(client, endpoint)),
          ...(await checkCommandInjection(client, endpoint)),
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
    };
  } catch (e) {
    const at = new Date().toISOString();
    if (e instanceof ScanCancelledError) {
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
