import {
  runScan,
  riskScore as computeRiskScore,
  type AuthContext,
  type AuthorizationScope,
  type EngineHandle,
  type ScanProfile,
  type ScanEvent,
} from "@hacker/scanner-core";
import { prisma } from "../lib/prisma.js";
import { decryptSecret } from "../lib/crypto.js";
import { scanEventBus } from "./eventBus.js";
import { recordAuditEvent } from "./auditLog.js";
import { ScanSessionLogger } from "./scanSessionLog.js";
import { canSkipDnsVerificationForTarget, hasValidDnsChallenge, targetBaseUrl, targetHostname, targetsCoverAllowedHosts } from "./targetVerification.js";

const activeHandles = new Map<string, EngineHandle>();

export function cancelScan(scanId: string): boolean {
  const handle = activeHandles.get(scanId);
  if (!handle) return false;
  handle.cancel();
  return true;
}
export async function executeScan(scanId: string, workerId: string): Promise<void> {
  const scan = await prisma.scan.findUniqueOrThrow({
    where: { id: scanId },
    include: {
      project: { include: { targets: true, organization: true } },
      scopeVersion: true,
      authConfig: { include: { secret: true } },
    },
  });

  // Claiming is performed by the database queue with a conditional update.
  // This guard prevents direct or stale invocations from running unclaimed.
  if (scan.status !== "RUNNING" || scan.workerId !== workerId) return;

  const startedAt = new Date();
  const sessionLogger = new ScanSessionLogger(scanId, startedAt);
  await sessionLogger.initialize().catch((err) => console.error("Unable to initialize scan session log:", err));

  const scope: AuthorizationScope = {
    allowedHosts: scan.scopeVersion.allowedHosts,
    allowedIpRanges: scan.scopeVersion.allowedIpRanges,
    allowedPaths: scan.scopeVersion.allowedPaths,
    excludedPaths: scan.scopeVersion.excludedPaths,
    activeTestingAllowed: scan.scopeVersion.activeTestingAllowed,
    maxRequestsPerSecond: scan.scopeVersion.maxRequestsPerSecond,
    maxScanDurationSeconds: scan.scopeVersion.maxScanDurationSeconds,
    maxTotalRequests: scan.scopeVersion.maxTotalRequests,
    environment: scan.scopeVersion.environment.toLowerCase() as AuthorizationScope["environment"],
  };

  const authConfigProjectMismatch = Boolean(scan.authConfig && scan.authConfig.projectId !== scan.projectId);
  let authContext: AuthContext | undefined;
  if (!authConfigProjectMismatch && scan.authConfig && scan.authConfig.mechanism !== "NONE" && scan.authConfig.secret) {
    const secretValue = decryptSecret({
      ciphertext: Buffer.from(scan.authConfig.secret.ciphertext),
      iv: Buffer.from(scan.authConfig.secret.iv),
      authTag: Buffer.from(scan.authConfig.secret.authTag),
    });
    authContext = {
      role: scan.authConfig.roleLabel,
      cookieHeader: scan.authConfig.mechanism === "COOKIE" ? secretValue : undefined,
      bearerToken: scan.authConfig.mechanism === "BEARER_TOKEN" ? secretValue : undefined,
    };
  }

  const targetBaseUrls = Array.from(new Set(scan.project.targets
    .filter((t: any) => t.type === "URL" || t.type === "DOMAIN")
      .map((t: any) => targetBaseUrl(t))));

  const handle: EngineHandle = { cancel: () => {} };
  activeHandles.set(scanId, handle);
  let persistence = Promise.resolve();
  let persistenceFailure: unknown;
  const heartbeat = setInterval(() => {
    void refreshWorkerLease(scanId, workerId, handle).catch((error) => {
      persistenceFailure = error;
      handle.cancel();
    });
  }, 8_000);
  heartbeat.unref();

  try {
    if (authConfigProjectMismatch) {
      throw new Error("Authentication config does not belong to the scan project.");
    }
    const activeRequest = scan.scopeVersion.activeTestingAllowed || scan.profile === "DEEP";
    if (scan.profile === "DEEP" && !scan.scopeVersion.activeTestingAllowed) {
      throw new Error("Deep scan authorization was disabled before the worker started.");
    }
    if (!scan.scopeVersion.authorizationStatement?.trim()) {
      throw new Error("The recorded authorization statement is missing.");
    }
    if (!scan.scopeVersion.isActive) {
      throw new Error("The scan scope is no longer active; interrupted work cannot resume under an outdated scope.");
    }
    if (activeRequest) {
      const membership = await prisma.orgMembership.findUnique({
        where: { userId_organizationId: { userId: scan.triggeredById, organizationId: scan.project.organizationId } },
      });
      if (!membership || (membership.role !== "OWNER" && membership.role !== "ADMIN")) {
        throw new Error("Active and deep scans require an organization owner/admin at execution time.");
      }
    }
    const { targets: proofTargets, unmatchedHosts } = targetsCoverAllowedHosts(
      scan.scopeVersion.allowedHosts,
      scan.project.targets,
    );
    if (unmatchedHosts.length > 0) {
      throw new Error(`No DNS-verifiable target matches the authorized hosts: ${unmatchedHosts.join(", ")}.`);
    }
    for (const target of proofTargets) {
      const hostname = targetHostname(target);
      if (canSkipDnsVerificationForTarget(hostname, scan.scopeVersion.allowedHosts)) continue;
      if (!(await hasValidDnsChallenge(target))) {
        throw new Error(`DNS control proof is missing or no longer valid for ${hostname}.`);
      }
      await prisma.target.update({ where: { id: target.id }, data: { verifiedAt: new Date() } });
    }

    const result = await runScan(
      {
        scanId,
        projectId: scan.projectId,
        targetBaseUrls,
        scope,
        profile: scan.profile.toLowerCase() as ScanProfile,
        authContext,
      },
      (event) => {
        scanEventBus.publish(scanId, event);
        sessionLogger.append(event);
        persistence = persistence.then(() => persistEvent(scanId, scan.projectId, event));
      },
      handle,
    );
    await persistence;
    if (persistenceFailure) throw persistenceFailure;
    await sessionLogger.flush();

    await prisma.scan.update({
      where: { id: scanId, workerId, status: "RUNNING" },
      data: {
        status: result.stopReason === "cancelled" ? "CANCELLED" : "COMPLETED",
        completedAt: new Date(),
        workerId: null,
        leaseExpiresAt: null,
        heartbeatAt: null,
        requestCount: result.requestCount,
        stopReason: result.stopReason,
        capabilityReport: result.capabilityReport as any,
        currentStage: result.stopReason === "completed" ? "completed" : "cancelled",
        progressPercent: 100,
      },
    });

    if (result.technologies.length > 0) {
      await prisma.technologyRecord.createMany({
        data: result.technologies.map((t) => ({
          scanId,
          name: t.name,
          category: t.category,
          version: t.version,
          confidence: t.confidence,
          evidence: t.evidence,
        })),
      });
    }

    await recordAuditEvent({
      organizationId: scan.project.organizationId,
      projectId: scan.projectId,
      actorId: scan.triggeredById,
      action: "scan.completed",
      targetType: "Scan",
      targetId: scanId,
      metadata: { findingCount: result.findings.length, requestCount: result.requestCount, stopReason: result.stopReason },
    });
  } catch (err) {
    await persistence.catch(() => undefined);
    await prisma.scan.update({
      where: { id: scanId, workerId, status: "RUNNING" },
      data: {
        status: "FAILED",
        completedAt: new Date(),
        failureReason: (err as Error).message,
        workerId: null,
        leaseExpiresAt: null,
        heartbeatAt: null,
        stopReason: "error",
      },
    });
    const failedEvent = { type: "scan_failed" as const, at: new Date().toISOString(), reason: (err as Error).message };
    scanEventBus.publish(scanId, failedEvent);
    sessionLogger.append(failedEvent);
    await sessionLogger.flush();
    await recordAuditEvent({
      organizationId: scan.project.organizationId,
      projectId: scan.projectId,
      actorId: scan.triggeredById,
      action: "scan.failed",
      targetType: "Scan",
      targetId: scanId,
      metadata: { reason: (err as Error).message },
    });
  } finally {
    clearInterval(heartbeat);
    await sessionLogger.flush();
    activeHandles.delete(scanId);
  }
}

async function refreshWorkerLease(scanId: string, workerId: string, handle: EngineHandle): Promise<void> {
  const current = await prisma.scan.findUnique({
    where: { id: scanId },
    select: { status: true, workerId: true, cancelRequestedAt: true },
  });
  if (!current || current.status !== "RUNNING" || current.workerId !== workerId) {
    handle.cancel();
    return;
  }
  if (current.cancelRequestedAt) {
    handle.cancel();
    return;
  }
  const now = new Date();
  await prisma.scan.updateMany({
    where: { id: scanId, status: "RUNNING", workerId, cancelRequestedAt: null },
    data: { heartbeatAt: now, leaseExpiresAt: new Date(now.getTime() + 30_000) },
  });
}

async function persistEvent(scanId: string, projectId: string, event: ScanEvent) {
  switch (event.type) {
    case "stage_started":
      await prisma.scan.updateMany({
        where: { id: scanId, status: "RUNNING" },
        data: { currentStage: event.stage, progressPercent: stageProgress(event.stage) },
      });
      await prisma.scanStageEvent.create({ data: { scanId, stage: event.stage, status: "started" } });
      break;
    case "stage_completed":
      await prisma.scan.updateMany({
        where: { id: scanId, status: "RUNNING" },
        data: { currentStage: event.stage, progressPercent: stageProgress(event.stage) },
      });
      await prisma.scanStageEvent.create({ data: { scanId, stage: event.stage, status: "completed", summary: event.summary ?? (event.durationMs === undefined ? undefined : `Completed in ${event.durationMs}ms`) } });
      break;
    case "endpoint_discovered":
      await prisma.discoveredEndpointRecord.create({
        data: {
          scanId,
          projectId,
          url: event.endpoint.url,
          methods: event.endpoint.methodsObserved,
          statusCodes: event.endpoint.statusCodesObserved,
          queryParams: event.endpoint.queryParams,
          formFields: event.endpoint.formFields,
          requiresAuth: String(event.endpoint.requiresAuth),
          sourceType: event.endpoint.sourceType,
          contentType: event.endpoint.contentType,
          parentUrl: event.endpoint.parentUrl,
        },
      });
      break;
    case "finding_raised": {
      const f = event.finding;
      await prisma.finding.create({
        data: {
          id: f.id,
          scanId,
          projectId,
          ruleId: f.ruleId,
          title: f.title,
          severity: f.severity,
          confidence: f.confidence,
          cwe: f.cwe,
          owaspCategory: f.owaspCategory,
          affectedEndpoint: f.affectedEndpoint,
          reproduction: f.reproduction,
          rootCause: f.rootCause,
          impact: f.impact,
          remediation: f.remediation,
          references: f.references,
          verification: f.verification,
          occurrences: f.occurrences,
          module: f.module,
          firstSeenStage: f.firstSeenStage,
          riskScore: computeRiskScore(f),
          evidence: {
            create: f.evidence.map((e) => ({ description: e.description, exchangeId: e.exchangeId, detail: e.detail })),
          },
          remediationStatus: { create: { state: "OPEN" } },
        },
      });
      break;
    }
    default:
      break;
  }
}

function stageProgress(stage: string): number {
  const stages = [
    "scope_validation", "target_discovery", "crawling", "endpoint_discovery",
    "technology_identification", "passive_analysis", "auth_session_analysis",
    "active_testing", "finding_verification", "risk_scoring", "report_generation",
  ];
  return Math.round(((stages.indexOf(stage) + 1) / stages.length) * 95);
}
