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

const activeHandles = new Map<string, EngineHandle>();

export function cancelScan(scanId: string): boolean {
  const handle = activeHandles.get(scanId);
  if (!handle) return false;
  handle.cancel();
  return true;
}

export async function executeScan(scanId: string): Promise<void> {
  const scan = await prisma.scan.findUniqueOrThrow({
    where: { id: scanId },
    include: {
      project: { include: { targets: true, organization: true } },
      scopeVersion: true,
      authConfig: { include: { secret: true } },
    },
  });

  await prisma.scan.update({ where: { id: scanId }, data: { status: "RUNNING", startedAt: new Date() } });

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

  let authContext: AuthContext | undefined;
  if (scan.authConfig && scan.authConfig.mechanism !== "NONE" && scan.authConfig.secret) {
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

  const targetBaseUrls = scan.project.targets
    .filter((t: any) => t.type === "URL" || t.type === "DOMAIN")
    .map((t: any) => (t.type === "DOMAIN" ? `https://${t.value}` : t.value));

  const handle: EngineHandle = { cancel: () => {} };
  activeHandles.set(scanId, handle);

  try {
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
        void persistEvent(scanId, scan.projectId, event);
      },
      handle,
    );

    await prisma.scan.update({
      where: { id: scanId },
      data: {
        status: result.stopReason === "cancelled" ? "CANCELLED" : "COMPLETED",
        completedAt: new Date(),
        requestCount: result.requestCount,
        stopReason: result.stopReason,
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
    await prisma.scan.update({
      where: { id: scanId },
      data: { status: "FAILED", completedAt: new Date(), failureReason: (err as Error).message },
    });
    scanEventBus.publish(scanId, { type: "scan_failed", at: new Date().toISOString(), reason: (err as Error).message });
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
    activeHandles.delete(scanId);
  }
}

async function persistEvent(scanId: string, projectId: string, event: ScanEvent) {
  switch (event.type) {
    case "stage_started":
      await prisma.scanStageEvent.create({ data: { scanId, stage: event.stage, status: "started" } });
      break;
    case "stage_completed":
      await prisma.scanStageEvent.create({ data: { scanId, stage: event.stage, status: "completed", summary: event.summary } });
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

// typing helper only
async function noop() {
  return {} as import("@hacker/scanner-core").ScanEvent;
}
