import type { FastifyInstance } from "fastify";
import { prisma } from "../lib/prisma.js";
import { createScanSchema } from "../lib/schemas.js";
import { requireProjectAccess } from "../plugins/authPlugin.js";
import { recordAuditEvent } from "../services/auditLog.js";
import { scanQueue } from "../services/scanQueue.js";
import { cancelScan } from "../services/scanOrchestrator.js";
import { scanEventBus } from "../services/eventBus.js";

export default async function scanRoutes(app: FastifyInstance) {
  app.post("/api/projects/:projectId/scans", async (req, reply) => {
    const { projectId } = req.params as { projectId: string };
    const access = await requireProjectAccess(req, reply, projectId);
    if (!access) return;
    if (access.membership.role === "VIEWER") {
      return reply.code(403).send({ error: "Viewers cannot start scans" });
    }
    const parsed = createScanSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const scopeVersion = await prisma.scopeVersion.findFirst({ where: { projectId, isActive: true } });
    if (!scopeVersion) {
      return reply.code(400).send({ error: "This project has no authorized scope configured yet. Define scope before starting a scan." });
    }
    const targetCount = await prisma.target.count({ where: { projectId } });
    if (targetCount === 0) {
      return reply.code(400).send({ error: "Add at least one target before starting a scan." });
    }

    const scan = await prisma.scan.create({
      data: {
        projectId,
        scopeVersionId: scopeVersion.id,
        authConfigId: parsed.data.authConfigId,
        profile: parsed.data.profile,
        triggerSource: parsed.data.triggerSource,
        triggeredById: req.currentUser!.id,
        status: "QUEUED",
      },
    });

    await recordAuditEvent({
      organizationId: access.project.organizationId,
      projectId,
      actorId: req.currentUser!.id,
      action: "scan.started",
      targetType: "Scan",
      targetId: scan.id,
      metadata: { profile: scan.profile, scopeVersionId: scopeVersion.id, triggerSource: scan.triggerSource },
      ipAddress: req.ip,
    });

    await scanQueue.enqueue(scan.id);
    return reply.code(201).send({ scan });
  });

  app.get("/api/projects/:projectId/scans", async (req, reply) => {
    const { projectId } = req.params as { projectId: string };
    const access = await requireProjectAccess(req, reply, projectId);
    if (!access) return;
    const scans = await prisma.scan.findMany({
      where: { projectId },
      orderBy: { createdAt: "desc" },
      include: { _count: { select: { findings: true } }, triggeredBy: { select: { name: true, email: true } } },
    });
    return reply.send({ scans });
  });

  app.get("/api/scans/:scanId", async (req, reply) => {
    const { scanId } = req.params as { scanId: string };
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { stageEvents: { orderBy: { occurredAt: "asc" } }, project: true },
    });
    if (!scan) return reply.code(404).send({ error: "Scan not found" });
    const access = await requireProjectAccess(req, reply, scan.projectId);
    if (!access) return;
    return reply.send({ scan });
  });

  app.post("/api/scans/:scanId/cancel", async (req, reply) => {
    const { scanId } = req.params as { scanId: string };
    const scan = await prisma.scan.findUnique({ where: { id: scanId } });
    if (!scan) return reply.code(404).send({ error: "Scan not found" });
    const access = await requireProjectAccess(req, reply, scan.projectId);
    if (!access) return;
    const cancelled = cancelScan(scanId);
    if (!cancelled) return reply.code(409).send({ error: "Scan is not currently running" });
    await recordAuditEvent({
      organizationId: access.project.organizationId,
      projectId: scan.projectId,
      actorId: req.currentUser!.id,
      action: "scan.cancel_requested",
      targetType: "Scan",
      targetId: scanId,
      ipAddress: req.ip,
    });
    return reply.send({ ok: true });
  });

  app.delete("/api/scans/:scanId", async (req, reply) => {
    const { scanId } = req.params as { scanId: string };
    const scan = await prisma.scan.findUnique({ where: { id: scanId } });
    if (!scan) return reply.send({ ok: true, alreadyDeleted: true });
    const access = await requireProjectAccess(req, reply, scan.projectId);
    if (!access) return;
    if (access.membership.role === "VIEWER") {
      return reply.code(403).send({ error: "Viewers cannot delete scans" });
    }

    if (scan.status === "RUNNING" || scan.status === "QUEUED") {
      cancelScan(scanId);
    }

    await prisma.technologyRecord.deleteMany({ where: { scanId } });
    await prisma.scan.delete({ where: { id: scanId } });

    await recordAuditEvent({
      organizationId: access.project.organizationId,
      projectId: scan.projectId,
      actorId: req.currentUser!.id,
      action: "scan.deleted",
      targetType: "Scan",
      targetId: scanId,
      metadata: { profile: scan.profile },
      ipAddress: req.ip,
    });
    return reply.send({ ok: true });
  });

  app.delete("/api/projects/:projectId/scans", async (req, reply) => {
    const { projectId } = req.params as { projectId: string };
    const access = await requireProjectAccess(req, reply, projectId);
    if (!access) return;
    if (access.membership.role === "VIEWER") {
      return reply.code(403).send({ error: "Viewers cannot clear scans" });
    }

    const { status } = req.query as { status?: string };
    const whereClause: any = { projectId };
    if (status && status !== "ALL") {
      whereClause.status = status;
    } else if (!status) {
      whereClause.status = { in: ["COMPLETED", "FAILED", "CANCELLED"] };
    }

    const targetScans = await prisma.scan.findMany({ where: whereClause, select: { id: true } });
    const scanIds = targetScans.map((s) => s.id);
    if (scanIds.length > 0) {
      await prisma.technologyRecord.deleteMany({ where: { scanId: { in: scanIds } } });
      await prisma.scan.deleteMany({ where: { id: { in: scanIds } } });
      await recordAuditEvent({
        organizationId: access.project.organizationId,
        projectId,
        actorId: req.currentUser!.id,
        action: "scans.cleared",
        targetType: "Project",
        targetId: projectId,
        metadata: { clearedCount: scanIds.length },
        ipAddress: req.ip,
      });
    }
    return reply.send({ ok: true, clearedCount: scanIds.length });
  });

  // Server-Sent Events stream of live scan progress. Replays buffered
  // history first so a client that connects mid-scan isn't missing
  // earlier stages, then streams new events as they occur.
  app.get("/api/scans/:scanId/events", async (req, reply) => {
    const { scanId } = req.params as { scanId: string };
    const scan = await prisma.scan.findUnique({ where: { id: scanId } });
    if (!scan) return reply.code(404).send({ error: "Scan not found" });
    const access = await requireProjectAccess(req, reply, scan.projectId);
    if (!access) return;

    reply.raw.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-store",
      Connection: "keep-alive",
    });

    const send = (data: unknown) => {
      reply.raw.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    for (const event of scanEventBus.replay(scanId)) send(event);

    const unsubscribe = scanEventBus.subscribe(scanId, send);
    const heartbeat = setInterval(() => reply.raw.write(": heartbeat\n\n"), 15000);

    req.raw.on("close", () => {
      clearInterval(heartbeat);
      unsubscribe();
    });
  });

  app.get("/api/projects/:projectId/findings", async (req, reply) => {
    const { projectId } = req.params as { projectId: string };
    const access = await requireProjectAccess(req, reply, projectId);
    if (!access) return;
    const { severity, scanId } = req.query as { severity?: string; scanId?: string };
    const findings = await prisma.finding.findMany({
      where: { projectId, ...(severity ? { severity } : {}), ...(scanId ? { scanId } : {}) },
      orderBy: [{ riskScore: "desc" }],
      include: { evidence: true, remediationStatus: true },
    });
    return reply.send({ findings });
  });

  app.patch("/api/findings/:findingId/remediation", async (req, reply) => {
    const { findingId } = req.params as { findingId: string };
    const finding = await prisma.finding.findUnique({ where: { id: findingId } });
    if (!finding) return reply.code(404).send({ error: "Finding not found" });
    const access = await requireProjectAccess(req, reply, finding.projectId);
    if (!access) return;

    const body = req.body as { state?: string; note?: string };
    const updated = await prisma.remediationStatus.upsert({
      where: { findingId },
      create: { findingId, state: (body.state as any) ?? "OPEN", note: body.note, updatedById: req.currentUser!.id },
      update: { state: body.state as any, note: body.note, updatedById: req.currentUser!.id },
    });

    await recordAuditEvent({
      organizationId: access.project.organizationId,
      projectId: finding.projectId,
      actorId: req.currentUser!.id,
      action: "finding.remediation_updated",
      targetType: "Finding",
      targetId: findingId,
      metadata: { state: body.state, note: body.note },
      ipAddress: req.ip,
    });

    return reply.send({ remediationStatus: updated });
  });
}
