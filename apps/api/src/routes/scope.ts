import type { FastifyInstance } from "fastify";
import { prisma } from "../lib/prisma.js";
import { targetSchema, createScopeSchema, authConfigSchema } from "../lib/schemas.js";
import { requireProjectAccess } from "../plugins/authPlugin.js";
import { recordAuditEvent } from "../services/auditLog.js";
import { encryptSecret } from "../lib/crypto.js";

export default async function scopeRoutes(app: FastifyInstance) {
  // --- Targets -------------------------------------------------------
  app.post("/api/projects/:projectId/targets", async (req, reply) => {
    const { projectId } = req.params as { projectId: string };
    const access = await requireProjectAccess(req, reply, projectId);
    if (!access) return;
    const parsed = targetSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const target = await prisma.target.create({ data: { projectId, ...parsed.data } });
    await recordAuditEvent({
      organizationId: access.project.organizationId,
      projectId,
      actorId: req.currentUser!.id,
      action: "target.added",
      targetType: "Target",
      targetId: target.id,
      metadata: { type: target.type, value: target.value },
      ipAddress: req.ip,
    });
    return reply.code(201).send({ target });
  });

  app.patch("/api/projects/:projectId/targets/:targetId", async (req, reply) => {
    const { projectId, targetId } = req.params as { projectId: string; targetId: string };
    const access = await requireProjectAccess(req, reply, projectId);
    if (!access) return;
    if (access.membership.role === "VIEWER") {
      return reply.code(403).send({ error: "Viewers cannot edit targets" });
    }
    const parsed = targetSchema.partial().safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const existing = await prisma.target.findFirst({ where: { id: targetId, projectId } });
    if (!existing) return reply.code(404).send({ error: "Target not found" });

    const target = await prisma.target.update({
      where: { id: targetId },
      data: parsed.data,
    });
    await recordAuditEvent({
      organizationId: access.project.organizationId,
      projectId,
      actorId: req.currentUser!.id,
      action: "target.updated",
      targetType: "Target",
      targetId: target.id,
      metadata: { changes: parsed.data },
      ipAddress: req.ip,
    });
    return reply.send({ target });
  });

  app.delete("/api/projects/:projectId/targets/:targetId", async (req, reply) => {
    const { projectId, targetId } = req.params as { projectId: string; targetId: string };
    const access = await requireProjectAccess(req, reply, projectId);
    if (!access) return;
    if (access.membership.role === "VIEWER") {
      return reply.code(403).send({ error: "Viewers cannot remove targets" });
    }
    const existing = await prisma.target.findFirst({ where: { id: targetId, projectId } });
    if (!existing) {
      return reply.send({ ok: true, alreadyDeleted: true });
    }

    try {
      await prisma.target.delete({ where: { id: targetId } });
    } catch {
      return reply.send({ ok: true, alreadyDeleted: true });
    }
    await recordAuditEvent({
      organizationId: access.project.organizationId,
      projectId,
      actorId: req.currentUser!.id,
      action: "target.removed",
      targetType: "Target",
      targetId,
      ipAddress: req.ip,
    });
    return reply.send({ ok: true });
  });

  // --- Scope -----------------------------------------------------------
  // Creating a new scope version deactivates the previous one. Scopes are
  // never edited in place, so every scan's scopeVersionId points at an
  // immutable, fully-attributed record of what was authorized.
  app.post("/api/projects/:projectId/scope", async (req, reply) => {
    const { projectId } = req.params as { projectId: string };
    const access = await requireProjectAccess(req, reply, projectId);
    if (!access) return;
    if (access.membership.role === "VIEWER") {
      return reply.code(403).send({ error: "Viewers cannot authorize scope changes" });
    }
    const parsed = createScopeSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const scopeVersion = await prisma.$transaction(async (tx: any) => {
      await tx.scopeVersion.updateMany({ where: { projectId, isActive: true }, data: { isActive: false } });
      return tx.scopeVersion.create({
        data: {
          projectId,
          allowedHosts: parsed.data.allowedHosts,
          allowedIpRanges: parsed.data.allowedIpRanges,
          allowedPaths: parsed.data.allowedPaths,
          excludedPaths: parsed.data.excludedPaths,
          environment: parsed.data.environment,
          activeTestingAllowed: parsed.data.activeTestingAllowed,
          maxRequestsPerSecond: parsed.data.maxRequestsPerSecond,
          maxScanDurationSeconds: parsed.data.maxScanDurationSeconds,
          maxTotalRequests: parsed.data.maxTotalRequests,
          authorizationStatement: parsed.data.authorizationStatement,
          authorizedById: req.currentUser!.id,
        },
      });
    });

    await recordAuditEvent({
      organizationId: access.project.organizationId,
      projectId,
      actorId: req.currentUser!.id,
      action: "scope.authorized",
      targetType: "ScopeVersion",
      targetId: scopeVersion.id,
      metadata: {
        allowedHosts: parsed.data.allowedHosts,
        activeTestingAllowed: parsed.data.activeTestingAllowed,
        environment: parsed.data.environment,
        authorizationStatement: parsed.data.authorizationStatement,
      },
      ipAddress: req.ip,
    });

    return reply.code(201).send({ scopeVersion });
  });

  app.delete("/api/projects/:projectId/scope", async (req, reply) => {
    const { projectId } = req.params as { projectId: string };
    const access = await requireProjectAccess(req, reply, projectId);
    if (!access) return;
    if (access.membership.role === "VIEWER") {
      return reply.code(403).send({ error: "Viewers cannot modify scope" });
    }

    await prisma.scopeVersion.updateMany({
      where: { projectId, isActive: true },
      data: { isActive: false },
    });

    await recordAuditEvent({
      organizationId: access.project.organizationId,
      projectId,
      actorId: req.currentUser!.id,
      action: "scope.reset",
      targetType: "Project",
      targetId: projectId,
      ipAddress: req.ip,
    });

    return reply.send({ ok: true });
  });

  // --- Authentication configuration ------------------------------------
  app.post("/api/projects/:projectId/auth-configs", async (req, reply) => {
    const { projectId } = req.params as { projectId: string };
    const access = await requireProjectAccess(req, reply, projectId);
    if (!access) return;
    const parsed = authConfigSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    let secretId: string | undefined;
    if (parsed.data.secretValue) {
      const enc = encryptSecret(parsed.data.secretValue);
      const secret = await prisma.secret.create({ data: { ciphertext: enc.ciphertext, iv: enc.iv, authTag: enc.authTag } });
      secretId = secret.id;
    }

    const authConfig = await prisma.authenticationConfig.create({
      data: {
        projectId,
        roleLabel: parsed.data.roleLabel,
        mechanism: parsed.data.mechanism,
        loginUrl: parsed.data.loginUrl,
        usernameField: parsed.data.usernameField,
        secretId,
      },
    });

    await recordAuditEvent({
      organizationId: access.project.organizationId,
      projectId,
      actorId: req.currentUser!.id,
      action: "auth_config.created",
      targetType: "AuthenticationConfig",
      targetId: authConfig.id,
      // Never log secret material — only the non-sensitive shape of the config.
      metadata: { roleLabel: authConfig.roleLabel, mechanism: authConfig.mechanism },
      ipAddress: req.ip,
    });

    return reply.code(201).send({ authConfig: { id: authConfig.id, roleLabel: authConfig.roleLabel, mechanism: authConfig.mechanism } });
  });
}
