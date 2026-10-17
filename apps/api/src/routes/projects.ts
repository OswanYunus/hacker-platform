import type { FastifyInstance } from "fastify";
import { prisma } from "../lib/prisma.js";
import { createProjectSchema } from "../lib/schemas.js";
import { requireAuth, requireProjectAccess } from "../plugins/authPlugin.js";
import { recordAuditEvent } from "../services/auditLog.js";

export default async function projectRoutes(app: FastifyInstance) {
  app.get("/api/projects", async (req, reply) => {
    if (!requireAuth(req, reply)) return;
    const memberships = await prisma.orgMembership.findMany({ where: { userId: req.currentUser.id } });
    const orgIds = memberships.map((m: any) => m.organizationId);
    const projects = await prisma.project.findMany({
      where: { organizationId: { in: orgIds }, archivedAt: null },
      orderBy: { updatedAt: "desc" },
      include: {
        _count: { select: { scans: true, findings: true } },
        scopeVersions: { where: { isActive: true }, take: 1 },
      },
    });
    return reply.send({ projects });
  });

  app.post("/api/projects", async (req, reply) => {
    if (!requireAuth(req, reply)) return;
    const parsed = createProjectSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const { organizationId } = (req.body as { organizationId?: string }) ?? {};
    if (!organizationId) return reply.code(400).send({ error: "organizationId is required" });

    const membership = await prisma.orgMembership.findUnique({
      where: { userId_organizationId: { userId: req.currentUser.id, organizationId } },
    });
    if (!membership || membership.role === "VIEWER") {
      return reply.code(403).send({ error: "You do not have permission to create projects in this organization" });
    }

    const project = await prisma.project.create({
      data: {
        organizationId,
        name: parsed.data.name,
        description: parsed.data.description,
        createdById: req.currentUser.id,
      },
    });

    await recordAuditEvent({
      organizationId,
      projectId: project.id,
      actorId: req.currentUser.id,
      action: "project.created",
      targetType: "Project",
      targetId: project.id,
      metadata: { name: project.name },
      ipAddress: req.ip,
    });

    return reply.code(201).send({ project });
  });

  app.get("/api/projects/:projectId", async (req, reply) => {
    const { projectId } = req.params as { projectId: string };
    const access = await requireProjectAccess(req, reply, projectId);
    if (!access) return;

    const project = await prisma.project.findUnique({
      where: { id: projectId },
      include: {
        targets: {
          select: {
            id: true,
            projectId: true,
            type: true,
            value: true,
            label: true,
            verificationRecordName: true,
            verifiedAt: true,
            createdAt: true,
          },
        },
        scopeVersions: { orderBy: { createdAt: "desc" }, include: { authorizedBy: { select: { id: true, name: true, email: true } } } },
        authConfigs: { select: { id: true, roleLabel: true, mechanism: true, loginUrl: true, createdAt: true } },
        scans: { orderBy: { createdAt: "desc" }, take: 20 },
        _count: { select: { findings: true } },
      },
    });
    return reply.send({ project });
  });

  app.delete("/api/projects/:projectId", async (req, reply) => {
    const { projectId } = req.params as { projectId: string };
    const access = await requireProjectAccess(req, reply, projectId);
    if (!access) return;
    if (access.membership.role !== "OWNER" && access.membership.role !== "ADMIN") {
      return reply.code(403).send({ error: "Only organization owners/admins can archive a project" });
    }
    await prisma.project.update({ where: { id: projectId }, data: { archivedAt: new Date() } });
    await recordAuditEvent({
      organizationId: access.project.organizationId,
      projectId,
      actorId: req.currentUser!.id,
      action: "project.archived",
      targetType: "Project",
      targetId: projectId,
      ipAddress: req.ip,
    });
    return reply.send({ ok: true });
  });
}
