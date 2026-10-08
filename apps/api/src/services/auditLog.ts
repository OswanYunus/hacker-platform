import { prisma } from "../lib/prisma.js";

export interface AuditLogInput {
  organizationId: string;
  projectId?: string;
  actorId?: string;
  action: string;
  targetType: string;
  targetId: string;
  metadata?: Record<string, unknown>;
  ipAddress?: string;
}

/**
 * Records one audit event. Called at every point in the API where
 * something authorization-relevant happens: project creation, scope
 * changes, authentication config changes, scan starts, scan cancellation,
 * remediation status changes. Never updated or deleted — if something
 * needs correcting, a new event is appended that supersedes it.
 */
export async function recordAuditEvent(input: AuditLogInput): Promise<void> {
  await prisma.auditEvent.create({
    data: {
      organizationId: input.organizationId,
      projectId: input.projectId,
      actorId: input.actorId,
      action: input.action,
      targetType: input.targetType,
      targetId: input.targetId,
      metadata: input.metadata as any,
      ipAddress: input.ipAddress,
    },
  });
}

export async function listProjectAuditTrail(projectId: string, limit = 200) {
  return prisma.auditEvent.findMany({
    where: { projectId },
    orderBy: { createdAt: "desc" },
    take: limit,
    include: { actor: { select: { id: true, name: true, email: true } } },
  });
}
