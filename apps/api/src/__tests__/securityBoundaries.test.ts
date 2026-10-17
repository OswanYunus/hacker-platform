import Fastify from "fastify";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/prisma.js", () => ({
  prisma: {
    authenticationConfig: { findFirst: vi.fn() },
    auditEvent: { deleteMany: vi.fn() },
  },
}));
vi.mock("../plugins/authPlugin.js", () => ({
  requireProjectAccess: vi.fn(),
}));
vi.mock("../services/auditLog.js", () => ({
  listProjectAuditTrail: vi.fn(),
}));
vi.mock("../services/scanQueue.js", () => ({ scanQueue: { enqueue: vi.fn() } }));
vi.mock("../services/scanOrchestrator.js", () => ({ cancelScan: vi.fn() }));
vi.mock("../services/eventBus.js", () => ({ scanEventBus: { subscribe: vi.fn() } }));
vi.mock("../services/scanSessionLog.js", () => ({
  removeScanSessionLog: vi.fn(),
  scanSessionLogPath: vi.fn(),
}));
vi.mock("../services/targetVerification.js", () => ({
  hasValidDnsChallenge: vi.fn(),
  targetHostname: vi.fn(),
  targetsCoverAllowedHosts: vi.fn(),
}));

import { prisma } from "../lib/prisma.js";
import { requireProjectAccess } from "../plugins/authPlugin.js";
import scanRoutes from "../routes/scans.js";
import auditRoutes from "../routes/audit.js";

describe("security boundary regressions", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(requireProjectAccess).mockResolvedValue({
      project: { organizationId: "org_1" },
      membership: { role: "OWNER" },
    } as never);
  });

  it("rejects an authentication config that is not in the scan project", async () => {
    vi.mocked(prisma.authenticationConfig.findFirst).mockResolvedValue(null as never);
    const app = Fastify();
    await app.register(scanRoutes);

    const response = await app.inject({
      method: "POST",
      url: "/api/projects/project_a/scans",
      payload: { profile: "STANDARD", authConfigId: "config_from_project_b" },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().error).toContain("not found in this project");
    expect(prisma.authenticationConfig.findFirst).toHaveBeenCalledWith({
      where: { id: "config_from_project_b", projectId: "project_a" },
      select: { id: true },
    });
    await app.close();
  });

  it("does not expose audit-trail deletion to any project role", async () => {
    const app = Fastify();
    await app.register(auditRoutes);

    const response = await app.inject({
      method: "DELETE",
      url: "/api/projects/project_a/audit-trail",
    });

    expect(response.statusCode).toBe(405);
    expect(prisma.auditEvent.deleteMany).not.toHaveBeenCalled();
    await app.close();
  });
});
