import type { FastifyInstance } from "fastify";
import { prisma } from "../lib/prisma.js";
import { requireProjectAccess } from "../plugins/authPlugin.js";
import { listProjectAuditTrail } from "../services/auditLog.js";
import { evaluateCiPolicy } from "@hacker/scanner-core";
import { ciPolicySchema } from "../lib/schemas.js";

export default async function auditRoutes(app: FastifyInstance) {
  app.get("/api/projects/:projectId/audit-trail", async (req, reply) => {
    const { projectId } = req.params as { projectId: string };
    const access = await requireProjectAccess(req, reply, projectId);
    if (!access) return;
    const events = await listProjectAuditTrail(projectId);
    return reply.send({ events });
  });

  app.delete("/api/projects/:projectId/audit-trail", async (req, reply) => {
    const { projectId } = req.params as { projectId: string };
    const access = await requireProjectAccess(req, reply, projectId);
    if (!access) return;
    return reply.code(405).send({ error: "Audit trail is append-only and cannot be cleared." });
  });

  // Used by CI integrations: given a completed scan and a fail policy,
  // returns pass/fail + the specific violations, so a pipeline can gate
  // deployment on it (`curl .../ci-check | jq .pass`).
  app.post("/api/scans/:scanId/ci-check", async (req, reply) => {
    const { scanId } = req.params as { scanId: string };
    const scan = await prisma.scan.findUnique({ where: { id: scanId }, include: { findings: true } });
    if (!scan) return reply.code(404).send({ error: "Scan not found" });
    const access = await requireProjectAccess(req, reply, scan.projectId);
    if (!access) return;

    if (scan.status !== "COMPLETED") {
      return reply.code(409).send({ error: `Scan status is ${scan.status}, not COMPLETED` });
    }

    const parsed = ciPolicySchema.safeParse(req.body ?? {});
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const findingsAsCore = scan.findings.map((f: any) => ({ ...f, severity: f.severity as any, confidence: f.confidence as any, verification: f.verification as any }));
    const result = evaluateCiPolicy(findingsAsCore as any, parsed.data);
    return reply.send(result);
  });

  // Compares two scans on the same project — surfaces which findings are
  // new, which were resolved (present in the older scan, absent here),
  // and which recurred.
  app.get("/api/projects/:projectId/scans/compare", async (req, reply) => {
    const { projectId } = req.params as { projectId: string };
    const access = await requireProjectAccess(req, reply, projectId);
    if (!access) return;
    const { baseScanId, compareScanId } = req.query as { baseScanId?: string; compareScanId?: string };
    if (!baseScanId || !compareScanId) {
      return reply.code(400).send({ error: "baseScanId and compareScanId query params are required" });
    }

    const [base, compare] = await Promise.all([
      prisma.finding.findMany({ where: { scanId: baseScanId, projectId } }),
      prisma.finding.findMany({ where: { scanId: compareScanId, projectId } }),
    ]);

    const key = (f: { ruleId: string; affectedEndpoint: string }) => `${f.ruleId}::${f.affectedEndpoint}`;
    const baseKeys = new Set(base.map(key));
    const compareKeys = new Set(compare.map(key));

    const newFindings = compare.filter((f: any) => !baseKeys.has(key(f)));
    const resolvedFindings = base.filter((f: any) => !compareKeys.has(key(f)));
    const recurring = compare.filter((f: any) => baseKeys.has(key(f)));

    return reply.send({ newFindings, resolvedFindings, recurring });
  });
}
