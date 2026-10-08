import type { FastifyInstance } from "fastify";
import { prisma } from "../lib/prisma.js";
import { requireProjectAccess } from "../plugins/authPlugin.js";
import { summarizeSeverity } from "@hacker/scanner-core";

async function loadReportData(scanId: string) {
  const scan = await prisma.scan.findUnique({
    where: { id: scanId },
    include: {
      project: true,
      scopeVersion: { include: { authorizedBy: { select: { name: true, email: true } } } },
      triggeredBy: { select: { name: true, email: true } },
      findings: { include: { evidence: true }, orderBy: { riskScore: "desc" } },
    },
  });
  return scan;
}

export default async function reportRoutes(app: FastifyInstance) {
  app.get("/api/scans/:scanId/report", async (req, reply) => {
    const { scanId } = req.params as { scanId: string };
    const { format } = req.query as { format?: string };
    const scan = await loadReportData(scanId);
    if (!scan) return reply.code(404).send({ error: "Scan not found" });
    const access = await requireProjectAccess(req, reply, scan.projectId);
    if (!access) return;

    const fmt = (format ?? "json").toLowerCase();
    const findingsAsCore = scan.findings.map((f: any) => ({ ...f, severity: f.severity as any, confidence: f.confidence as any, verification: f.verification as any }));
    const summary = summarizeSeverity(findingsAsCore as any);

    if (fmt === "json") {
      return reply.send(buildReportJson(scan, summary));
    }
    if (fmt === "csv") {
      reply.header("Content-Type", "text/csv");
      reply.header("Content-Disposition", `attachment; filename="scan-${scanId}.csv"`);
      return reply.send(buildCsv(scan));
    }
    if (fmt === "markdown" || fmt === "md") {
      reply.header("Content-Type", "text/markdown");
      return reply.send(buildMarkdown(scan, summary));
    }
    if (fmt === "pdf") {
      // PDF export is a documented Phase 3 interface, not implemented yet.
      // Returning 501 rather than a fake/empty PDF so callers (including
      // CI integrations) fail loudly instead of silently.
      return reply.code(501).send({
        error: "PDF export is not yet implemented. Use format=json, format=markdown, or format=csv for now.",
      });
    }
    return reply.code(400).send({ error: `Unknown report format "${format}"` });
  });
}

function buildReportJson(scan: NonNullable<Awaited<ReturnType<typeof loadReportData>>>, summary: ReturnType<typeof summarizeSeverity>) {
  return {
    executiveSummary: {
      project: scan.project.name,
      scanId: scan.id,
      profile: scan.profile,
      status: scan.status,
      startedAt: scan.startedAt,
      completedAt: scan.completedAt,
      requestCount: scan.requestCount,
      severityCounts: summary,
    },
    scope: {
      environment: scan.scopeVersion.environment,
      allowedHosts: scan.scopeVersion.allowedHosts,
      activeTestingAllowed: scan.scopeVersion.activeTestingAllowed,
      authorizedBy: scan.scopeVersion.authorizedBy,
      authorizedAt: scan.scopeVersion.authorizedAt,
    },
    findings: scan.findings.map((f: any) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      confidence: f.confidence,
      verification: f.verification,
      riskScore: f.riskScore,
      cwe: f.cwe,
      owaspCategory: f.owaspCategory,
      affectedEndpoint: f.affectedEndpoint,
      rootCause: f.rootCause,
      impact: f.impact,
      remediation: f.remediation,
      reproduction: f.reproduction,
      references: f.references,
      occurrences: f.occurrences,
      evidence: f.evidence.map((e: any) => ({ description: e.description, detail: e.detail })),
    })),
  };
}

function buildMarkdown(scan: NonNullable<Awaited<ReturnType<typeof loadReportData>>>, summary: ReturnType<typeof summarizeSeverity>) {
  const lines: string[] = [];
  lines.push(`# Security Assessment Report — ${scan.project.name}`);
  lines.push("");
  lines.push(`**Scan ID:** ${scan.id}  `);
  lines.push(`**Profile:** ${scan.profile}  `);
  lines.push(`**Environment:** ${scan.scopeVersion.environment}  `);
  lines.push(`**Started:** ${scan.startedAt?.toISOString() ?? "—"}  `);
  lines.push(`**Completed:** ${scan.completedAt?.toISOString() ?? "—"}  `);
  lines.push(`**Requests issued:** ${scan.requestCount}`);
  lines.push("");
  lines.push("## Risk summary");
  lines.push("");
  lines.push(`| Critical | High | Medium | Low | Info |`);
  lines.push(`|---|---|---|---|---|`);
  lines.push(`| ${summary.critical} | ${summary.high} | ${summary.medium} | ${summary.low} | ${summary.info} |`);
  lines.push("");
  lines.push("## Scope authorization");
  lines.push("");
  lines.push(`Authorized by **${scan.scopeVersion.authorizedBy.name}** (${scan.scopeVersion.authorizedBy.email}) on ${scan.scopeVersion.authorizedAt.toISOString()}.`);
  lines.push(`Active testing: ${scan.scopeVersion.activeTestingAllowed ? "permitted" : "not permitted (passive-only scan)"}.`);
  lines.push("");

  for (const sev of ["critical", "high", "medium", "low", "info"] as const) {
    const findings = scan.findings.filter((f: any) => f.severity === sev);
    if (findings.length === 0) continue;
    lines.push(`## ${capitalize(sev)} findings`);
    lines.push("");
    for (const f of findings) {
      lines.push(`### ${f.title}`);
      lines.push("");
      lines.push(`- **Affected endpoint:** ${f.affectedEndpoint}`);
      lines.push(`- **Confidence:** ${f.confidence} · **Verification:** ${f.verification} · **Occurrences:** ${f.occurrences}`);
      if (f.cwe) lines.push(`- **CWE:** ${f.cwe}`);
      if (f.owaspCategory) lines.push(`- **OWASP:** ${f.owaspCategory}`);
      lines.push("");
      lines.push(`**Root cause:** ${f.rootCause}`);
      lines.push("");
      lines.push(`**Impact:** ${f.impact}`);
      lines.push("");
      lines.push(`**Remediation:** ${f.remediation}`);
      lines.push("");
      lines.push(`**Reproduction:** ${f.reproduction}`);
      lines.push("");
    }
  }
  return lines.join("\n");
}

function buildCsv(scan: NonNullable<Awaited<ReturnType<typeof loadReportData>>>) {
  const header = ["id", "title", "severity", "confidence", "verification", "riskScore", "affectedEndpoint", "cwe", "owaspCategory"];
  const rows = scan.findings.map((f: any) =>
    [f.id, f.title, f.severity, f.confidence, f.verification, f.riskScore, f.affectedEndpoint, f.cwe ?? "", f.owaspCategory ?? ""]
      .map(csvEscape)
      .join(","),
  );
  return [header.join(","), ...rows].join("\n");
}

function csvEscape(value: unknown): string {
  const s = String(value ?? "");
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
