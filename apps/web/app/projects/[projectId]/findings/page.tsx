"use client";

import { Fragment, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { AppShell } from "@/components/AppShell";
import { projectNavItems } from "@/lib/projectNav";
import { Panel, StatCard, inputClass } from "@/components/ui";
import { SeverityBadge, ConfidenceLabel } from "@/components/SeverityBadge";
import { api } from "@/lib/api";

interface FindingRow {
  id: string;
  title: string;
  severity: string;
  confidence: string;
  verification: string;
  riskScore: number;
  affectedEndpoint: string;
  cwe?: string;
  owaspCategory?: string;
  rootCause: string;
  impact: string;
  remediation: string;
  references: string[];
  occurrences: number;
  remediationStatus?: { state: string };
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export default function FindingsPage({ params }: { params: { projectId: string } }) {
  const nav = projectNavItems(params.projectId);
  const searchParams = useSearchParams();
  const scanId = searchParams.get("scanId") ?? undefined;
  const [findings, setFindings] = useState<FindingRow[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("all");

  useEffect(() => {
    const query = scanId ? `?scanId=${scanId}` : "";
    api.get<{ findings: FindingRow[] }>(`/api/projects/${params.projectId}/findings${query}`).then((r) => setFindings(r.findings));
  }, [params.projectId, scanId]);

  const counts = useMemo(() => {
    const c: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) if (f.remediationStatus?.state !== "FALSE_POSITIVE") c[f.severity]++;
    return c;
  }, [findings]);

  const visible = findings.filter((f) => severityFilter === "all" || f.severity === severityFilter);

  async function updateRemediation(findingId: string, state: string) {
    await api.patch(`/api/findings/${findingId}/remediation`, { state });
    setFindings((fs) => fs.map((f) => (f.id === findingId ? { ...f, remediationStatus: { state } } : f)));
  }

  return (
    <AppShell projectNav={nav} activeHref={`${nav.base}/findings`}>
      <div className="mx-auto max-w-5xl space-y-5 px-8 py-8">
        <h1 className="text-lg font-semibold text-ink-950">Findings{scanId ? " — this scan" : ""}</h1>

        <div className="grid grid-cols-5 gap-3">
          {SEVERITY_ORDER.map((sev) => (
            <StatCard key={sev} label={sev} value={counts[sev]} tone={sev === "critical" ? "critical" : sev === "high" ? "high" : "default"} />
          ))}
        </div>

        <div className="flex items-center gap-2">
          <label className="text-xs text-ink-600">Filter:</label>
          <select className={inputClass + " w-40"} value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
            <option value="all">All severities</option>
            {SEVERITY_ORDER.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>

        <Panel>
          <table className="data-table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Finding</th>
                <th>Confidence</th>
                <th>Risk</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {visible.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-ink-600">
                    No findings match this filter.
                  </td>
                </tr>
              )}
              {visible.map((f) => (
                <Fragment key={f.id}>
                  <tr className="cursor-pointer" onClick={() => setExpanded(expanded === f.id ? null : f.id)}>
                    <td>
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td>
                      <div className="font-medium text-ink-900">{f.title}</div>
                      <div className="mono text-2xs text-ink-600">{f.affectedEndpoint}</div>
                    </td>
                    <td>
                      <ConfidenceLabel confidence={f.confidence} />
                    </td>
                    <td className="tabular-nums">{f.riskScore}</td>
                    <td>
                      <select
                        className="rounded-sm border border-paper-200 bg-white px-1.5 py-0.5 text-2xs"
                        value={f.remediationStatus?.state ?? "OPEN"}
                        onClick={(e) => e.stopPropagation()}
                        onChange={(e) => updateRemediation(f.id, e.target.value)}
                      >
                        <option value="OPEN">Open</option>
                        <option value="IN_PROGRESS">In progress</option>
                        <option value="RESOLVED">Resolved</option>
                        <option value="ACCEPTED_RISK">Accepted risk</option>
                        <option value="FALSE_POSITIVE">False positive</option>
                      </select>
                    </td>
                  </tr>
                  {expanded === f.id && (
                    <tr>
                      <td colSpan={5} className="bg-paper-50">
                        <div className="space-y-2 p-3 text-xs">
                          <DetailRow label="Root cause" value={f.rootCause} />
                          <DetailRow label="Impact" value={f.impact} />
                          <DetailRow label="Remediation" value={f.remediation} />
                          {f.references?.length > 0 && (
                            <div>
                              <div className="font-medium text-ink-800">References</div>
                              <div className="flex flex-wrap gap-x-3 gap-y-1 text-ink-600">
                                {f.references.map((ref) => (
                                  <a
                                    key={ref}
                                    href={ref}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="underline hover:text-ink-900 break-all"
                                  >
                                    {ref.replace(/^https?:\/\//, "")}
                                  </a>
                                ))}
                              </div>
                            </div>
                          )}
                          <div className="flex gap-4 text-ink-600">
                            {f.cwe && <span>{f.cwe}</span>}
                            {f.owaspCategory && <span>{f.owaspCategory}</span>}
                            <span>{f.occurrences} occurrence(s)</span>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>
    </AppShell>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="font-medium text-ink-800">{label}</div>
      <div className="text-ink-700">{value}</div>
    </div>
  );
}
