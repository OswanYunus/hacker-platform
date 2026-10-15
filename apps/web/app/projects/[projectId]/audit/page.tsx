"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { AppShell } from "@/components/AppShell";
import { projectNavItems } from "@/lib/projectNav";
import { Panel, PanelHeader } from "@/components/ui";
import { api } from "@/lib/api";

interface AuditEventRow {
  id: string;
  action: string;
  targetType: string;
  targetId: string;
  metadata: Record<string, unknown> | null;
  createdAt: string;
  actor: { name: string; email: string } | null;
  ipAddress?: string | null;
}

const ACTION_LABELS: Record<string, string> = {
  "project.created": "Project created",
  "project.updated": "Project updated",
  "project.deleted": "Project deleted",
  "project.archived": "Project archived",
  "scope.authorized": "Scope authorized",
  "scope.updated": "Scope updated",
  "target.added": "Target added",
  "target.updated": "Target updated",
  "target.removed": "Target removed",
  "scan.started": "Scan started",
  "scan.completed": "Scan completed",
  "scan.failed": "Scan failed",
  "scan.cancel_requested": "Scan cancel requested",
  "scan.cancelled": "Scan cancelled",
  "scan.deleted": "Scan deleted",
  "scans.cleared": "Scans cleared",
  "finding.remediation_updated": "Remediation updated",
  "auth_config.created": "Auth config created",
  "auth_config.updated": "Auth config updated",
  "auth_config.deleted": "Auth config deleted",
  "member.invited": "Member invited",
  "member.removed": "Member removed",
  "member.role_changed": "Member role changed",
};

function humanAction(action: string): string {
  return ACTION_LABELS[action] ?? action.replace(/[._]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

const META_KEY_LABELS: Record<string, string> = {
  profile: "Profile",
  triggerSource: "Trigger",
  findingCount: "Findings",
  requestCount: "Requests",
  stopReason: "Stop reason",
  allowedHosts: "Allowed hosts",
  activeTestingAllowed: "Active testing",
  environment: "Environment",
  authorizationStatement: "Auth statement",
  changes: "Changes",
  state: "State",
  note: "Note",
  type: "Type",
  value: "Value",
  reason: "Reason",
  clearedCount: "Cleared count",
};

function humanKey(key: string): string {
  return META_KEY_LABELS[key] ?? key.replace(/([A-Z])/g, " $1").replace(/^./, (c) => c.toUpperCase());
}

function humanValue(key: string, value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) return value.join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  const str = String(value);
  if (key === "stopReason") return str.replace(/_/g, " ");
  if (key === "state") {
    const states: Record<string, string> = {
      OPEN: "Open",
      IN_PROGRESS: "In progress",
      RESOLVED: "Resolved",
      ACCEPTED_RISK: "Accepted risk",
      FALSE_POSITIVE: "False positive",
    };
    return states[str] ?? str;
  }
  return str;
}

export default function AuditPage() {
  const params = useParams<{ projectId: string }>();
  const nav = projectNavItems(params.projectId);
  const [events, setEvents] = useState<AuditEventRow[]>([]);
  const [category, setCategory] = useState<string>("ALL");
  const [search, setSearch] = useState("");
  const [clearing, setClearing] = useState(false);

  useEffect(() => {
    api
      .get<{ events: AuditEventRow[] }>(`/api/projects/${params.projectId}/audit-trail`)
      .then((r) => setEvents(r.events));
  }, [params.projectId]);

  async function clearAuditTrail() {
    if (events.length === 0) return;
    if (!window.confirm("Clear all audit records for this project?")) return;
    setClearing(true);
    try {
      await api.delete(`/api/projects/${params.projectId}/audit-trail`);
      setEvents([]);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Could not clear audit trail");
    } finally {
      setClearing(false);
    }
  }

  const counts = {
    ALL: events.length,
    SCANS: events.filter((e) => e.action.startsWith("scan")).length,
    SCOPE: events.filter((e) => e.action.startsWith("scope") || e.action.startsWith("target")).length,
    REMEDIATION: events.filter((e) => e.action.startsWith("finding") || e.action.startsWith("auth") || e.action.startsWith("project")).length,
  };

  const filteredEvents = events.filter((e) => {
    if (category === "SCANS" && !e.action.startsWith("scan")) return false;
    if (category === "SCOPE" && !e.action.startsWith("scope") && !e.action.startsWith("target")) return false;
    if (category === "REMEDIATION" && !e.action.startsWith("finding") && !e.action.startsWith("auth") && !e.action.startsWith("project")) return false;

    if (search.trim()) {
      const q = search.toLowerCase();
      const matchAction = e.action.toLowerCase().includes(q) || humanAction(e.action).toLowerCase().includes(q);
      const matchActor = e.actor?.name.toLowerCase().includes(q) || e.actor?.email.toLowerCase().includes(q);
      const matchMeta = e.metadata ? JSON.stringify(e.metadata).toLowerCase().includes(q) : false;
      return matchAction || matchActor || matchMeta;
    }
    return true;
  });

  return (
    <AppShell projectNav={nav} activeHref={`${nav.base}/audit`}>
      <div className="mx-auto max-w-5xl space-y-5 px-8 py-8">
        <div>
          <h1 className="text-lg font-semibold text-ink-950">Audit trail</h1>
          <p className="mt-1 text-sm text-ink-600">
            Authorization-relevant actions recorded on this project.
          </p>
        </div>

        <Panel>
          <PanelHeader
            title="Activity log"
            action={
              events.length > 0 ? (
                <button
                  onClick={clearAuditTrail}
                  disabled={clearing}
                  className="text-xs text-ink-600 underline hover:text-[#A4221B]"
                >
                  {clearing ? "Clearing…" : "Clear audit trail"}
                </button>
              ) : undefined
            }
          />

          {/* Clean standard tab bar */}
          <div className="flex items-center justify-between border-b border-paper-200 px-4">
            <nav className="flex gap-4">
              {[
                { id: "ALL", label: "All" },
                { id: "SCANS", label: "Scans" },
                { id: "SCOPE", label: "Scope & Targets" },
                { id: "REMEDIATION", label: "Remediation & Config" },
              ].map((tab) => {
                const count = counts[tab.id as keyof typeof counts] ?? 0;
                const active = category === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setCategory(tab.id)}
                    className={`py-2 text-xs font-medium border-b-2 -mb-px transition-colors ${
                      active
                        ? "border-ink-900 text-ink-900"
                        : "border-transparent text-ink-600 hover:text-ink-900"
                    }`}
                  >
                    {tab.label} <span className="text-ink-400">({count})</span>
                  </button>
                );
              })}
            </nav>

            <div className="py-1.5">
              <input
                type="text"
                placeholder="Filter activity…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="rounded-sm border border-paper-200 bg-white px-2 py-1 text-xs text-ink-900 placeholder:text-ink-400 focus:border-ink-700 focus:outline-none"
              />
            </div>
          </div>

          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: "160px" }}>Date</th>
                <th style={{ width: "180px" }}>Actor</th>
                <th style={{ width: "160px" }}>Action</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.length === 0 && (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-ink-600">
                    {search ? "No matching audit records." : "No audit records found."}
                  </td>
                </tr>
              )}
              {filteredEvents.map((e) => (
                <tr key={e.id}>
                  {/* Date */}
                  <td className="whitespace-nowrap text-xs text-ink-600">
                    {new Date(e.createdAt).toLocaleString(undefined, {
                      month: "short",
                      day: "numeric",
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </td>

                  {/* Actor */}
                  <td className="text-xs">
                    {e.actor ? (
                      <div>
                        <span className="font-medium text-ink-900">{e.actor.name}</span>
                        <span className="block text-2xs text-ink-500">{e.actor.email}</span>
                      </div>
                    ) : (
                      <span className="text-ink-500">System</span>
                    )}
                  </td>

                  {/* Action — clean text, no box */}
                  <td className="text-xs font-medium text-ink-900">
                    {humanAction(e.action)}
                  </td>

                  {/* Details — clean text key/value lines, no box chips */}
                  <td className="text-xs text-ink-700">
                    {e.metadata && Object.keys(e.metadata).length > 0 ? (
                      <div className="space-y-0.5">
                        {Object.entries(e.metadata)
                          .filter(([k, v]) => k !== "scopeVersionId" && v !== null && v !== undefined && v !== "")
                          .map(([k, v]) => (
                            <div key={k} className="text-2xs">
                              <span className="font-medium text-ink-800">{humanKey(k)}:</span>{" "}
                              <span className="text-ink-600">{humanValue(k, v)}</span>
                            </div>
                          ))}
                      </div>
                    ) : (
                      <span className="text-ink-400">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>
    </AppShell>
  );
}
