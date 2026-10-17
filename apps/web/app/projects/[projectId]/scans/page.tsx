"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { AppShell } from "@/components/AppShell";
import { projectNavItems } from "@/lib/projectNav";
import { Panel, PanelHeader, Button, Field, inputClass } from "@/components/ui";
import { api } from "@/lib/api";

interface ScanSummary {
  id: string;
  status: string;
  profile: string;
  createdAt: string;
  requestCount: number;
  _count: { findings: number };
  triggeredBy: { name: string };
}

interface AuthProfile {
  id: string;
  roleLabel: string;
  mechanism: string;
}

const PROFILE_DESCRIPTIONS: Record<string, string> = {
  QUICK: "Fast scan, ~25 pages. Active checks run only when the authorized scope permits them.",
  STANDARD: "Normal assessment depth, ~100 pages. Active checks require owner/admin authorization and DNS control proof by default.",
  DEEP: "Expanded crawl, up to 400 pages and 6 links deep. Requires active-testing authorization and DNS control proof by default.",
  CI: "Fast, regression-oriented — tuned for pipeline gating.",
};

const STATUS_COLORS: Record<string, string> = {
  QUEUED: "text-ink-600",
  RUNNING: "text-[#204163] font-medium",
  COMPLETED: "text-[#2E6B1F]",
  FAILED: "text-[#A4221B]",
  CANCELLED: "text-ink-500",
};

export default function ScansPage() {
  const params = useParams<{ projectId: string }>();
  const router = useRouter();
  const nav = projectNavItems(params.projectId);
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [profile, setProfile] = useState("STANDARD");
  const [authProfiles, setAuthProfiles] = useState<AuthProfile[]>([]);
  const [authConfigId, setAuthConfigId] = useState("");
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [clearing, setClearing] = useState(false);

  function reload() {
    api.get<{ scans: ScanSummary[] }>(`/api/projects/${params.projectId}/scans`).then((r) => setScans(r.scans));
  }
  useEffect(() => {
    reload();
    api.get<{ project: { authConfigs: AuthProfile[] } }>(`/api/projects/${params.projectId}`)
      .then((r) => setAuthProfiles(r.project.authConfigs))
      .catch(() => setAuthProfiles([]));
  }, [params.projectId]);

  async function startScan() {
    setStarting(true);
    setError(null);
    try {
      const { scan } = await api.post<{ scan: { id: string } }>(`/api/projects/${params.projectId}/scans`, {
        profile,
        ...(authConfigId ? { authConfigId } : {}),
      });
      router.push(`/projects/${params.projectId}/scans/${scan.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start scan.");
      setStarting(false);
    }
  }

  async function deleteSingleScan(scanId: string) {
    if (!window.confirm("Delete this scan and all its findings?")) return;
    setDeletingId(scanId);
    try {
      await api.delete(`/api/scans/${scanId}`);
      setScans((prev) => prev.filter((s) => s.id !== scanId));
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to delete scan");
    } finally {
      setDeletingId(null);
    }
  }

  async function clearPastScans() {
    const finishedCount = scans.filter((s) => s.status !== "RUNNING" && s.status !== "QUEUED").length;
    if (finishedCount === 0) return;
    if (!window.confirm(`Clear all ${finishedCount} finished scans?`)) return;
    setClearing(true);
    try {
      await api.delete(`/api/projects/${params.projectId}/scans`);
      setScans((prev) => prev.filter((s) => s.status === "RUNNING" || s.status === "QUEUED"));
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to clear scans");
    } finally {
      setClearing(false);
    }
  }

  const counts = useMemo(() => {
    return {
      ALL: scans.length,
      RUNNING: scans.filter((s) => s.status === "RUNNING" || s.status === "QUEUED").length,
      COMPLETED: scans.filter((s) => s.status === "COMPLETED").length,
      FAILED: scans.filter((s) => s.status === "FAILED" || s.status === "CANCELLED").length,
    };
  }, [scans]);

  const filteredScans = useMemo(() => {
    if (statusFilter === "ALL") return scans;
    if (statusFilter === "RUNNING") return scans.filter((s) => s.status === "RUNNING" || s.status === "QUEUED");
    if (statusFilter === "COMPLETED") return scans.filter((s) => s.status === "COMPLETED");
    if (statusFilter === "FAILED") return scans.filter((s) => s.status === "FAILED" || s.status === "CANCELLED");
    return scans;
  }, [scans, statusFilter]);

  const hasFinishedScans = scans.some((s) => s.status !== "RUNNING" && s.status !== "QUEUED");

  return (
    <AppShell projectNav={nav} activeHref={`${nav.base}/scans`}>
      <div className="mx-auto max-w-5xl space-y-6 px-8 py-8">
        <div>
          <h1 className="text-lg font-semibold text-ink-950">Scans</h1>
          <p className="mt-1 text-sm text-ink-600">Start new security scans or inspect past runs.</p>
        </div>

        <Panel>
          <PanelHeader title="Start a new scan" />
          <div className="space-y-3 p-4">
            <Field label="Scan profile">
              <select className={inputClass} value={profile} onChange={(e) => setProfile(e.target.value)}>
                <option value="QUICK">Quick</option>
                <option value="STANDARD">Standard</option>
                <option value="DEEP">Deep</option>
                <option value="CI">CI</option>
              </select>
            </Field>
            <p className="text-xs text-ink-600">{PROFILE_DESCRIPTIONS[profile]}</p>
            <Field label="Authorized test role" hint="Optional. Select a dedicated owner-provided role to compare protected API routes with anonymous access.">
              <select className={inputClass} value={authConfigId} onChange={(e) => setAuthConfigId(e.target.value)}>
                <option value="">Unauthenticated scan</option>
                {authProfiles.map((auth) => (
                  <option key={auth.id} value={auth.id}>{auth.roleLabel} · {auth.mechanism}</option>
                ))}
              </select>
            </Field>
            {error && <p className="text-xs text-[#A4221B]">{error}</p>}
            <Button onClick={startScan} disabled={starting}>
              {starting ? "Starting…" : "Start scan"}
            </Button>
          </div>
        </Panel>

        <Panel>
          <PanelHeader
            title="Scan history"
            action={
              hasFinishedScans ? (
                <button
                  onClick={clearPastScans}
                  disabled={clearing}
                  className="text-xs text-ink-600 underline hover:text-[#A4221B]"
                >
                  {clearing ? "Clearing…" : "Clear finished scans"}
                </button>
              ) : undefined
            }
          />

          {/* Clean hairline sub-tabs */}
          <div className="flex border-b border-paper-200 px-4">
            <nav className="flex gap-4">
              {[
                { id: "ALL", label: "All" },
                { id: "RUNNING", label: "Running" },
                { id: "COMPLETED", label: "Completed" },
                { id: "FAILED", label: "Failed / Cancelled" },
              ].map((tab) => {
                const count = counts[tab.id as keyof typeof counts] ?? 0;
                const active = statusFilter === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setStatusFilter(tab.id)}
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
          </div>

          <table className="data-table">
            <thead>
              <tr>
                <th>Started</th>
                <th>Profile</th>
                <th>Triggered by</th>
                <th>Requests</th>
                <th>Findings</th>
                <th>Status</th>
                <th className="text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredScans.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-ink-600">
                    {statusFilter === "ALL" ? "No scans yet." : `No ${statusFilter.toLowerCase()} scans.`}
                  </td>
                </tr>
              )}
              {filteredScans.map((s) => (
                <tr key={s.id}>
                  <td className="whitespace-nowrap">
                    <Link href={`/projects/${params.projectId}/scans/${s.id}`} className="hover:underline">
                      {new Date(s.createdAt).toLocaleString(undefined, {
                        month: "short",
                        day: "numeric",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </Link>
                  </td>
                  <td>{s.profile}</td>
                  <td>{s.triggeredBy?.name ?? "—"}</td>
                  <td className="tabular-nums">{s.requestCount}</td>
                  <td className="tabular-nums">
                    {s._count.findings > 0 ? (
                      <span className="font-semibold text-[#A4221B]">{s._count.findings}</span>
                    ) : (
                      "0"
                    )}
                  </td>
                  <td>
                    <span className={STATUS_COLORS[s.status] ?? "text-ink-600"}>
                      {s.status}
                    </span>
                  </td>
                  <td className="whitespace-nowrap text-right">
                    <div className="inline-flex items-center gap-3">
                      <Link
                        href={`/projects/${params.projectId}/scans/${s.id}`}
                        className="text-xs text-ink-700 underline"
                      >
                        View
                      </Link>
                      <button
                        onClick={() => deleteSingleScan(s.id)}
                        disabled={deletingId === s.id}
                        className="text-xs text-ink-600 underline hover:text-[#A4221B]"
                      >
                        {deletingId === s.id ? "…" : "Delete"}
                      </button>
                    </div>
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
