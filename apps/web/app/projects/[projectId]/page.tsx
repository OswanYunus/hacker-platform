"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { api } from "@/lib/api";
import { AppShell } from "@/components/AppShell";
import { projectNavItems } from "@/lib/projectNav";
import { ScopeSummary } from "@/components/ScopeSummary";
import { Panel, PanelHeader, StatCard, Button } from "@/components/ui";

interface ProjectDetail {
  id: string;
  name: string;
  description?: string;
  targets: Array<{ id: string; type: string; value: string }>;
  scopeVersions: Array<{
    environment: string;
    allowedHosts: string[];
    activeTestingAllowed: boolean;
    authorizedBy: { name: string };
    authorizedAt: string;
    isActive: boolean;
  }>;
  scans: Array<{ id: string; status: string; profile: string; createdAt: string }>;
  _count: { findings: number };
}

export default function ProjectOverviewPage() {
  const params = useParams<{ projectId: string }>();
  const [project, setProject] = useState<ProjectDetail | null>(null);
  const nav = projectNavItems(params.projectId);

  useEffect(() => {
    api.get<{ project: ProjectDetail }>(`/api/projects/${params.projectId}`).then((r) => setProject(r.project));
  }, [params.projectId]);

  if (!project) {
    return (
      <AppShell projectNav={nav} activeHref={nav.base}>
        <div className="p-8 text-sm text-ink-600">Loading…</div>
      </AppShell>
    );
  }

  const activeScope = project.scopeVersions.find((s) => s.isActive);
  const runningScan = project.scans.find((s) => s.status === "RUNNING" || s.status === "QUEUED");

  return (
    <AppShell projectNav={nav} activeHref={nav.base}>
      <div className="mx-auto max-w-5xl space-y-5 px-8 py-8">
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-lg font-semibold text-ink-950">{project.name}</h1>
            {project.description && <p className="mt-1 text-sm text-ink-600">{project.description}</p>}
          </div>
          <Link href={`/projects/${params.projectId}/scans`}>
            <Button disabled={!activeScope}>Start scan</Button>
          </Link>
        </div>

        <ScopeSummary
          scope={
            activeScope
              ? {
                  environment: activeScope.environment,
                  allowedHosts: activeScope.allowedHosts,
                  activeTestingAllowed: activeScope.activeTestingAllowed,
                  authorizedByName: activeScope.authorizedBy.name,
                  authorizedAt: activeScope.authorizedAt,
                }
              : null
          }
        />
        {!activeScope && (
          <p className="text-xs text-ink-600">
            <Link href={`/projects/${params.projectId}/scope`} className="font-medium text-ink-900 underline">
              Configure authorized scope
            </Link>{" "}
            before starting a scan.
          </p>
        )}

        {runningScan && (
          <Link
            href={`/projects/${params.projectId}/scans/${runningScan.id}`}
            className="block rounded-md border border-[#B9CEE0] bg-[#DCE6EF] px-4 py-3 text-sm text-[#204163] hover:bg-[#CFE0EE]"
          >
            A scan is currently {runningScan.status.toLowerCase()} — view live progress →
          </Link>
        )}

        <div className="grid grid-cols-3 gap-3">
          <StatCard label="Targets" value={project.targets.length} />
          <StatCard label="Scans run" value={project.scans.length} />
          <StatCard label="Open findings" value={project._count.findings} />
        </div>

        <Panel>
          <PanelHeader
            title="Targets"
            action={<Link href={`/projects/${params.projectId}/scope`} className="text-xs text-ink-700 underline">Manage in Scope</Link>}
          />
          <table className="data-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              {project.targets.length === 0 && (
                <tr>
                  <td colSpan={2} className="py-6 text-center text-ink-600">
                    No targets yet.
                  </td>
                </tr>
              )}
              {project.targets.map((t) => (
                <tr key={t.id}>
                  <td>{t.type}</td>
                  <td className="mono">{t.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>

        <Panel>
          <PanelHeader title="Recent scans" action={<Link href={`/projects/${params.projectId}/scans`} className="text-xs text-ink-700 underline">View all</Link>} />
          <table className="data-table">
            <thead>
              <tr>
                <th>Started</th>
                <th>Profile</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {project.scans.slice(0, 5).map((s) => (
                <tr key={s.id}>
                  <td>
                    <Link href={`/projects/${params.projectId}/scans/${s.id}`} className="hover:underline">
                      {new Date(s.createdAt).toLocaleString()}
                    </Link>
                  </td>
                  <td>{s.profile}</td>
                  <td>
                    <StatusPill status={s.status} />
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

function StatusPill({ status }: { status: string }) {
  const colors: Record<string, string> = {
    QUEUED: "text-ink-600",
    RUNNING: "text-[#204163]",
    COMPLETED: "text-[#2E6B1F]",
    FAILED: "text-[#A4221B]",
    CANCELLED: "text-ink-600",
  };
  return <span className={colors[status] ?? "text-ink-600"}>{status}</span>;
}
