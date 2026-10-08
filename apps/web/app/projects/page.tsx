"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { api } from "@/lib/api";
import { AppShell } from "@/components/AppShell";
import { Button, Field, inputClass, Panel, PanelHeader } from "@/components/ui";

interface ProjectSummary {
  id: string;
  name: string;
  description?: string;
  organizationId: string;
  _count: { scans: number; findings: number };
  scopeVersions: Array<{ environment: string; activeTestingAllowed: boolean }>;
}

interface Organization {
  id: string;
  name: string;
  role: string;
}

export default function ProjectsPage() {
  const router = useRouter();
  const [projects, setProjects] = useState<ProjectSummary[] | null>(null);
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState({ name: "", description: "" });

  useEffect(() => {
    api
      .get<{ user: unknown; organizations: Organization[] }>("/api/auth/me")
      .then((me) => setOrganizations(me.organizations))
      .catch(() => router.push("/login"));
    api.get<{ projects: ProjectSummary[] }>("/api/projects").then((r) => setProjects(r.projects));
  }, [router]);

  async function createProject(e: React.FormEvent) {
    e.preventDefault();
    if (!organizations[0]) return;
    const { project } = await api.post<{ project: ProjectSummary }>("/api/projects", {
      ...form,
      organizationId: organizations[0].id,
    });
    router.push(`/projects/${project.id}/scope`);
  }

  return (
    <AppShell activeHref="/projects">
      <div className="mx-auto max-w-5xl px-8 py-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold text-ink-950">Projects</h1>
            <p className="mt-1 text-sm text-ink-600">Each project holds one authorized target scope and its scan history.</p>
          </div>
          <Button onClick={() => setCreating(true)}>New project</Button>
        </div>

        {creating && (
          <Panel className="mt-5">
            <PanelHeader title="New project" subtitle="You'll define the authorized scope on the next step." />
            <form onSubmit={createProject} className="space-y-4 p-4">
              <Field label="Project name">
                <input required className={inputClass} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </Field>
              <Field label="Description" hint="Optional.">
                <textarea className={inputClass} rows={2} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
              </Field>
              <div className="flex gap-2">
                <Button type="submit">Create project</Button>
                <Button variant="secondary" onClick={() => setCreating(false)}>
                  Cancel
                </Button>
              </div>
            </form>
          </Panel>
        )}

        <Panel className="mt-5">
          <table className="data-table">
            <thead>
              <tr>
                <th>Project</th>
                <th>Environment</th>
                <th>Active testing</th>
                <th>Scans</th>
                <th>Findings</th>
              </tr>
            </thead>
            <tbody>
              {projects?.length === 0 && (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-sm text-ink-600">
                    No projects yet. Create one to define an authorized scope and start scanning.
                  </td>
                </tr>
              )}
              {projects?.map((p) => {
                const scope = p.scopeVersions[0];
                return (
                  <tr key={p.id}>
                    <td>
                      <Link href={`/projects/${p.id}`} className="font-medium text-ink-900 hover:underline">
                        {p.name}
                      </Link>
                      {p.description && <div className="text-2xs text-ink-600">{p.description}</div>}
                    </td>
                    <td>{scope ? scope.environment : <span className="text-ink-600">No scope configured</span>}</td>
                    <td>{scope ? (scope.activeTestingAllowed ? "Yes" : "Passive only") : "—"}</td>
                    <td className="tabular-nums">{p._count.scans}</td>
                    <td className="tabular-nums">{p._count.findings}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </Panel>
      </div>
    </AppShell>
  );
}
