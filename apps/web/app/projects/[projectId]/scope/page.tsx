"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { AppShell } from "@/components/AppShell";
import { projectNavItems } from "@/lib/projectNav";
import { ScopeSummary } from "@/components/ScopeSummary";
import { Panel, PanelHeader, Button, Field, inputClass } from "@/components/ui";
import { api } from "@/lib/api";

interface Target {
  id: string;
  type: string;
  value: string;
  verificationRecordName?: string | null;
  verifiedAt?: string | null;
}

interface DnsChallenge {
  recordName: string;
  value: string;
}

interface ScopeVersion {
  id: string;
  environment: string;
  allowedHosts: string[];
  allowedPaths?: string[];
  excludedPaths?: string[];
  allowedIpRanges?: string[];
  activeTestingAllowed: boolean;
  authorizedBy: { name: string };
  authorizedAt: string;
  isActive: boolean;
  maxRequestsPerSecond: number;
  maxScanDurationSeconds: number;
  maxTotalRequests: number;
  authorizationStatement: string;
}

interface AuthConfigSummary {
  id: string;
  roleLabel: string;
  mechanism: string;
  loginUrl?: string | null;
  createdAt: string;
}

export default function ScopePage() {
  const params = useParams<{ projectId: string }>();
  const verificationStorageKey = `dns-verification-challenges:${params.projectId}`;
  const nav = projectNavItems(params.projectId);
  const [targets, setTargets] = useState<Target[]>([]);
  const [scopeHistory, setScopeHistory] = useState<ScopeVersion[]>([]);
  const [authConfigs, setAuthConfigs] = useState<AuthConfigSummary[]>([]);
  const [authForm, setAuthForm] = useState({ roleLabel: "test-user", mechanism: "BEARER_TOKEN", loginUrl: "", secretValue: "" });
  const [authError, setAuthError] = useState<string | null>(null);
  const [newTarget, setNewTarget] = useState({ type: "DOMAIN", value: "" });
  const [form, setForm] = useState({
    allowedHosts: "",
    allowedPaths: "",
    excludedPaths: "",
    environment: "STAGING",
    activeTestingAllowed: false,
    maxRequestsPerSecond: 2,
    maxScanDurationSeconds: 1800,
    maxTotalRequests: 2000,
    authorizationStatement: "",
  });
  const [saved, setSaved] = useState(false);

  function reload() {
    api.get<{ project: { targets: Target[]; scopeVersions: ScopeVersion[]; authConfigs: AuthConfigSummary[] } }>(`/api/projects/${params.projectId}`).then((r) => {
      setTargets(r.project.targets);
      setScopeHistory(r.project.scopeVersions);
      setAuthConfigs(r.project.authConfigs);
    });
  }

  useEffect(() => {
    reload();
    setVerificationChallenges({});
    try {
      const savedChallenges = sessionStorage.getItem(verificationStorageKey);
      if (savedChallenges) {
        const parsed = JSON.parse(savedChallenges) as Record<string, DnsChallenge>;
        const valid = Object.fromEntries(
          Object.entries(parsed).filter(([, challenge]) =>
            typeof challenge?.recordName === "string" && typeof challenge?.value === "string",
          ),
        );
        setVerificationChallenges(valid);
      }
    } catch {
      sessionStorage.removeItem(verificationStorageKey);
    }
  }, [params.projectId]);

  const activeScope = scopeHistory.find((s) => s.isActive);

  const [editingTargetId, setEditingTargetId] = useState<string | null>(null);
  const [editTargetForm, setEditTargetForm] = useState({ type: "DOMAIN", value: "" });
  const [targetError, setTargetError] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [verificationChallenges, setVerificationChallenges] = useState<Record<string, DnsChallenge>>({});
  const [checkingVerificationId, setCheckingVerificationId] = useState<string | null>(null);

  function clearVerificationChallenge(targetId: string) {
    const next = { ...verificationChallenges };
    delete next[targetId];
    setVerificationChallenges(next);
    try {
      if (Object.keys(next).length > 0) sessionStorage.setItem(verificationStorageKey, JSON.stringify(next));
      else sessionStorage.removeItem(verificationStorageKey);
    } catch {
      // The in-memory challenge remains usable if browser storage is unavailable.
    }
  }

  async function addTarget(e: React.FormEvent) {
    e.preventDefault();
    setTargetError(null);
    try {
      await api.post(`/api/projects/${params.projectId}/targets`, newTarget);
      setNewTarget({ type: "DOMAIN", value: "" });
      reload();
    } catch (err: any) {
      setTargetError(err.message || "Failed to add target");
    }
  }

  function startEdit(t: Target) {
    setEditingTargetId(t.id);
    setEditTargetForm({ type: t.type, value: t.value });
    setTargetError(null);
  }

  function cancelEdit() {
    setEditingTargetId(null);
    setTargetError(null);
  }

  async function saveEditTarget(targetId: string) {
    setTargetError(null);
    try {
      await api.patch(`/api/projects/${params.projectId}/targets/${targetId}`, editTargetForm);
      clearVerificationChallenge(targetId);
      setEditingTargetId(null);
      reload();
    } catch (err: any) {
      setTargetError(err.message || "Failed to update target");
    }
  }

  async function deleteTarget(targetId: string) {
    if (!confirm("Are you sure you want to remove this target?")) return;
    if (isDeleting) return;
    setIsDeleting(true);
    setTargetError(null);
    setTargets((prev) => prev.filter((t) => t.id !== targetId));
    clearVerificationChallenge(targetId);
    try {
      await api.delete(`/api/projects/${params.projectId}/targets/${targetId}`);
    } catch (err: any) {
      setTargetError(err.message || "Failed to delete target");
    } finally {
      setIsDeleting(false);
      reload();
    }
  }

  async function startTargetVerification(targetId: string) {
    setTargetError(null);
    try {
      const result = await api.post<{ verification: DnsChallenge }>(
        `/api/projects/${params.projectId}/targets/${targetId}/verification`,
      );
      setVerificationChallenges((current) => ({ ...current, [targetId]: result.verification }));
      try {
        const saved = JSON.parse(sessionStorage.getItem(verificationStorageKey) || "{}");
        sessionStorage.setItem(verificationStorageKey, JSON.stringify({ ...saved, [targetId]: result.verification }));
      } catch {
        // The returned challenge remains available in the current page session.
      }
      reload();
    } catch (err) {
      setTargetError(err instanceof Error ? err.message : "Could not create DNS verification record.");
    }
  }

  async function checkTargetVerification(targetId: string) {
    setCheckingVerificationId(targetId);
    setTargetError(null);
    try {
      await api.post(`/api/projects/${params.projectId}/targets/${targetId}/verification/check`);
      clearVerificationChallenge(targetId);
      reload();
    } catch (err) {
      setTargetError(err instanceof Error ? err.message : "The DNS verification record was not found yet.");
    } finally {
      setCheckingVerificationId(null);
    }
  }

  async function saveScope(e: React.FormEvent) {
    e.preventDefault();
    await api.post(`/api/projects/${params.projectId}/scope`, {
      allowedHosts: form.allowedHosts.split(",").map((s) => s.trim()).filter(Boolean),
      allowedPaths: form.allowedPaths.split(",").map((s) => s.trim()).filter(Boolean),
      excludedPaths: form.excludedPaths.split(",").map((s) => s.trim()).filter(Boolean),
      environment: form.environment,
      activeTestingAllowed: form.activeTestingAllowed,
      maxRequestsPerSecond: Number(form.maxRequestsPerSecond),
      maxScanDurationSeconds: Number(form.maxScanDurationSeconds),
      maxTotalRequests: Number(form.maxTotalRequests),
      authorizationStatement: form.authorizationStatement,
    });
    setSaved(true);
    reload();
  }

  async function saveAuthConfig(e: React.FormEvent) {
    e.preventDefault();
    setAuthError(null);
    try {
      await api.post(`/api/projects/${params.projectId}/auth-configs`, {
        ...authForm,
        loginUrl: authForm.loginUrl || undefined,
      });
      setAuthForm({ ...authForm, secretValue: "" });
      reload();
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : "Could not save test role.");
    }
  }

  async function resetActiveScope() {
    if (!confirm("Are you sure you want to deactivate and remove the active scope for this project? No scans will be allowed until a new scope is defined.")) {
      return;
    }
    try {
      await api.delete(`/api/projects/${params.projectId}/scope`);
      reload();
    } catch (err: any) {
      alert(err.message || "Failed to reset scope");
    }
  }

  return (
    <AppShell projectNav={nav} activeHref={`${nav.base}/scope`}>
      <div className="mx-auto max-w-3xl space-y-6 px-8 py-8">
        <div>
          <h1 className="text-lg font-semibold text-ink-950">Scope &amp; authorization</h1>
          <p className="mt-1 text-sm text-ink-600">
            A scan can only touch what is explicitly authorized here. Saving creates a new, immutable scope version and
            is recorded in the audit trail with your identity and timestamp.
          </p>
        </div>

        <ScopeSummary
          scope={
            activeScope
              ? {
                  environment: activeScope.environment,
                  allowedHosts: activeScope.allowedHosts,
                  allowedPaths: activeScope.allowedPaths,
                  excludedPaths: activeScope.excludedPaths,
                  allowedIpRanges: activeScope.allowedIpRanges,
                  activeTestingAllowed: activeScope.activeTestingAllowed,
                  authorizedByName: activeScope.authorizedBy?.name,
                  authorizedAt: activeScope.authorizedAt,
                  maxRequestsPerSecond: activeScope.maxRequestsPerSecond,
                  maxScanDurationSeconds: activeScope.maxScanDurationSeconds,
                  maxTotalRequests: activeScope.maxTotalRequests,
                  authorizationStatement: activeScope.authorizationStatement,
                }
              : null
          }
          onResetScope={activeScope ? resetActiveScope : undefined}
        />

        <Panel>
          <PanelHeader title="Targets" subtitle="Prove domain control before scanning. The proof is checked again when each scan starts." />
          <div className="p-4">
            {targetError && (
              <div className="mb-3 rounded border border-[#A4221B]/30 bg-red-50 px-3 py-2 text-xs font-medium text-[#A4221B]">
                {targetError}
              </div>
            )}
            <table className="data-table mb-3">
              <thead>
                <tr>
                  <th className="w-32">Type</th>
                  <th>Value</th>
                  <th className="w-40">DNS control</th>
                  <th className="w-48 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {targets.map((t) => (
                  <tr key={t.id}>
                    {editingTargetId === t.id ? (
                      <>
                        <td className="w-32">
                          <select
                            className={inputClass}
                            value={editTargetForm.type}
                            onChange={(e) => setEditTargetForm({ ...editTargetForm, type: e.target.value })}
                          >
                            <option value="DOMAIN">Domain</option>
                            <option value="URL">URL</option>
                            <option value="API_ENDPOINT">API endpoint</option>
                            <option value="IP_RANGE">IP range</option>
                          </select>
                        </td>
                        <td colSpan={2}>
                          <input
                            required
                            className={inputClass}
                            value={editTargetForm.value}
                            onChange={(e) => setEditTargetForm({ ...editTargetForm, value: e.target.value })}
                          />
                        </td>
                        <td className="text-right space-x-2">
                          <button
                            type="button"
                            onClick={() => saveEditTarget(t.id)}
                            className="text-xs font-semibold text-ink-950 hover:underline"
                          >
                            Save
                          </button>
                          <button
                            type="button"
                            onClick={cancelEdit}
                            className="text-xs text-ink-600 hover:underline"
                          >
                            Cancel
                          </button>
                        </td>
                      </>
                    ) : (
                      <>
                        <td className="w-32">{t.type}</td>
                        <td className="mono">{t.value}</td>
                        <td>
                          {t.verifiedAt ? (
                            <span className="text-xs font-medium text-[#2E6B1F]">Verified · {new Date(t.verifiedAt).toLocaleDateString()}</span>
                          ) : (
                            <span className="text-xs text-ink-600">Not verified</span>
                          )}
                        </td>
                        <td className="text-right space-x-3">
                          <button
                            type="button"
                            onClick={() => startTargetVerification(t.id)}
                            className="text-xs font-semibold text-ink-950 hover:underline"
                          >
                            {t.verificationRecordName ? "New proof" : "Verify"}
                          </button>
                          <button
                            type="button"
                            onClick={() => startEdit(t)}
                            className="text-xs font-medium text-ink-700 hover:text-ink-950 hover:underline"
                          >
                            Edit
                          </button>
                          <button
                            type="button"
                            onClick={() => deleteTarget(t.id)}
                            className="text-xs font-medium text-[#A4221B] hover:underline"
                          >
                            Delete
                          </button>
                        </td>
                      </>
                    )}
                  </tr>
                ))}
                {targets.length === 0 && (
                  <tr>
                    <td colSpan={4} className="py-4 text-center text-ink-600">No targets added yet.</td>
                  </tr>
                )}
              </tbody>
            </table>
            {Object.entries(verificationChallenges).map(([targetId, challenge]) => (
              <div key={targetId} className="mb-4 rounded border border-paper-300 bg-paper-50 p-3 text-sm">
                <p className="font-semibold text-ink-950">Add this TXT record to your domain DNS</p>
                <p className="mt-1 text-xs text-ink-600">The scanner checks this record before each scan. DNS changes can take a few minutes to appear.</p>
                <p className="mt-1 text-xs text-ink-600">This proof is kept in this browser tab if you refresh the page.</p>
                <dl className="mt-3 grid gap-2 text-xs md:grid-cols-[90px_1fr]">
                  <dt className="font-medium">Record name</dt><dd className="break-all font-mono">{challenge.recordName}</dd>
                  <dt className="font-medium">Record type</dt><dd>TXT</dd>
                  <dt className="font-medium">Value</dt><dd className="break-all font-mono">{challenge.value}</dd>
                </dl>
                <div className="mt-3 flex items-center gap-2">
                  <Button type="button" variant="secondary" disabled={checkingVerificationId === targetId} onClick={() => checkTargetVerification(targetId)}>
                    {checkingVerificationId === targetId ? "Checking DNS…" : "Check DNS proof"}
                  </Button>
                  <button type="button" className="text-xs text-ink-600 hover:underline" onClick={() => clearVerificationChallenge(targetId)}>
                    Hide
                  </button>
                </div>
              </div>
            ))}
            <form onSubmit={addTarget} className="flex items-end gap-2">
              <Field label="Type">
                <select className={inputClass} value={newTarget.type} onChange={(e) => setNewTarget({ ...newTarget, type: e.target.value })}>
                  <option value="DOMAIN">Domain</option>
                  <option value="URL">URL</option>
                  <option value="API_ENDPOINT">API endpoint</option>
                  <option value="IP_RANGE">IP range</option>
                </select>
              </Field>
              <Field label="Value">
                <input
                  required
                  placeholder="staging.example.com"
                  className={inputClass}
                  value={newTarget.value}
                  onChange={(e) => setNewTarget({ ...newTarget, value: e.target.value })}
                />
              </Field>
              <Button type="submit" variant="secondary">
                Add target
              </Button>
            </form>
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Owner-provided test roles" subtitle="Use a dedicated account or session that you are authorized to use for this assessment." />
          <div className="space-y-4 p-4">
            <p className="text-xs text-ink-600">
              Credentials are encrypted at rest and never written to scan logs. The scanner only sends them to hosts and paths in the active authorized scope. Cookie and bearer-token profiles are supported.
            </p>
            {authConfigs.length > 0 && (
              <ul className="space-y-1 text-xs text-ink-700">
                {authConfigs.map((config) => (
                  <li key={config.id}>{config.roleLabel} · {config.mechanism}{config.loginUrl ? ` · ${config.loginUrl}` : ""}</li>
                ))}
              </ul>
            )}
            {authError && <p className="text-xs text-[#A4221B]">{authError}</p>}
            <form onSubmit={saveAuthConfig} className="grid gap-3 md:grid-cols-2">
              <Field label="Test role label" hint="For example: staging-admin or test-customer.">
                <input required className={inputClass} value={authForm.roleLabel} onChange={(e) => setAuthForm({ ...authForm, roleLabel: e.target.value })} />
              </Field>
              <Field label="Credential type">
                <select className={inputClass} value={authForm.mechanism} onChange={(e) => setAuthForm({ ...authForm, mechanism: e.target.value })}>
                  <option value="BEARER_TOKEN">Bearer token</option>
                  <option value="COOKIE">Session cookie</option>
                </select>
              </Field>
              <Field label="Login URL (optional)">
                <input type="url" className={inputClass} placeholder="https://staging.example.com/login" value={authForm.loginUrl} onChange={(e) => setAuthForm({ ...authForm, loginUrl: e.target.value })} />
              </Field>
              <Field label={authForm.mechanism === "COOKIE" ? "Cookie header value" : "Bearer token"}>
                <input required type="password" autoComplete="new-password" className={inputClass} value={authForm.secretValue} onChange={(e) => setAuthForm({ ...authForm, secretValue: e.target.value })} />
              </Field>
              <div className="md:col-span-2">
                <Button type="submit">Save test role</Button>
              </div>
            </form>
          </div>
        </Panel>

        <Panel>
          <PanelHeader title="Define authorized scope" />
          <form onSubmit={saveScope} className="space-y-4 p-4">
            <Field label="Authorized hosts" hint="Comma-separated. Supports *.sub.example.com wildcards.">
              <input
                required
                className={inputClass}
                placeholder="staging.example.com, *.staging.example.com"
                value={form.allowedHosts}
                onChange={(e) => setForm({ ...form, allowedHosts: e.target.value })}
              />
            </Field>

            <div className="grid grid-cols-2 gap-4">
              <Field label="Allowed paths" hint="Optional. Leave empty to allow all paths on authorized hosts.">
                <input className={inputClass} placeholder="/app, /api" value={form.allowedPaths} onChange={(e) => setForm({ ...form, allowedPaths: e.target.value })} />
              </Field>
              <Field label="Excluded paths" hint="Always blocked, even on an authorized host.">
                <input className={inputClass} placeholder="/billing, /admin/danger-zone" value={form.excludedPaths} onChange={(e) => setForm({ ...form, excludedPaths: e.target.value })} />
              </Field>
            </div>

            <Field label="Environment">
              <select className={inputClass} value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value })}>
                <option value="PRODUCTION">Production</option>
                <option value="STAGING">Staging</option>
                <option value="DEVELOPMENT">Development</option>
                <option value="OTHER">Other</option>
              </select>
            </Field>

            <label className="flex items-start gap-2 rounded-sm border border-paper-200 bg-paper-50 p-3 text-sm">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={form.activeTestingAllowed}
                onChange={(e) => setForm({ ...form, activeTestingAllowed: e.target.checked })}
              />
              <span>
                <span className="font-medium text-ink-900">Permit active testing.</span>{" "}
                <span className="text-ink-600">
                  When off, scans only run discovery and passive analysis. When on, active checks require an
                  organization owner/admin authorization statement. DNS control proof is also required by default;
                  the local operator can temporarily exempt exact test hostnames.
                </span>
              </span>
            </label>

            <div className="grid grid-cols-3 gap-4">
              <Field label="Max requests / second">
                <input
                  type="number"
                  min={0.1}
                  step={0.1}
                  className={inputClass}
                  value={form.maxRequestsPerSecond}
                  onChange={(e) => setForm({ ...form, maxRequestsPerSecond: Number(e.target.value) })}
                />
              </Field>
              <Field label="Max duration (seconds)">
                <input
                  type="number"
                  min={60}
                  className={inputClass}
                  value={form.maxScanDurationSeconds}
                  onChange={(e) => setForm({ ...form, maxScanDurationSeconds: Number(e.target.value) })}
                />
              </Field>
              <Field label="Max total requests">
                <input
                  type="number"
                  min={10}
                  className={inputClass}
                  value={form.maxTotalRequests}
                  onChange={(e) => setForm({ ...form, maxTotalRequests: Number(e.target.value) })}
                />
              </Field>
            </div>

            <Field label="Authorization statement" hint="Who approved testing this target, and how. Stored verbatim in the audit trail.">
              <textarea
                required
                minLength={20}
                rows={3}
                className={inputClass}
                placeholder="I am the engineering lead for this application and am authorized to test our staging environment under internal policy SEC-04."
                value={form.authorizationStatement}
                onChange={(e) => setForm({ ...form, authorizationStatement: e.target.value })}
              />
            </Field>

            <div className="flex items-center gap-3">
              <Button type="submit">Save &amp; authorize scope</Button>
              {saved && <span className="text-xs text-[#2E6B1F]">Saved.</span>}
            </div>
          </form>
        </Panel>

        <Panel>
          <PanelHeader title="Scope history" subtitle="Every version is immutable and attributed." />
          <table className="data-table">
            <thead>
              <tr>
                <th>Authorized</th>
                <th>By</th>
                <th>Environment</th>
                <th>Active testing</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {scopeHistory.map((s) => (
                <tr key={s.id}>
                  <td>{new Date(s.authorizedAt).toLocaleString()}</td>
                  <td>{s.authorizedBy.name}</td>
                  <td>{s.environment}</td>
                  <td>{s.activeTestingAllowed ? "Yes" : "No"}</td>
                  <td>{s.isActive ? <span className="text-[#2E6B1F]">Active</span> : "Superseded"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>
    </AppShell>
  );
}
