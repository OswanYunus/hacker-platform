"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { AppShell } from "@/components/AppShell";
import { projectNavItems } from "@/lib/projectNav";
import { Panel, PanelHeader, Button } from "@/components/ui";
import { SeverityBadge } from "@/components/SeverityBadge";
import { api } from "@/lib/api";
import { SCAN_STAGES, type ScanEvent, type ScanStage, type Finding } from "@hacker/scanner-core/client";

const STAGE_LABELS: Record<ScanStage, string> = {
  scope_validation: "Scope validation",
  target_discovery: "Target discovery",
  crawling: "Application crawling",
  endpoint_discovery: "Endpoint discovery",
  technology_identification: "Technology identification",
  passive_analysis: "Passive analysis",
  auth_session_analysis: "Authentication & session analysis",
  active_testing: "Active security tests",
  finding_verification: "Finding verification",
  risk_scoring: "Risk scoring",
  report_generation: "Report generation",
};

interface ScanDetail {
  id: string;
  status: string;
  profile: string;
  requestCount: number;
  stopReason?: string;
}

export default function ScanLivePage() {
  const params = useParams<{ projectId: string; scanId: string }>();
  const nav = projectNavItems(params.projectId);
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [stageStatus, setStageStatus] = useState<Record<string, "pending" | "active" | "done">>({});
  const [findings, setFindings] = useState<Finding[]>([]);
  const [requestCount, setRequestCount] = useState(0);
  const [logLines, setLogLines] = useState<string[]>([]);
  const [done, setDone] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api.get<{ scan: ScanDetail }>(`/api/scans/${params.scanId}`).then((r) => {
      setScan(r.scan);
      if (r.scan.status === "COMPLETED" || r.scan.status === "FAILED" || r.scan.status === "CANCELLED") setDone(true);
    });

    const source = new EventSource(`/api/scans/${params.scanId}/events`);
    source.onmessage = (ev) => {
      const event: ScanEvent = JSON.parse(ev.data);
      handleEvent(event);
    };
    return () => source.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params.scanId]);

  function handleEvent(event: ScanEvent) {
    switch (event.type) {
      case "stage_started":
        setStageStatus((s) => ({ ...s, [event.stage]: "active" }));
        appendLog(`Started: ${STAGE_LABELS[event.stage]}`, event.at);
        break;
      case "stage_completed":
        setStageStatus((s) => ({ ...s, [event.stage]: "done" }));
        appendLog(`Completed: ${STAGE_LABELS[event.stage]}${event.durationMs === undefined ? "" : ` (${event.durationMs}ms)`}`, event.at);
        break;
      case "finding_raised":
        setFindings((f) => [event.finding, ...f]);
        appendLog(`[${event.finding.severity.toUpperCase()}] ${event.finding.title} — ${event.finding.affectedEndpoint}`, event.at);
        break;
      case "request_issued":
        setRequestCount((c) => c + 1);
        appendLog(`${event.stage}: ${event.method} ${redactUrl(event.url)}`, event.at);
        break;
      case "scan_log":
        appendLog(event.message, event.at);
        break;
      case "endpoint_discovered":
        appendLog(`Discovered endpoint (${event.endpoint.sourceType}): ${redactUrl(event.endpoint.url)}`, event.at);
        break;
      case "technology_detected":
        appendLog(`Technology detected: ${event.technology.name}${event.technology.version ? ` ${event.technology.version}` : ""}`, event.at);
        break;
      case "scan_completed":
        appendLog(`Scan completed — ${event.findingCount} finding(s), ${event.requestCount} requests issued.`, event.at);
        setDone(true);
        break;
      case "scan_failed":
        appendLog(`Scan failed: ${event.reason}`, event.at);
        setDone(true);
        break;
      case "scan_cancelled":
        appendLog("Scan cancelled.", event.at);
        setDone(true);
        break;
    }
  }

  function appendLog(line: string, at = new Date().toISOString()) {
    setLogLines((l) => [...l.slice(-199), `${at}  ${line}`]);
    requestAnimationFrame(() => logRef.current?.scrollTo({ top: logRef.current.scrollHeight }));
  }

  const router = useRouter();

  async function cancel() {
    await api.post(`/api/scans/${params.scanId}/cancel`);
  }

  async function deleteThisScan() {
    if (!window.confirm("Are you sure you want to delete this scan and all its findings and logs?")) return;
    try {
      await api.delete(`/api/scans/${params.scanId}`);
      router.push(`/projects/${params.projectId}/scans`);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to delete scan");
    }
  }

  return (
    <AppShell projectNav={nav} activeHref={`${nav.base}/scans`}>
      <div className="mx-auto max-w-6xl space-y-5 px-8 py-8">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="flex items-baseline gap-3">
              <h1 className="text-lg font-semibold text-ink-950">
                {scan?.profile ? `${scan.profile} Scan` : "Scan"}
              </h1>
              {scan?.status && (
                <span
                  className={`text-xs font-medium ${
                    scan.status === "COMPLETED"
                      ? "text-[#2E6B1F]"
                      : scan.status === "RUNNING"
                      ? "text-[#204163]"
                      : scan.status === "FAILED"
                      ? "text-[#A4221B]"
                      : "text-ink-600"
                  }`}
                >
                  {scan.status}
                </span>
              )}
            </div>
            <p className="mt-1 flex flex-wrap items-center gap-2 text-xs text-ink-600">
              <span className="mono text-2xs text-ink-500">
                ID: {params.scanId}
              </span>
              <span>·</span>
              <span>{requestCount} requests issued</span>
              {scan?.stopReason && <span>· stopped: {scan.stopReason.replace(/_/g, " ")}</span>}
            </p>
          </div>
          <div className="flex items-center gap-3">
            {!done && (
              <Button variant="danger" onClick={cancel}>
                Cancel scan
              </Button>
            )}
            {done && (
              <>
                <Link href={`/projects/${params.projectId}/findings?scanId=${params.scanId}`}>
                  <Button>View findings</Button>
                </Link>
                <a
                  href={`/api/scans/${params.scanId}/log`}
                  className="rounded-sm border border-paper-200 bg-white px-3 py-1.5 text-sm font-medium text-ink-900 hover:bg-paper-100"
                >
                  Download session log
                </a>
                <button
                  onClick={deleteThisScan}
                  className="text-xs text-ink-600 underline hover:text-[#A4221B]"
                >
                  Delete scan
                </button>
              </>
            )}
          </div>
        </div>

        <div className="grid grid-cols-[220px_1fr] gap-5">
          <Panel>
            <PanelHeader title="Stages" />
            <ol className="p-3">
              {SCAN_STAGES.map((stage) => (
                <li key={stage} className="flex items-center gap-2 py-1.5 text-xs">
                  <StageDot status={stageStatus[stage] ?? "pending"} />
                  <span className={stageStatus[stage] === "active" ? "font-medium text-ink-900" : "text-ink-700"}>
                    {STAGE_LABELS[stage]}
                  </span>
                </li>
              ))}
            </ol>
          </Panel>

          <div className="space-y-5">
            <Panel>
              <PanelHeader title="Live log" />
              <div ref={logRef} className="mono h-40 overflow-y-auto bg-ink-950 p-3 text-2xs text-paper-100">
                {logLines.length === 0 && <div className="text-paper-200/50">Waiting for scan to start…</div>}
                {logLines.map((line, i) => (
                  <div key={i}>{line}</div>
                ))}
              </div>
            </Panel>

            <Panel>
              <PanelHeader title={`Findings (${findings.length})`} />
              <table className="data-table">
                <tbody>
                  {findings.length === 0 && (
                    <tr>
                      <td className="py-6 text-center text-ink-600">No findings raised yet.</td>
                    </tr>
                  )}
                  {findings.map((f) => (
                    <tr key={f.id}>
                      <td className="w-24">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td>
                        <div className="font-medium text-ink-900">{f.title}</div>
                        <div className="mono text-2xs text-ink-600">{f.affectedEndpoint}</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          </div>
        </div>
      </div>
    </AppShell>
  );
}

function redactUrl(value: string): string {
  return value.replace(/https?:\/\/[^\s"'<>]+/gi, (candidate) => {
    try {
      const url = new URL(candidate);
      for (const key of Array.from(url.searchParams.keys())) {
        if (/password|secret|token|authorization|cookie|credential|api[_-]?key/i.test(key)) {
          url.searchParams.set(key, "[REDACTED]");
        }
      }
      url.username = "";
      url.password = "";
      url.hash = "";
      return url.toString();
    } catch {
      return candidate;
    }
  });
}

function StageDot({ status }: { status: "pending" | "active" | "done" }) {
  if (status === "done") return <span className="h-2 w-2 rounded-full bg-[#2E6B1F]" />;
  if (status === "active") return <span className="h-2 w-2 animate-pulse rounded-full bg-accent" />;
  return <span className="h-2 w-2 rounded-full border border-ink-600" />;
}
