"use client";

import { useState } from "react";
import clsx from "clsx";

export interface ScopeSummaryData {
  environment: string;
  allowedHosts: string[];
  allowedPaths?: string[];
  excludedPaths?: string[];
  allowedIpRanges?: string[];
  activeTestingAllowed: boolean;
  authorizedByName?: string;
  authorizedAt?: string;
  maxRequestsPerSecond?: number;
  maxScanDurationSeconds?: number;
  maxTotalRequests?: number;
  authorizationStatement?: string;
}

const ENV_STYLES: Record<string, string> = {
  PRODUCTION: "bg-[#F3DEDC] text-[#7A1A14] border-[#E3B5B0]",
  STAGING: "bg-[#F0E3D0] text-[#6B4A10] border-[#DCC291]",
  DEVELOPMENT: "bg-[#DCE6EF] text-[#204163] border-[#B9CEE0]",
  OTHER: "bg-paper-100 text-ink-700 border-paper-200",
};

export function ScopeSummary({
  scope,
  onResetScope,
}: {
  scope: ScopeSummaryData | null;
  onResetScope?: () => void;
}) {
  const [expanded, setExpanded] = useState(false);

  if (!scope) {
    return (
      <div className="flex items-center justify-between rounded-md border border-[#E3B5B0] bg-[#F3DEDC] px-4 py-3 text-sm text-[#7A1A14]">
        <span>No authorized scope has been configured for this project yet. Scans cannot start until scope is defined.</span>
      </div>
    );
  }

  return (
    <div className="rounded-md border border-paper-200 bg-white text-sm overflow-hidden transition-all">
      {/* Clickable summary header */}
      <div
        onClick={() => setExpanded(!expanded)}
        className="flex cursor-pointer flex-wrap items-center justify-between gap-x-6 gap-y-2 px-4 py-3 hover:bg-paper-50"
      >
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <span
            className={clsx(
              "rounded-sm border px-2 py-0.5 text-2xs font-semibold uppercase tracking-wide",
              ENV_STYLES[scope.environment] ?? ENV_STYLES.OTHER,
            )}
          >
            {scope.environment}
          </span>
          <span className="text-ink-700">
            Authorized hosts:{" "}
            <span className="mono font-medium text-ink-900">{scope.allowedHosts.join(", ") || "—"}</span>
          </span>
          <span className={clsx("text-xs font-medium", scope.activeTestingAllowed ? "text-[#6B4A10]" : "text-ink-600")}>
            {scope.activeTestingAllowed ? "Active testing permitted" : "Passive-only (active testing disabled)"}
          </span>
        </div>

        <div className="flex items-center gap-3 text-xs text-ink-500">
          <span>{expanded ? "Hide details ▲" : "Click to view full scope ▼"}</span>
        </div>
      </div>

      {/* Expanded uneditable details */}
      {expanded && (
        <div className="border-t border-paper-200 bg-paper-50/50 p-4 space-y-4 text-xs">
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
            <div>
              <div className="font-semibold text-ink-900">Environment</div>
              <div className="text-ink-700 mt-0.5">{scope.environment}</div>
            </div>
            <div>
              <div className="font-semibold text-ink-900">Active security testing</div>
              <div className="text-ink-700 mt-0.5">
                {scope.activeTestingAllowed ? "Enabled (State-changing & injection tests allowed)" : "Disabled (Passive observation only)"}
              </div>
            </div>
            <div>
              <div className="font-semibold text-ink-900">Authorized by</div>
              <div className="text-ink-700 mt-0.5">
                {scope.authorizedByName ?? "Authorized user"}
                {scope.authorizedAt ? ` on ${new Date(scope.authorizedAt).toLocaleString()}` : ""}
              </div>
            </div>

            <div>
              <div className="font-semibold text-ink-900">Rate limit</div>
              <div className="text-ink-700 mt-0.5">{scope.maxRequestsPerSecond ?? 2} requests / second</div>
            </div>
            <div>
              <div className="font-semibold text-ink-900">Max scan duration</div>
              <div className="text-ink-700 mt-0.5">
                {scope.maxScanDurationSeconds ? `${Math.round(scope.maxScanDurationSeconds / 60)} minutes` : "30 minutes"}
              </div>
            </div>
            <div>
              <div className="font-semibold text-ink-900">Total request ceiling</div>
              <div className="text-ink-700 mt-0.5">{scope.maxTotalRequests?.toLocaleString() ?? "2,000"} requests</div>
            </div>

            <div className="sm:col-span-2 md:col-span-3">
              <div className="font-semibold text-ink-900">Allowed URL paths</div>
              <div className="mono text-ink-700 mt-0.5">
                {scope.allowedPaths && scope.allowedPaths.length > 0 ? scope.allowedPaths.join(", ") : "All paths (no path restrictions)"}
              </div>
            </div>

            {scope.excludedPaths && scope.excludedPaths.length > 0 && (
              <div className="sm:col-span-2 md:col-span-3">
                <div className="font-semibold text-ink-900">Excluded URL paths</div>
                <div className="mono text-[#A4221B] mt-0.5">{scope.excludedPaths.join(", ")}</div>
              </div>
            )}
          </div>

          {/* Uneditable signed consent statement */}
          <div>
            <div className="font-semibold text-ink-900 mb-1">Authorization Attestation & Consent (Signed)</div>
            <div className="rounded-sm border border-paper-200 bg-white p-3 font-mono text-2xs text-ink-800 whitespace-pre-wrap select-all">
              {scope.authorizationStatement || "No authorization statement recorded."}
            </div>
          </div>

          {onResetScope && (
            <div className="pt-2 flex justify-end">
              <button
                type="button"
                onClick={onResetScope}
                className="text-xs text-ink-600 underline hover:text-[#A4221B]"
              >
                Reset / Delete active scope
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
