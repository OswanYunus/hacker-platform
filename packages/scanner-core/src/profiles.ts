import type { ScanProfile } from "./types.js";

export interface ProfileCapabilities {
  maxPages: number;
  maxDepth: number;
  maxRequests: number;
  maxDurationSeconds: number;
  fixedPathDiscovery: boolean;
  apiRouteRequests: boolean;
  activeChecks: boolean;
  authComparison: boolean;
  pairedTimingValidation: boolean;
}

export const PROFILE_CAPABILITIES: Record<ScanProfile, ProfileCapabilities> = {
  quick: { maxPages: 25, maxDepth: 2, maxRequests: 150, maxDurationSeconds: 120, fixedPathDiscovery: false, apiRouteRequests: false, activeChecks: false, authComparison: false, pairedTimingValidation: false },
  standard: { maxPages: 100, maxDepth: 3, maxRequests: 600, maxDurationSeconds: 600, fixedPathDiscovery: true, apiRouteRequests: true, activeChecks: true, authComparison: true, pairedTimingValidation: false },
  deep: { maxPages: 400, maxDepth: 6, maxRequests: 1600, maxDurationSeconds: 1500, fixedPathDiscovery: true, apiRouteRequests: true, activeChecks: true, authComparison: true, pairedTimingValidation: true },
  ci: { maxPages: 50, maxDepth: 2, maxRequests: 300, maxDurationSeconds: 180, fixedPathDiscovery: false, apiRouteRequests: false, activeChecks: false, authComparison: false, pairedTimingValidation: false },
};

export type CapabilityState = { status: "ran" } | { status: "skipped"; reason: string } | { status: "unavailable"; reason: string };
export interface ScanCapabilityReport {
  profile: ScanProfile;
  effectiveBudgets: { maxPages: number; maxDepth: number; maxRequests: number; maxDurationSeconds: number };
  capabilities: Record<string, CapabilityState>;
  notAssessed: string[];
}

export function effectiveProfile(profile: ScanProfile, activeTestingAllowed: boolean, limits: { maxTotalRequests: number; maxScanDurationSeconds: number }): ProfileCapabilities {
  const selected = PROFILE_CAPABILITIES[profile];
  return { ...selected, maxRequests: Math.min(selected.maxRequests, limits.maxTotalRequests), maxDurationSeconds: Math.min(selected.maxDurationSeconds, limits.maxScanDurationSeconds), activeChecks: selected.activeChecks && activeTestingAllowed, fixedPathDiscovery: selected.fixedPathDiscovery && activeTestingAllowed, apiRouteRequests: selected.apiRouteRequests && activeTestingAllowed, authComparison: selected.authComparison && activeTestingAllowed, pairedTimingValidation: selected.pairedTimingValidation && activeTestingAllowed };
}
