/**
 * Core domain types for the Hacker scanning engine.
 *
 * These types are deliberately framework-agnostic: scanner-core has no
 * dependency on the API server, the database, or any transport. It takes
 * a Scope + a set of HTTP exchanges and produces Findings. This keeps the
 * engine testable in isolation and reusable from a CLI, a worker, or CI.
 */

// ---------------------------------------------------------------------------
// Scope & authorization
// ---------------------------------------------------------------------------

/** Testing intensity. Determines concurrency, request volume, and which
 * scanner modules are allowed to run. */
export type ScanProfile = "quick" | "standard" | "deep" | "ci";

export interface AuthorizationScope {
  /** Hostnames this scan is permitted to touch. Exact match or leading
   * "*." wildcard subdomain match, e.g. "*.staging.example.com". */
  allowedHosts: string[];
  /** Optional CIDR ranges that may additionally be in-scope for IP-based
   * targets. Rarely used; most web targets are host-scoped. */
  allowedIpRanges?: string[];
  /** URL path prefixes that are explicitly allowed. Empty = all paths on
   * an allowed host are in scope. */
  allowedPaths?: string[];
  /** URL path prefixes that must never be requested, even if the host
   * matches (e.g. "/billing", "/api/internal"). Excludes always win. */
  excludedPaths?: string[];
  /** Whether active (state-changing / exploit-attempt) testing is
   * permitted at all. If false, only passive/discovery stages run. */
  activeTestingAllowed: boolean;
  /** Max requests per second the scanner may issue against this target. */
  maxRequestsPerSecond: number;
  /** Hard ceiling on total scan duration, in seconds. */
  maxScanDurationSeconds: number;
  /** Hard ceiling on total requests issued in a single scan. */
  maxTotalRequests: number;
  /** Free-text description of the environment, shown in the UI and in
   * reports so nobody mistakes a staging scan for a production one. */
  environment: "production" | "staging" | "development" | "other";
}

export interface ScopeValidationResult {
  inScope: boolean;
  reason?: string;
}

// ---------------------------------------------------------------------------
// HTTP exchange — the atomic unit of evidence
// ---------------------------------------------------------------------------

export interface HttpRequestRecord {
  method: string;
  url: string;
  headers: Record<string, string>;
  bodyPreview?: string;
}

export interface HttpResponseRecord {
  status: number;
  headers: Record<string, string>;
  bodyPreview?: string;
  /** Full body only retained when a check needs it (e.g. JS secret
   * scanning); kept separate from bodyPreview to control evidence size. */
  body?: string;
  timingMs: number;
  tlsProtocol?: string;
}

export interface HttpExchange {
  id: string;
  request: HttpRequestRecord;
  response: HttpResponseRecord;
  /** Which scan stage produced this exchange, for provenance. */
  stage: ScanStage;
  discoveredAt: string; // ISO timestamp
  /** Authenticated role this request was made as, if any. */
  actorRole?: string;
}

// ---------------------------------------------------------------------------
// Attack surface
// ---------------------------------------------------------------------------

export interface DiscoveredEndpoint {
  url: string;
  methodsObserved: string[];
  statusCodesObserved: number[];
  queryParams: string[];
  formFields: string[];
  requiresAuth: boolean | "unknown";
  sourceType: "crawl" | "openapi" | "sitemap" | "manual" | "js-reference";
  contentType?: string;
  parentUrl?: string;
}

export interface TechnologyFingerprint {
  name: string;
  category: "framework" | "server" | "cms" | "library" | "language" | "other";
  version?: string;
  confidence: Confidence;
  evidence: string;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "confirmed" | "high" | "medium" | "low";
export type VerificationStatus =
  | "unverified"
  | "verification_in_progress"
  | "confirmed"
  | "likely"
  | "false_positive";

export interface Evidence {
  description: string;
  exchangeId?: string;
  detail?: string;
}

export interface Finding {
  id: string;
  /** Stable identifier for the rule/check that produced this finding,
   * e.g. "missing-hsts", "idor-sequential-id". Used for deduplication
   * and for regression comparison across scans. */
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  cwe?: string;
  owaspCategory?: string;
  affectedEndpoint: string;
  evidence: Evidence[];
  reproduction: string;
  rootCause: string;
  impact: string;
  remediation: string;
  references: string[];
  verification: VerificationStatus;
  /** How many distinct raw observations were merged into this finding. */
  occurrences: number;
  firstSeenStage: ScanStage;
  module: ScannerModuleId;
}

/** A raw signal from a single check, before correlation/dedup. Checks
 * return RawObservations; the correlation engine turns many of these
 * into a smaller set of Findings. */
export type RawObservation = Omit<Finding, "id" | "occurrences" | "evidence"> & {
  evidence: Evidence[];
};

// ---------------------------------------------------------------------------
// Scan stages & modules
// ---------------------------------------------------------------------------

export const SCAN_STAGES = [
  "scope_validation",
  "target_discovery",
  "crawling",
  "endpoint_discovery",
  "technology_identification",
  "passive_analysis",
  "auth_session_analysis",
  "active_testing",
  "finding_verification",
  "risk_scoring",
  "report_generation",
] as const;
export type ScanStage = (typeof SCAN_STAGES)[number];

export const SCANNER_MODULE_IDS = [
  "discovery",
  "configuration",
  "authentication",
  "authorization",
  "session",
  "input-validation",
  "api",
  "client-side",
  "dependency",
  "business-logic",
] as const;
export type ScannerModuleId = (typeof SCANNER_MODULE_IDS)[number];

// ---------------------------------------------------------------------------
// Streamed events (what the frontend sees live over SSE/WebSocket)
// ---------------------------------------------------------------------------

export type ScanEvent =
  | { type: "stage_started"; stage: ScanStage; at: string }
  | { type: "stage_completed"; stage: ScanStage; at: string; summary?: string }
  | { type: "endpoint_discovered"; endpoint: DiscoveredEndpoint; at: string }
  | { type: "technology_detected"; technology: TechnologyFingerprint; at: string }
  | { type: "finding_raised"; finding: Finding; at: string }
  | { type: "request_issued"; method: string; url: string; at: string }
  | { type: "scan_log"; level: "info" | "warn" | "error"; message: string; at: string }
  | { type: "scan_completed"; at: string; findingCount: number; requestCount: number }
  | { type: "scan_failed"; at: string; reason: string }
  | { type: "scan_cancelled"; at: string };

export interface ScanRunConfig {
  scanId: string;
  projectId: string;
  targetBaseUrls: string[];
  scope: AuthorizationScope;
  profile: ScanProfile;
  /** If set, limits which modules run regardless of profile defaults. */
  enabledModules?: ScannerModuleId[];
  authContext?: AuthContext;
}

export interface AuthContext {
  role: string;
  cookieHeader?: string;
  bearerToken?: string;
  extraHeaders?: Record<string, string>;
}

export interface ScanResult {
  scanId: string;
  startedAt: string;
  completedAt: string;
  endpoints: DiscoveredEndpoint[];
  technologies: TechnologyFingerprint[];
  findings: Finding[];
  requestCount: number;
  stageDurationsMs: Partial<Record<ScanStage, number>>;
  stopReason: "completed" | "cancelled" | "duration_limit" | "request_limit" | "error";
}
