import type { Finding } from "./types.js";
import { severityWeight } from "./correlation.js";

const CONFIDENCE_WEIGHT: Record<Finding["confidence"], number> = {
  confirmed: 1.0,
  high: 0.85,
  medium: 0.6,
  low: 0.35,
};

const VERIFICATION_WEIGHT: Record<Finding["verification"], number> = {
  confirmed: 1.0,
  likely: 0.75,
  unverified: 0.5,
  verification_in_progress: 0.5,
  false_positive: 0,
};

/**
 * Produces a 0–100 remediation-priority score. Severity dominates (it's
 * what the finding would cost if exploited); confidence and verification
 * discount that cost by how sure we are the finding is real. A
 * false_positive always scores 0 regardless of severity.
 */
export function riskScore(finding: Finding): number {
  const base = (severityWeight(finding.severity) / 5) * 100;
  const score = base * CONFIDENCE_WEIGHT[finding.confidence] * VERIFICATION_WEIGHT[finding.verification];
  return Math.round(score);
}

export function prioritize(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => riskScore(b) - riskScore(a));
}

export interface SeveritySummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export function summarizeSeverity(findings: Finding[]): SeveritySummary {
  const summary: SeveritySummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
  for (const f of findings) {
    if (f.verification === "false_positive") continue;
    summary[f.severity]++;
    summary.total++;
  }
  return summary;
}

/** Evaluates a CI pass/fail policy like { critical: 0, high: 2 } meaning
 * "fail if critical > 0 OR high > 2". */
export interface CiPolicy {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
}

export function evaluateCiPolicy(findings: Finding[], policy: CiPolicy): { pass: boolean; violations: string[] } {
  const summary = summarizeSeverity(findings);
  const violations: string[] = [];
  (Object.keys(policy) as Array<keyof CiPolicy>).forEach((sev) => {
    const threshold = policy[sev];
    if (threshold === undefined) return;
    if (summary[sev] > threshold) {
      violations.push(`${summary[sev]} ${sev} finding(s) exceed policy threshold of ${threshold}`);
    }
  });
  return { pass: violations.length === 0, violations };
}
