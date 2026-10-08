import { describe, it, expect } from "vitest";
import { riskScore, evaluateCiPolicy } from "../riskScoring.js";
import type { Finding } from "../types.js";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "f1",
    ruleId: "r1",
    title: "t",
    severity: "medium",
    confidence: "high",
    affectedEndpoint: "https://example.com/",
    evidence: [],
    reproduction: "",
    rootCause: "",
    impact: "",
    remediation: "",
    references: [],
    verification: "confirmed",
    occurrences: 1,
    firstSeenStage: "passive_analysis",
    module: "configuration",
    ...overrides,
  };
}

describe("riskScore", () => {
  it("scores a confirmed critical finding at the top of the range", () => {
    const score = riskScore(finding({ severity: "critical", confidence: "confirmed", verification: "confirmed" }));
    expect(score).toBe(100);
  });

  it("scores a false positive at zero regardless of severity", () => {
    const score = riskScore(finding({ severity: "critical", verification: "false_positive" }));
    expect(score).toBe(0);
  });

  it("ranks a high-confidence medium above a low-confidence high in close cases", () => {
    const highConfMedium = riskScore(finding({ severity: "medium", confidence: "confirmed", verification: "confirmed" }));
    const lowConfHigh = riskScore(finding({ severity: "high", confidence: "low", verification: "unverified" }));
    expect(highConfMedium).toBeGreaterThan(lowConfHigh);
  });
});

describe("evaluateCiPolicy", () => {
  it("fails the build when critical findings exceed zero", () => {
    const findings = [finding({ severity: "critical" })];
    const result = evaluateCiPolicy(findings, { critical: 0 });
    expect(result.pass).toBe(false);
    expect(result.violations[0]).toMatch(/critical/);
  });

  it("passes when findings are within the configured thresholds", () => {
    const findings = [finding({ severity: "high" }), finding({ severity: "high" })];
    const result = evaluateCiPolicy(findings, { critical: 0, high: 2 });
    expect(result.pass).toBe(true);
  });

  it("ignores false positives when evaluating policy", () => {
    const findings = [finding({ severity: "critical", verification: "false_positive" })];
    const result = evaluateCiPolicy(findings, { critical: 0 });
    expect(result.pass).toBe(true);
  });
});
