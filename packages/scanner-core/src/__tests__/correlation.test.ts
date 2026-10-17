import { describe, it, expect } from "vitest";
import { correlateFindings } from "../correlation.js";
import type { RawObservation } from "../types.js";

function obs(url: string, ruleId = "missing-hsts"): RawObservation {
  return {
    ruleId,
    title: "Missing HSTS",
    severity: "medium",
    confidence: "high",
    affectedEndpoint: url,
    rootCause: "x",
    impact: "y",
    remediation: "z",
    references: [],
    evidence: [{ description: "Observed header", exchangeId: "ex_test" }],
    reproduction: "repro",
    verification: "confirmed",
    firstSeenStage: "passive_analysis",
    module: "configuration",
  };
}

describe("correlateFindings", () => {
  it("merges many observations of the same rule against similar endpoints into one finding", () => {
    const observations = Array.from({ length: 50 }, (_, i) => obs(`https://example.com/api/items/${i}`));
    const findings = correlateFindings(observations);
    expect(findings).toHaveLength(1);
    expect(findings[0].occurrences).toBe(50);
    expect(findings[0].verification).toBe("evidence_supported");
  });

  it("keeps distinct rule findings separate", () => {
    const observations = [obs("https://example.com/a", "missing-hsts"), obs("https://example.com/a", "missing-csp")];
    const findings = correlateFindings(observations);
    expect(findings).toHaveLength(2);
  });

  it("keeps findings on genuinely different hosts separate", () => {
    const observations = [obs("https://a.example.com/x"), obs("https://b.example.com/x")];
    const findings = correlateFindings(observations);
    expect(findings).toHaveLength(2);
  });

  it("sorts output by severity, highest first", () => {
    const critical = { ...obs("https://example.com/c", "crit-rule"), severity: "critical" as const };
    const low = { ...obs("https://example.com/l", "low-rule"), severity: "low" as const };
    const findings = correlateFindings([low, critical]);
    expect(findings[0].severity).toBe("critical");
  });

  it("does not preserve a check's unsupported confirmed label", () => {
    const unsupported = { ...obs("https://example.com/a", "missing-hsts"), evidence: [{ description: "claim" }] };
    const [finding] = correlateFindings([unsupported]);
    expect(finding.verification).toBe("inconclusive");
    expect(finding.verification).not.toBe("confirmed");
    expect(finding.verification).not.toBe("independently_verified");
  });

  it("requires a same-origin probe URL for active injection evidence", () => {
    const active = {
      ...obs("https://example.com/search", "sqli-error-based"),
      evidence: [{ description: "Database error matched", detail: "Probe URL: https://other.example/p?q=x" }],
    };
    expect(correlateFindings([active])[0].verification).toBe("inconclusive");
  });
});
