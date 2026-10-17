import { describe, expect, it } from "vitest";
import { assessVerification, calibrateConfidence } from "../verification.js";
import type { RawObservation } from "../types.js";

function observation(overrides: Partial<RawObservation> = {}): RawObservation {
  return {
    ruleId: "missing-hsts",
    title: "Missing HSTS",
    severity: "medium",
    confidence: "high",
    affectedEndpoint: "https://example.com/",
    evidence: [{ description: "Strict-Transport-Security absent", exchangeId: "ex_1" }],
    reproduction: "Inspect response headers.",
    rootCause: "The response did not include HSTS.",
    impact: "Transport policy is not advertised.",
    remediation: "Configure HSTS.",
    references: [],
    verification: "confirmed",
    firstSeenStage: "passive_analysis",
    module: "configuration",
    ...overrides,
  };
}

describe("rule-specific verification", () => {
  it("downgrades a rule's confirmed claim to evidence-supported when required exchange evidence exists", () => {
    expect(assessVerification(observation())).toBe("evidence_supported");
  });

  it("marks a deterministic rule inconclusive when its exchange provenance is missing", () => {
    expect(assessVerification(observation({ evidence: [{ description: "HSTS missing" }] }))).toBe("inconclusive");
  });

  it("does not let a check self-assert independent verification", () => {
    expect(assessVerification(observation({ verification: "independently_verified" }))).toBe("evidence_supported");
  });

  it("does not promote unregistered rules to evidence-supported", () => {
    expect(assessVerification(observation({ ruleId: "new-rule" }))).toBe("suspected");
  });

  it("caps single-probe injection confidence and downgrades inconclusive evidence", () => {
    const active = observation({
      ruleId: "sqli-time-based",
      evidence: [{ description: "One delayed probe", detail: "Probe URL: https://example.com/?q=x" }],
    });
    expect(calibrateConfidence(active, "evidence_supported")).toBe("low");
    expect(calibrateConfidence(observation(), "inconclusive")).toBe("low");
  });
});
