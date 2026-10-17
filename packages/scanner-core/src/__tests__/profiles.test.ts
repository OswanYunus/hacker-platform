import { describe, expect, it } from "vitest";
import { effectiveProfile, PROFILE_CAPABILITIES } from "../profiles.js";

describe("explicit scan profile capabilities", () => {
  const limits = { maxTotalRequests: 5000, maxScanDurationSeconds: 5000 };
  it("selects meaningfully different work for Quick, Standard, Deep, and CI", () => {
    expect(PROFILE_CAPABILITIES.quick.activeChecks).toBe(false);
    expect(PROFILE_CAPABILITIES.standard.activeChecks).toBe(true);
    expect(PROFILE_CAPABILITIES.deep.pairedTimingValidation).toBe(true);
    expect(PROFILE_CAPABILITIES.ci.pairedTimingValidation).toBe(false);
    expect(PROFILE_CAPABILITIES.deep.maxPages).toBeGreaterThan(PROFILE_CAPABILITIES.standard.maxPages);
  });
  it("cannot grant active requests when target authorization denies them", () => {
    for (const profile of ["quick", "standard", "deep", "ci"] as const) {
      const policy = effectiveProfile(profile, false, limits);
      expect(policy.activeChecks).toBe(false);
      expect(policy.fixedPathDiscovery).toBe(false);
      expect(policy.apiRouteRequests).toBe(false);
      expect(policy.pairedTimingValidation).toBe(false);
    }
  });
  it("caps each profile's request and duration budgets by scope", () => {
    const policy = effectiveProfile("deep", true, { maxTotalRequests: 40, maxScanDurationSeconds: 25 });
    expect(policy.maxRequests).toBe(40);
    expect(policy.maxDurationSeconds).toBe(25);
  });
});
