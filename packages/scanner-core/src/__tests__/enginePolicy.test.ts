import { describe, expect, it } from "vitest";
import { discoveryProbePaths } from "../engine.js";

describe("discovery probe policy", () => {
  it("does not enumerate fixed paths when active testing is disabled", () => {
    expect(discoveryProbePaths(false)).toEqual([]);
  });

  it("permits the fixed path registry only when active testing is authorized", () => {
    const paths = discoveryProbePaths(true);
    expect(paths).toContain("/.env");
    expect(paths.length).toBeGreaterThan(0);
  });
});
