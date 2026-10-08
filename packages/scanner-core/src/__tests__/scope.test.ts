import { describe, it, expect } from "vitest";
import { validateScope, isForbiddenIpv4 } from "../scope.js";
import type { AuthorizationScope } from "../types.js";

const baseScope: AuthorizationScope = {
  allowedHosts: ["example.com", "*.staging.example.com"],
  allowedPaths: [],
  excludedPaths: ["/billing"],
  activeTestingAllowed: false,
  maxRequestsPerSecond: 5,
  maxScanDurationSeconds: 600,
  maxTotalRequests: 1000,
  environment: "staging",
};

describe("validateScope", () => {
  it("allows the exact configured host", () => {
    expect(validateScope("https://example.com/app", baseScope).inScope).toBe(true);
  });

  it("allows a wildcard subdomain match", () => {
    expect(validateScope("https://api.staging.example.com/v1", baseScope).inScope).toBe(true);
  });

  it("rejects an unrelated host", () => {
    const r = validateScope("https://evil.com/", baseScope);
    expect(r.inScope).toBe(false);
  });

  it("rejects a host that merely contains the allowed domain as a suffix trick", () => {
    const r = validateScope("https://notexample.com/", baseScope);
    expect(r.inScope).toBe(false);
  });

  it("rejects explicitly excluded paths even on an allowed host", () => {
    const r = validateScope("https://example.com/billing/invoice", baseScope);
    expect(r.inScope).toBe(false);
  });

  it("rejects non-http(s) protocols", () => {
    const r = validateScope("file:///etc/passwd", baseScope);
    expect(r.inScope).toBe(false);
  });

  it("rejects literal private IPv4 addresses regardless of host allow-list", () => {
    const scope: AuthorizationScope = { ...baseScope, allowedHosts: ["169.254.169.254"] };
    const r = validateScope("http://169.254.169.254/latest/meta-data/", scope);
    expect(r.inScope).toBe(false);
  });

  it("honors an explicit allowedPaths restriction", () => {
    const scope: AuthorizationScope = { ...baseScope, allowedPaths: ["/app"] };
    expect(validateScope("https://example.com/app/settings", scope).inScope).toBe(true);
    expect(validateScope("https://example.com/other", scope).inScope).toBe(false);
  });
});

describe("isForbiddenIpv4", () => {
  it("flags loopback, link-local, and RFC1918 ranges", () => {
    expect(isForbiddenIpv4("127.0.0.1")).toBe(true);
    expect(isForbiddenIpv4("169.254.169.254")).toBe(true); // cloud metadata
    expect(isForbiddenIpv4("10.1.2.3")).toBe(true);
    expect(isForbiddenIpv4("192.168.1.1")).toBe(true);
    expect(isForbiddenIpv4("172.20.3.4")).toBe(true);
  });

  it("does not flag ordinary public addresses", () => {
    expect(isForbiddenIpv4("93.184.216.34")).toBe(false);
    expect(isForbiddenIpv4("8.8.8.8")).toBe(false);
  });
});
