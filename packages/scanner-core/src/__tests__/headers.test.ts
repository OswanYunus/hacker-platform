import { describe, it, expect } from "vitest";
import { checkSecurityHeaders } from "../checks/headers.js";
import { mockExchange } from "./fixtures.js";

describe("checkSecurityHeaders", () => {
  it("flags all baseline headers missing on a bare HTML response", () => {
    const ex = mockExchange({ url: "https://example.com/", responseHeaders: {} });
    const findings = checkSecurityHeaders(ex);
    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain("missing-hsts");
    expect(ruleIds).toContain("missing-csp");
    expect(ruleIds).toContain("missing-x-content-type-options");
    expect(ruleIds).toContain("missing-frame-protection");
  });

  it("does not flag HSTS on a plain HTTP response (not applicable)", () => {
    const ex = mockExchange({ url: "http://example.com/" });
    const findings = checkSecurityHeaders(ex);
    expect(findings.map((f) => f.ruleId)).not.toContain("missing-hsts");
  });

  it("does not re-flag headers that are present", () => {
    const ex = mockExchange({
      url: "https://example.com/",
      responseHeaders: {
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
      },
    });
    expect(checkSecurityHeaders(ex)).toHaveLength(0);
  });

  it("flags wildcard CORS combined with credentials as critical", () => {
    const ex = mockExchange({
      url: "https://example.com/api/data",
      responseHeaders: {
        "content-type": "application/json",
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
        "strict-transport-security": "max-age=1",
        "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
      },
    });
    const findings = checkSecurityHeaders(ex);
    const cors = findings.find((f) => f.ruleId === "cors-wildcard-with-credentials");
    expect(cors).toBeDefined();
    expect(cors?.severity).toBe("critical");
  });

  it("does not flag headers on non-HTML asset responses", () => {
    const ex = mockExchange({
      url: "https://example.com/logo.png",
      responseHeaders: { "content-type": "image/png" },
    });
    expect(checkSecurityHeaders(ex)).toHaveLength(0);
  });

  it("does not flag headers on error responses", () => {
    const ex = mockExchange({ url: "https://example.com/missing", status: 404 });
    expect(checkSecurityHeaders(ex)).toHaveLength(0);
  });
});
