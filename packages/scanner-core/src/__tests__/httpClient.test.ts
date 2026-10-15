import { describe, expect, it } from "vitest";
import { ScannerHttpClient, ScopeViolationError } from "../httpClient.js";
import type { AuthorizationScope } from "../types.js";

const scope: AuthorizationScope = {
  allowedHosts: ["example.com"],
  allowedPaths: ["/"],
  activeTestingAllowed: true,
  maxRequestsPerSecond: 1,
  maxScanDurationSeconds: 60,
  maxTotalRequests: 20,
  environment: "production",
};

describe("ScannerHttpClient request policy", () => {
  it.each(["POST", "PUT", "PATCH", "DELETE"])(
    "blocks state-changing %s requests before network access",
    async (method) => {
      const client = new ScannerHttpClient({ scope });
      await expect(client.request(method, "https://example.com/", "active_testing"))
        .rejects.toBeInstanceOf(ScopeViolationError);
      expect(client.totalRequests).toBe(0);
    },
  );
});
