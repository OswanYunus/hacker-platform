import { describe, expect, it } from "vitest";
import { checkPrivilegedPathAccess } from "../checks/authorization.js";
import type { ScannerHttpClient } from "../httpClient.js";
import type { DiscoveredEndpoint } from "../types.js";
import { assessVerification } from "../verification.js";

const endpoint: DiscoveredEndpoint = {
  url: "https://example.com/robots.txt",
  methodsObserved: ["GET"],
  statusCodesObserved: [200],
  queryParams: [],
  formFields: [],
  requiresAuth: false,
  sourceType: "crawl",
  contentType: "text/plain",
};

function response(url: string, body: string, contentType = "text/html") {
  return {
    id: "exchange",
    request: { method: "GET", url, headers: {} },
    response: { status: 200, headers: { "content-type": contentType }, body, bodyPreview: body, timingMs: 1 },
    stage: "active_testing" as const,
    discoveredAt: new Date(0).toISOString(),
  };
}

describe("privileged path access check", () => {
  it("does not flag public pages, robots, sitemap, or SPA fallback responses", async () => {
    const publicFallback = "<!doctype html><html><body><div id=app></div><script src=/assets/index.js></script></body></html>";
    const client = {
      getAnonymous: async (url: string) => response(url, publicFallback),
    } as unknown as ScannerHttpClient;

    expect(await checkPrivilegedPathAccess(client, endpoint)).toEqual([]);
  });

  it("flags a distinct admin page with explicit administrative functionality", async () => {
    const publicPage = "<html><body>Welcome to the public site</body></html>";
    const adminPage = "<html><h1>Admin dashboard</h1><a>Manage users</a></html>";
    const client = {
      getAnonymous: async (url: string) => response(
        url,
        new URL(url).pathname === "/admin" ? adminPage : publicPage,
      ),
    } as unknown as ScannerHttpClient;

    const findings = await checkPrivilegedPathAccess(client, endpoint);
    expect(findings).toHaveLength(1);
    expect(findings[0].affectedEndpoint).toBe("https://example.com/admin");
    expect(findings[0].rootCause).toContain("credential-free request");
    expect(findings[0].evidence).toHaveLength(2);
    expect(assessVerification(findings[0])).toBe("evidence_supported");
    expect(assessVerification({ ...findings[0], evidence: findings[0].evidence.slice(0, 1) })).toBe("inconclusive");
  });
});
