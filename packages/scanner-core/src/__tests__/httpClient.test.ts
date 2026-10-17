import { afterEach, describe, expect, it, vi } from "vitest";
import { RequestCancelledError, RequestTimeoutError, ScannerHttpClient, ScopeViolationError } from "../httpClient.js";
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
  afterEach(() => vi.restoreAllMocks());
  const ipScope = { ...scope, allowedHosts: ["8.8.8.8"] };

  it.each(["POST", "PUT", "PATCH", "DELETE"])(
    "blocks state-changing %s requests before network access",
    async (method) => {
      const client = new ScannerHttpClient({ scope });
      await expect(client.request(method, "https://example.com/", "active_testing"))
        .rejects.toBeInstanceOf(ScopeViolationError);
      expect(client.totalRequests).toBe(0);
    },
  );

  it.each(["endpoint_discovery", "auth_session_analysis", "active_testing"] as const)(
    "blocks %s requests when active testing is outside the authorized scope",
    async (stage) => {
      const client = new ScannerHttpClient({ scope: { ...scope, activeTestingAllowed: false } });
      await expect(client.get("https://example.com/", stage)).rejects.toBeInstanceOf(ScopeViolationError);
      expect(client.totalRequests).toBe(0);
    },
  );

  it("aborts a request that exceeds the per-request deadline", async () => {
    vi.spyOn(globalThis, "fetch").mockImplementation((_input, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
    }));
    const client = new ScannerHttpClient({ scope: ipScope, requestTimeoutMs: 20 });

    await expect(client.get("https://8.8.8.8/", "target_discovery"))
      .rejects.toBeInstanceOf(RequestTimeoutError);
    expect(client.totalRequests).toBe(1);
  });

  it("does not send configured credentials through the anonymous GET method", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response("ok", { status: 200 }));
    const client = new ScannerHttpClient({
      scope: ipScope,
      auth: { cookieHeader: "session=secret", bearerToken: "secret-token", role: "admin" },
    });

    await client.getAnonymous("https://8.8.8.8/", "active_testing");
    const headers = new Headers(fetchSpy.mock.calls[0][1]?.headers);
    expect(headers.has("cookie")).toBe(false);
    expect(headers.has("authorization")).toBe(false);
  });

  it("aborts in-flight network requests when the scan is cancelled", async () => {
    let notifyFetchStarted!: () => void;
    const fetchStarted = new Promise<void>((resolve) => { notifyFetchStarted = resolve; });
    vi.spyOn(globalThis, "fetch").mockImplementation((_input, init) => new Promise((_resolve, reject) => {
      notifyFetchStarted();
      init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
    }));
    const client = new ScannerHttpClient({ scope: ipScope, requestTimeoutMs: 5_000 });
    const request = client.get("https://8.8.8.8/", "target_discovery");
    await fetchStarted;
    client.cancel();

    await expect(request).rejects.toBeInstanceOf(RequestCancelledError);
  });
});
