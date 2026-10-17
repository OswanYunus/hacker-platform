import { describe, expect, it } from "vitest";
import { checkSqliGetParams, checkReflectedXss, checkPathTraversal, checkSsti, checkOpenRedirect, checkCommandInjection } from "../checks/injection.js";
import type { DiscoveredEndpoint } from "../types.js";

const endpoint: DiscoveredEndpoint = { url: "http://127.0.0.1:43123/item?id=1", methodsObserved: ["GET"], statusCodesObserved: [200], queryParams: ["id"], formFields: [], requiresAuth: false, sourceType: "manual" };
function fakeClient(respond: (url: string, call: number) => { status?: number; body?: string; headers?: Record<string, string>; timingMs?: number }) {
  const calls = new Map<string, number>();
  const send = async (_method: string, url: string) => {
    const n = (calls.get(url) ?? 0) + 1; calls.set(url, n);
    const r = respond(url, n);
    return { response: { status: r.status ?? 200, body: r.body ?? "ok", bodyPreview: r.body ?? "ok", headers: r.headers ?? { "content-type": "text/html" }, timingMs: r.timingMs ?? 20 } } as any;
  };
  return { get: (url: string) => send("GET", url), request: (_method: string, url: string) => send("GET", url) } as any;
}
const tests = [
  ["SQLi", (client: any) => checkSqliGetParams(client, endpoint), (url: string) => url.includes("%27") ? { body: "SQL syntax error" } : { body: "item" }],
  ["XSS", (client: any) => checkReflectedXss(client, endpoint), (url: string) => url.includes("%3Cscript%3E") ? { body: "<html><script>alert(1)</script></html>" } : { body: "<html>safe</html>" }],
  ["path traversal", (client: any) => checkPathTraversal(client, { ...endpoint, queryParams: ["file"] }), (url: string) => url.includes("scan-benchmark-canary") ? { body: "SCAN_BENCHMARK_CANARY_X7" } : { body: "not found" }],
  ["SSTI", (client: any) => checkSsti(client, endpoint), (url: string) => url.includes("%7B%7B7*7%7D%7D") ? { body: "49" } : { body: "none" }],
  ["open redirect", (client: any) => checkOpenRedirect(client, endpoint), (url: string) => url.includes("scan-probe-redir.invalid.example") ? { status: 302, headers: { location: "https://scan-probe-redir.invalid.example/path" } } : { status: 200 }],
] as const;

describe("repeatable injection evidence validators", () => {
  for (const [name, run, response] of tests) {
    it(`${name}: reports repeated positive evidence and rejects a safe control`, async () => {
      const positive = await run(fakeClient((url) => response(url)));
      expect(positive.length).toBeGreaterThan(0);
      const negative = await run(fakeClient(() => ({ body: "ordinary safe response", status: 200 })));
      expect(negative).toHaveLength(0);
    });
  }
  it("never sends OS command payloads", async () => {
    let requests = 0;
    const client = { get: async () => { requests++; throw new Error("unexpected request"); } } as any;
    expect(await checkCommandInjection(client, { ...endpoint, queryParams: ["cmd"] }, { timingValidation: true })).toHaveLength(0);
    expect(requests).toBe(0);
  });
});
