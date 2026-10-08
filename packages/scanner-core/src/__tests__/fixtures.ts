import type { HttpExchange } from "../types.js";

export function mockExchange(overrides: {
  url?: string;
  method?: string;
  status?: number;
  requestHeaders?: Record<string, string>;
  responseHeaders?: Record<string, string>;
  body?: string;
}): HttpExchange {
  return {
    id: "ex_test_" + Math.random().toString(36).slice(2),
    request: {
      method: overrides.method ?? "GET",
      url: overrides.url ?? "https://example.com/",
      headers: overrides.requestHeaders ?? {},
    },
    response: {
      status: overrides.status ?? 200,
      headers: { "content-type": "text/html", ...overrides.responseHeaders },
      body: overrides.body,
      bodyPreview: overrides.body?.slice(0, 2000),
      timingMs: 42,
    },
    stage: "passive_analysis",
    discoveredAt: new Date().toISOString(),
  };
}
