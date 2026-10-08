import { describe, it, expect } from "vitest";
import { checkExposedFile } from "../checks/infoDisclosure.js";
import type { HttpExchange } from "../types.js";

function makeExchange(url: string, body: string, contentType = "text/plain", status = 200): HttpExchange {
  return {
    id: "ex_1",
    request: { method: "GET", url, headers: {} },
    response: {
      status,
      headers: { "content-type": contentType },
      body,
      timingMs: 10,
    },
    stage: "endpoint_discovery",
    discoveredAt: new Date().toISOString(),
  };
}

describe("checkExposedFile SPA fallback filtering", () => {
  it("ignores sensitive paths when the server returns an SPA HTML fallback", () => {
    const htmlBody = `<!doctype html><html lang="en"><head><title>App</title></head><body><div id="root"></div></body></html>`;
    const ex = makeExchange("https://example.com/.env", htmlBody, "text/html");
    const observations = checkExposedFile(ex);
    expect(observations).toHaveLength(0);
  });

  it("detects genuine exposed .env file containing environment variables", () => {
    const envBody = `DATABASE_URL=postgres://user:pass@localhost:5432/db\nAPI_SECRET=mysecretkey123`;
    const ex = makeExchange("https://example.com/.env", envBody, "text/plain");
    const observations = checkExposedFile(ex);
    expect(observations).toHaveLength(1);
    expect(observations[0].ruleId).toContain("exposed-file");
    expect(observations[0].severity).toBe("critical");
  });

  it("detects genuine exposed .git/HEAD containing ref pointer", () => {
    const gitHead = `ref: refs/heads/main\n`;
    const ex = makeExchange("https://example.com/.git/HEAD", gitHead, "text/plain");
    const observations = checkExposedFile(ex);
    expect(observations).toHaveLength(1);
    expect(observations[0].title).toBe("Exposed .git repository metadata");
  });
});
