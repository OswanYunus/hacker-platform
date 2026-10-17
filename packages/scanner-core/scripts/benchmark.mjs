import { writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { checkSqliGetParams, checkReflectedXss, checkPathTraversal, checkSsti, checkOpenRedirect } from "../dist/checks/injection.js";

// Deterministic in-process transport fixtures: no external network access.
// Values are synthetic and rule ground truth is declared below.
const endpoint = { url: "http://127.0.0.1:43123/item?id=1", methodsObserved: ["GET"], statusCodesObserved: [200], queryParams: ["id"], formFields: [], requiresAuth: false, sourceType: "manual" };
const families = [
  ["sqli", (c) => checkSqliGetParams(c, endpoint), (u) => u.includes("%27") ? "SQL syntax error" : "ordinary record"],
  ["reflected-xss", (c) => checkReflectedXss(c, endpoint), (u) => u.includes("%3Cscript%3E") ? "<html><script>alert(1)</script></html>" : "<html>safe</html>"],
  ["path-traversal", (c) => checkPathTraversal(c, { ...endpoint, queryParams: ["file"] }), (u) => u.includes("scan-benchmark-canary") ? "SCAN_BENCHMARK_CANARY_X7" : "not found"],
  ["ssti", (c) => checkSsti(c, endpoint), (u) => u.includes("%7B%7B7*7%7D%7D") ? "49" : "none"],
  ["open-redirect", (c) => checkOpenRedirect(c, endpoint), (u) => u.includes("scan-probe-redir.invalid.example") ? "https://scan-probe-redir.invalid.example/path" : ""],
];
function fixtureClient(family, positive) {
  const counts = new Map(); let requests = 0;
  const send = async (url) => {
    requests++; const call = (counts.get(url) ?? 0) + 1; counts.set(url, call);
    const value = positive ? family[2](url) : (family[0] === "open-redirect" ? "" : "safe ordinary response");
    const redirect = family[0] === "open-redirect";
    const isDelay = false;
    const body = redirect ? "redirect" : isDelay ? "done" : value;
    return { response: { status: redirect && value ? 302 : 200, body, bodyPreview: body, headers: { "content-type": "text/html", ...(redirect && value ? { location: value } : {}) }, timingMs: isDelay ? 5200 : 100 + requests % 7 } };
  };
  return { client: { get: send, request: (_method, url) => send(url) }, get requests() { return requests; } };
}
const results = [];
for (const family of families) {
  const runs = [];
  for (let repeat = 0; repeat < 3; repeat++) {
    const started = performance.now();
    const vulnerable = fixtureClient(family, true);
    const safe = fixtureClient(family, false);
    const positiveFindings = await family[1](vulnerable.client);
    const negativeFindings = await family[1](safe.client);
    runs.push({ expected: 1, detected: positiveFindings.length > 0 ? 1 : 0, falsePositives: negativeFindings.length > 0 ? 1 : 0, findings: positiveFindings.map((f) => ({ ruleId: f.ruleId, confidence: f.confidence, verification: f.verification })), requests: vulnerable.requests + safe.requests, runtimeMs: Number((performance.now() - started).toFixed(2)) });
  }
  const tp = runs.reduce((n, r) => n + r.detected, 0), fp = runs.reduce((n, r) => n + r.falsePositives, 0), fn = runs.length - tp;
  results.push({ family: family[0], fixtureCount: 2, repetitions: runs.length, truePositives: tp, falsePositives: fp, falseNegatives: fn, precision: tp + fp ? tp / (tp + fp) : null, recall: tp + fn ? tp / (tp + fn) : null, repeatability: tp / runs.length, totalRequests: runs.reduce((n, r) => n + r.requests, 0), totalRuntimeMs: Number(runs.reduce((n, r) => n + r.runtimeMs, 0).toFixed(2)), runs });
}
const output = process.argv[2] ?? "security-benchmark-results.json";
await writeFile(output, JSON.stringify({ benchmark: "synthetic-injection-validator-fixtures", generatedAt: new Date().toISOString(), transport: "deterministic in-process fixture; no network requests", groundTruth: "one vulnerable and one safe synthetic response fixture per family; 3 repetitions per fixture", results }, null, 2));
console.log(JSON.stringify({ output, results }, null, 2));
