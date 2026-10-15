import { lookup } from "node:dns/promises";
import type { AuthorizationScope, AuthContext, HttpExchange, HttpRequestRecord, HttpResponseRecord, ScanStage } from "./types.js";
import { validateScope, isForbiddenIpv4, isForbiddenIpv6 } from "./scope.js";

export class ScopeViolationError extends Error {}
export class BudgetExceededError extends Error {}

export interface ScannerHttpClientOptions {
  scope: AuthorizationScope;
  auth?: AuthContext;
  userAgent?: string;
  /** Called with every completed exchange, for live streaming + evidence storage. */
  onExchange?: (exchange: HttpExchange) => void;
  /** Hard cap independent of scope.maxTotalRequests, used to bound a single stage. */
  maxRequestsOverride?: number;
}

/**
 * All scanner modules issue requests through this client, never through a
 * bare fetch. It is the single enforcement point for:
 *  - scope (host/path allow+deny lists)
 *  - SSRF protection (resolves DNS and rejects private/reserved IPs,
 *    re-checked on every redirect hop — a target cannot bounce the
 *    scanner into internal infrastructure via a 3xx response)
 *  - rate limiting (requests/second from scope)
 *  - total request budget and scan duration budget
 */
export class ScannerHttpClient {
  private requestCount = 0;
  private readonly startedAt = Date.now();
  private lastRequestAt = 0;

  constructor(private readonly opts: ScannerHttpClientOptions) {}

  get totalRequests(): number {
    return this.requestCount;
  }

  private checkBudgets(): void {
    const elapsedS = (Date.now() - this.startedAt) / 1000;
    if (elapsedS > this.opts.scope.maxScanDurationSeconds) {
      throw new BudgetExceededError("Maximum scan duration exceeded");
    }
    const cap = this.opts.maxRequestsOverride ?? this.opts.scope.maxTotalRequests;
    if (this.requestCount >= cap) {
      throw new BudgetExceededError("Maximum request budget for this scan exceeded");
    }
  }

  private async throttle(): Promise<void> {
    const minIntervalMs = 1000 / Math.max(this.opts.scope.maxRequestsPerSecond, 0.1);
    const wait = this.lastRequestAt + minIntervalMs - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    this.lastRequestAt = Date.now();
  }

  /** DNS-resolves the host and rejects private/reserved/loopback targets.
   * This runs on the initial URL and again on every redirect hop. */
  private async assertResolvesToPublicAddress(hostname: string): Promise<void> {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
      if (isForbiddenIpv4(hostname)) throw new ScopeViolationError(`${hostname} is a private/reserved address`);
      return;
    }
    if (hostname.includes(":")) {
      if (isForbiddenIpv6(hostname)) throw new ScopeViolationError(`${hostname} is a private/reserved address`);
      return;
    }
    try {
      const results = await lookup(hostname, { all: true });
      for (const r of results) {
        if (r.family === 4 && isForbiddenIpv4(r.address)) {
          throw new ScopeViolationError(`${hostname} resolves to private/reserved address ${r.address}`);
        }
        if (r.family === 6 && isForbiddenIpv6(r.address)) {
          throw new ScopeViolationError(`${hostname} resolves to private/reserved address ${r.address}`);
        }
      }
    } catch (e) {
      if (e instanceof ScopeViolationError) throw e;
      throw new ScopeViolationError(`DNS resolution failed for ${hostname}: ${(e as Error).message}`);
    }
  }

  private buildHeaders(extra?: Record<string, string>, anonymous = false): Record<string, string> {
    const headers: Record<string, string> = {
      "User-Agent": this.opts.userAgent ?? "HackerScanner/0.1 (+authorized-security-assessment)",
      ...extra,
    };
    if (!anonymous && this.opts.auth?.cookieHeader) headers["Cookie"] = this.opts.auth.cookieHeader;
    if (!anonymous && this.opts.auth?.bearerToken) headers["Authorization"] = `Bearer ${this.opts.auth.bearerToken}`;
    if (!anonymous && this.opts.auth?.extraHeaders) Object.assign(headers, this.opts.auth.extraHeaders);
    return headers;
  }

  /**
   * Issues a single request with manual redirect handling so each hop is
   * re-validated against scope and SSRF rules before being followed.
   */
  async request(
    method: string,
    url: string,
    stage: ScanStage,
    init?: { headers?: Record<string, string>; body?: string; maxRedirects?: number; anonymous?: boolean },
  ): Promise<HttpExchange> {
    this.checkBudgets();

    const maxRedirects = init?.maxRedirects ?? 5;
    let currentUrl = url;
    let hop = 0;
    let lastRequest: HttpRequestRecord;
    let lastResponse: HttpResponseRecord;

    for (;;) {
      const validation = validateScope(currentUrl, this.opts.scope);
      if (!validation.inScope) {
        throw new ScopeViolationError(`${currentUrl}: ${validation.reason}`);
      }
      const parsed = new URL(currentUrl);
      await this.assertResolvesToPublicAddress(parsed.hostname);

      await this.throttle();
      this.requestCount++;

      const start = Date.now();
      const headers = this.buildHeaders(init?.headers, init?.anonymous);
      const res = await fetch(currentUrl, {
        method,
        headers,
        body: init?.body,
        redirect: "manual",
      });
      const timingMs = Date.now() - start;

      const resHeaders: Record<string, string> = {};
      res.headers.forEach((v, k) => (resHeaders[k] = v));

      const bodyText = await safeReadBody(res);

      lastRequest = { method, url: currentUrl, headers, bodyPreview: init?.body?.slice(0, 500) };
      lastResponse = {
        status: res.status,
        headers: resHeaders,
        body: bodyText,
        bodyPreview: bodyText?.slice(0, 2000),
        timingMs,
      };

      const isRedirect = res.status >= 300 && res.status < 400 && resHeaders["location"];
      if (isRedirect && hop < maxRedirects) {
        currentUrl = new URL(resHeaders["location"], currentUrl).toString();
        hop++;
        continue;
      }
      break;
    }

    const exchange: HttpExchange = {
      id: cryptoRandomId(),
      request: lastRequest,
      response: lastResponse,
      stage,
      discoveredAt: new Date().toISOString(),
      actorRole: init?.anonymous ? undefined : this.opts.auth?.role,
    };
    this.opts.onExchange?.(exchange);
    return exchange;
  }

  get(url: string, stage: ScanStage, headers?: Record<string, string>) {
    return this.request("GET", url, stage, { headers });
  }
}

async function safeReadBody(res: Response, maxBytes = 2_000_000): Promise<string | undefined> {
  try {
    const reader = res.body?.getReader();
    if (!reader) return await res.text();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) break;
      chunks.push(value);
    }
    const buf = Buffer.concat(chunks.map((c) => Buffer.from(c)));
    return buf.toString("utf-8");
  } catch {
    return undefined;
  }
}

function cryptoRandomId(): string {
  return "ex_" + Math.random().toString(36).slice(2) + Date.now().toString(36);
}
