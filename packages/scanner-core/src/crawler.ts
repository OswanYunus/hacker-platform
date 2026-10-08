import * as cheerio from "cheerio";
import type { ScannerHttpClient } from "./httpClient.js";
import { BudgetExceededError, ScopeViolationError } from "./httpClient.js";
import type { DiscoveredEndpoint, HttpExchange } from "./types.js";
import { validateScope } from "./scope.js";
import type { AuthorizationScope } from "./types.js";

export interface CrawlOptions {
  startUrls: string[];
  scope: AuthorizationScope;
  maxPages: number;
  maxDepth: number;
  onPageCrawled?: (endpoint: DiscoveredEndpoint) => void;
}

export interface CrawlResult {
  endpoints: DiscoveredEndpoint[];
  exchanges: HttpExchange[];
  stopReason: "exhausted" | "max_pages" | "budget_exceeded";
}

/**
 * Simple, dependency-light breadth-first crawler. Deliberately does not
 * execute JavaScript (no headless browser) in Phase 1 — it extracts links,
 * forms, and script src attributes from static HTML, which covers the
 * majority of server-rendered apps and still finds the API surface that
 * SPA bundles reference. A JS-rendering crawler (e.g. via a headless
 * browser pool) is a natural Phase 2/3 addition behind the same
 * CrawlResult interface, so nothing downstream needs to change.
 */
export async function crawl(client: ScannerHttpClient, opts: CrawlOptions): Promise<CrawlResult> {
  const visited = new Set<string>();
  const queue: Array<{ url: string; depth: number }> = opts.startUrls.map((u) => ({ url: normalizeUrl(u), depth: 0 }));
  const endpoints: DiscoveredEndpoint[] = [];
  const exchanges: HttpExchange[] = [];
  const endpointsByUrl = new Map<string, DiscoveredEndpoint>();

  let stopReason: CrawlResult["stopReason"] = "exhausted";

  while (queue.length > 0) {
    if (visited.size >= opts.maxPages) {
      stopReason = "max_pages";
      break;
    }
    const next = queue.shift()!;
    if (visited.has(next.url)) continue;
    if (next.depth > opts.maxDepth) continue;

    const validation = validateScope(next.url, opts.scope);
    if (!validation.inScope) continue;

    visited.add(next.url);

    let exchange: HttpExchange;
    try {
      exchange = await client.get(next.url, "crawling");
    } catch (e) {
      if (e instanceof BudgetExceededError) {
        stopReason = "budget_exceeded";
        break;
      }
      if (e instanceof ScopeViolationError) continue;
      continue; // network error on a single page shouldn't kill the crawl
    }
    exchanges.push(exchange);

    const endpoint = recordEndpoint(endpointsByUrl, endpoints, next.url, exchange, "crawl");

    const contentType = (exchange.response.headers["content-type"] || "").toLowerCase();
    if (!contentType.includes("html") || !exchange.response.body) continue;

    const $ = cheerio.load(exchange.response.body);

    // Links
    $("a[href]").each((_, el) => {
      const href = $(el).attr("href");
      if (!href) return;
      const resolved = safeResolve(href, next.url);
      if (resolved && validateScope(resolved, opts.scope).inScope) {
        queue.push({ url: normalizeUrl(resolved), depth: next.depth + 1 });
      }
    });

    // Forms -> record as endpoints with their fields/method
    $("form").each((_, el) => {
      const action = $(el).attr("action") || next.url;
      const method = ($(el).attr("method") || "GET").toUpperCase();
      const resolved = safeResolve(action, next.url);
      if (!resolved || !validateScope(resolved, opts.scope).inScope) return;
      const fields = $(el)
        .find("input[name], select[name], textarea[name]")
        .map((_, f) => $(f).attr("name"))
        .get()
        .filter(Boolean) as string[];
      const formEndpoint = recordEndpoint(endpointsByUrl, endpoints, resolved, undefined, "crawl");
      formEndpoint.methodsObserved = Array.from(new Set([...formEndpoint.methodsObserved, method]));
      formEndpoint.formFields = Array.from(new Set([...formEndpoint.formFields, ...fields]));
      formEndpoint.parentUrl = next.url;
      if (method === "GET") queue.push({ url: normalizeUrl(resolved), depth: next.depth + 1 });
    });

    // JS resources — not fetched/executed here, but recorded so a later
    // stage (client-side scanner) can fetch and scan them for endpoint
    // references and embedded secrets.
    $("script[src]").each((_, el) => {
      const src = $(el).attr("src");
      const resolved = src && safeResolve(src, next.url);
      if (resolved && validateScope(resolved, opts.scope).inScope) {
        queue.push({ url: normalizeUrl(resolved), depth: next.depth + 1 });
      }
    });

    opts.onPageCrawled?.(endpoint);
  }

  return { endpoints, exchanges, stopReason };
}

function recordEndpoint(
  map: Map<string, DiscoveredEndpoint>,
  list: DiscoveredEndpoint[],
  url: string,
  exchange: HttpExchange | undefined,
  sourceType: DiscoveredEndpoint["sourceType"],
): DiscoveredEndpoint {
  const key = normalizeUrl(url);
  let endpoint = map.get(key);
  if (!endpoint) {
    const parsed = new URL(key);
    endpoint = {
      url: key,
      methodsObserved: [],
      statusCodesObserved: [],
      queryParams: Array.from(parsed.searchParams.keys()),
      formFields: [],
      requiresAuth: "unknown",
      sourceType,
      contentType: exchange?.response.headers["content-type"],
    };
    map.set(key, endpoint);
    list.push(endpoint);
  }
  if (exchange) {
    endpoint.methodsObserved = Array.from(new Set([...endpoint.methodsObserved, exchange.request.method]));
    endpoint.statusCodesObserved = Array.from(new Set([...endpoint.statusCodesObserved, exchange.response.status]));
    if (exchange.response.status === 401 || exchange.response.status === 403) endpoint.requiresAuth = true;
  }
  return endpoint;
}

function safeResolve(href: string, base: string): string | null {
  try {
    if (href.startsWith("mailto:") || href.startsWith("tel:") || href.startsWith("javascript:")) return null;
    return new URL(href, base).toString();
  } catch {
    return null;
  }
}

function normalizeUrl(url: string): string {
  const u = new URL(url);
  u.hash = "";
  return u.toString();
}
