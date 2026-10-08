/**
 * Subset of scanner-core safe to import from browser/client code (the
 * Next.js frontend). Deliberately excludes httpClient.ts, crawler.ts, and
 * engine.ts, which import Node built-ins (node:dns/promises, etc.) and
 * would break a browser bundle if pulled in transitively through a
 * barrel export. Add new browser-safe exports here explicitly rather
 * than switching the frontend to the root index.
 */
export * from "./types.js";
export * from "./correlation.js";
export * from "./riskScoring.js";
