import type { AuthorizationScope, ScopeValidationResult } from "./types.js";

/**
 * Private/reserved IP ranges the scanner must never contact, even if a
 * redirect, a DNS answer, or a discovered link points there. This is the
 * SSRF backstop: scope defines what a human authorized, this defines what
 * the network is physically allowed to touch, independent of scope.
 *
 * Kept intentionally conservative — it is cheaper to require an operator
 * to explicitly allow a range (not currently supported for these blocks)
 * than to let a malicious or compromised target redirect the scanner into
 * internal infrastructure.
 */
const FORBIDDEN_IPV4_RANGES: Array<[string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10], // CGNAT
  ["127.0.0.0", 8],
  ["169.254.0.0", 16], // link-local / cloud metadata
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4],
];

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0;
}

export function isForbiddenIpv4(ip: string): boolean {
  const target = ipv4ToInt(ip);
  if (target === null) return false;
  for (const [base, prefix] of FORBIDDEN_IPV4_RANGES) {
    const baseInt = ipv4ToInt(base)!;
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    if ((target & mask) === (baseInt & mask)) return true;
  }
  return false;
}

/** IPv6 loopback/link-local/unique-local/metadata guard. */
export function isForbiddenIpv6(ip: string): boolean {
  const norm = ip.toLowerCase();
  if (norm === "::1") return true;
  if (norm.startsWith("fe80:")) return true; // link-local
  if (norm.startsWith("fc") || norm.startsWith("fd")) return true; // unique local
  if (norm.startsWith("::ffff:")) {
    const v4 = norm.split(":").pop();
    if (v4 && v4.includes(".")) return isForbiddenIpv4(v4);
  }
  return false;
}

function hostMatches(host: string, pattern: string): boolean {
  const h = host.toLowerCase();
  const p = pattern.toLowerCase();
  if (p.startsWith("*.")) {
    const suffix = p.slice(1); // ".example.com"
    return h.endsWith(suffix) && h !== suffix.slice(1);
  }
  return h === p;
}

function pathMatches(path: string, prefix: string): boolean {
  if (prefix === "/" || prefix === "") return true;
  return path === prefix || path.startsWith(prefix.endsWith("/") ? prefix : prefix + "/") || path === prefix;
}

/**
 * The single gate every scanner request must pass through. Pure function,
 * no network access, so it is fully unit-testable and cannot be bypassed
 * by a module that "forgets" to check — the HTTP client wrapper (see
 * httpClient.ts) calls this unconditionally before dialing out.
 */
export function validateScope(urlStr: string, scope: AuthorizationScope): ScopeValidationResult {
  let url: URL;
  try {
    url = new URL(urlStr);
  } catch {
    return { inScope: false, reason: "URL could not be parsed" };
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { inScope: false, reason: `Protocol ${url.protocol} is not permitted` };
  }

  // Literal IPv4 host given directly — check against the forbidden ranges.
  if (/^\d+\.\d+\.\d+\.\d+$/.test(url.hostname) && isForbiddenIpv4(url.hostname)) {
    return { inScope: false, reason: "Target resolves to a private/reserved IP range" };
  }
  if (url.hostname.includes(":") && isForbiddenIpv6(url.hostname)) {
    return { inScope: false, reason: "Target resolves to a private/reserved IPv6 range" };
  }

  const hostAllowed = scope.allowedHosts.some((h) => hostMatches(url.hostname, h));
  if (!hostAllowed) {
    return { inScope: false, reason: `Host ${url.hostname} is not in the authorized host list` };
  }

  if (scope.excludedPaths?.some((p) => pathMatches(url.pathname, p))) {
    return { inScope: false, reason: `Path ${url.pathname} is explicitly excluded from scope` };
  }

  if (scope.allowedPaths && scope.allowedPaths.length > 0) {
    const allowed = scope.allowedPaths.some((p) => pathMatches(url.pathname, p));
    if (!allowed) {
      return { inScope: false, reason: `Path ${url.pathname} is not in the authorized path list` };
    }
  }

  return { inScope: true };
}

export function assertActiveTestingAllowed(scope: AuthorizationScope): void {
  if (!scope.activeTestingAllowed) {
    throw new Error(
      "Active testing was requested but this project's scope has activeTestingAllowed=false. " +
        "Passive-only analysis may still run.",
    );
  }
}
