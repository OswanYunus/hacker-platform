import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { resolveTxt } from "node:dns/promises";

const TXT_PREFIX = "hacker-platform-verification=";

export interface VerifiableTarget {
  type: string;
  value: string;
  verificationRecordName?: string | null;
  verificationTokenHash?: Uint8Array | Buffer | string | null;
}

export function targetHostname(target: Pick<VerifiableTarget, "type" | "value">): string {
  if (target.type === "IP_RANGE") {
    throw new Error("IP ranges cannot be ownership-verified with a DNS TXT record.");
  }
  let url: URL;
  try {
    const value = /^https?:\/\//i.test(target.value) ? target.value : `https://${target.value}`;
    url = new URL(value);
  } catch {
    throw new Error("Target must contain a valid public DNS hostname.");
  }
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!host || isIP(host)) throw new Error("Target must use a DNS hostname, not an IP address.");
  return host;
}

export function targetBaseUrl(target: Pick<VerifiableTarget, "type" | "value">): string {
  const value = target.value.trim();
  const hasHttpScheme = /^https?:\/\//i.test(value);
  const hasOtherScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value) && !hasHttpScheme;
  if (hasOtherScheme) throw new Error("Target URL must use HTTP or HTTPS.");
  const url = new URL(hasHttpScheme ? value : `https://${value}`);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Target URL must use HTTP or HTTPS.");
  }
  return url.toString();
}

/**
 * Temporary operator-configured bypass for explicitly allowlisted hostnames.
 * Entries are exact DNS names only; wildcard entries are deliberately ignored.
 */
export function isDnsVerificationExempt(hostname: string, configuredHosts = process.env.DNS_VERIFICATION_EXEMPT_HOSTS ?? ""): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (!host || isIP(host) !== 0 || host.includes("*") || host.includes("/") || host.includes(":")) return false;
  return configuredHosts.split(",").some((entry) => {
    const configured = entry.trim().toLowerCase().replace(/\.$/, "");
    return configured.length > 0 && !configured.includes("*") && configured === host;
  });
}

export function canSkipDnsVerificationForTarget(
  hostname: string,
  allowedHosts: string[],
  configuredHosts = process.env.DNS_VERIFICATION_EXEMPT_HOSTS ?? "",
): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const explicitlyInScope = allowedHosts.some((allowedHost) => allowedHost.toLowerCase().replace(/\.$/, "") === host);
  return explicitlyInScope && isDnsVerificationExempt(host, configuredHosts);
}

export function createDnsChallenge(target: Pick<VerifiableTarget, "type" | "value">) {
  const hostname = targetHostname(target);
  const value = `${TXT_PREFIX}${randomBytes(32).toString("hex")}`;
  return {
    hostname,
    recordName: `_hacker-platform-verification.${hostname}`,
    value,
    tokenHash: hashTxtValue(value),
  };
}

export function hashTxtValue(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

export async function hasValidDnsChallenge(target: VerifiableTarget): Promise<boolean> {
  if (!target.verificationRecordName || !target.verificationTokenHash) return false;
  const expectedHash = Buffer.isBuffer(target.verificationTokenHash)
    ? target.verificationTokenHash
    : Buffer.from(target.verificationTokenHash);
  if (expectedHash.length !== 32) return false;
  try {
    const records = await resolveTxt(target.verificationRecordName);
    return records.some((parts) => {
      const candidateHash = hashTxtValue(parts.join(""));
      return candidateHash.length === expectedHash.length && timingSafeEqual(candidateHash, expectedHash);
    });
  } catch {
    return false;
  }
}

export function targetCoversAllowedHost(targetHost: string, allowedHost: string): boolean {
  const target = targetHost.toLowerCase();
  const allowed = allowedHost.toLowerCase();
  if (allowed.startsWith("*.")) return target === allowed.slice(2);
  return target === allowed || allowed.endsWith(`.${target}`);
}

export function targetsCoverAllowedHosts<T extends VerifiableTarget & { id: string }>(
  allowedHosts: string[],
  targets: T[],
): { targets: T[]; unmatchedHosts: string[] } {
  const targetHosts = new Map<string, T>();
  for (const target of targets) {
    try {
      targetHosts.set(targetHostname(target), target);
    } catch {
      // IP ranges and malformed targets cannot prove DNS control.
    }
  }
  const unmatchedHosts = allowedHosts.filter((allowedHost) =>
    !Array.from(targetHosts.keys()).some((host) => targetCoversAllowedHost(host, allowedHost)),
  );
  const usedTargets = new Set<string>();
  for (const allowedHost of allowedHosts) {
    const target = Array.from(targetHosts.entries()).find(([host]) => targetCoversAllowedHost(host, allowedHost))?.[1];
    if (target) usedTargets.add(target.id);
  }
  return { targets: targets.filter((target) => usedTargets.has(target.id)), unmatchedHosts };
}
