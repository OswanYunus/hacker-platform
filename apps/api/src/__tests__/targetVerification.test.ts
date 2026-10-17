import { describe, expect, it } from "vitest";
import { canSkipDnsVerificationForTarget, createDnsChallenge, isDnsVerificationExempt, targetBaseUrl, targetCoversAllowedHost, targetHostname } from "../services/targetVerification.js";

describe("target DNS control proof", () => {
  it("normalizes bare domain and URL targets to HTTPS roots", () => {
    expect(targetBaseUrl({ type: "DOMAIN", value: "wa.example.com" })).toBe("https://wa.example.com/");
    expect(targetBaseUrl({ type: "URL", value: "wa.example.com" })).toBe("https://wa.example.com/");
  });

  it("preserves an explicit HTTP(S) URL and rejects other schemes", () => {
    expect(targetBaseUrl({ type: "URL", value: "http://wa.example.com/app" })).toBe("http://wa.example.com/app");
    expect(targetBaseUrl({ type: "URL", value: "https://wa.example.com/app" })).toBe("https://wa.example.com/app");
    expect(() => targetBaseUrl({ type: "URL", value: "ftp://wa.example.com/file" })).toThrow("HTTP or HTTPS");
  });

  it("extracts the hostname from a domain or URL target", () => {
    expect(targetHostname({ type: "DOMAIN", value: "wa.example.com" })).toBe("wa.example.com");
    expect(targetHostname({ type: "URL", value: "https://WA.example.com/account" })).toBe("wa.example.com");
  });

  it("rejects IP and range targets that cannot publish the DNS proof", () => {
    expect(() => targetHostname({ type: "DOMAIN", value: "192.0.2.20" })).toThrow("DNS hostname");
    expect(() => targetHostname({ type: "IP_RANGE", value: "192.0.2.0/24" })).toThrow("IP ranges");
  });

  it("creates an opaque TXT challenge and hashes it for storage", () => {
    const challenge = createDnsChallenge({ type: "DOMAIN", value: "example.com" });
    expect(challenge.recordName).toBe("_hacker-platform-verification.example.com");
    expect(challenge.value).toMatch(/^hacker-platform-verification=[a-f0-9]{64}$/);
    expect(challenge.tokenHash).toHaveLength(32);
    expect(challenge.tokenHash.toString("utf8")).not.toBe(challenge.value);
  });

  it("requires the verified DNS owner to cover each allowed host", () => {
    expect(targetCoversAllowedHost("example.com", "*.example.com")).toBe(true);
    expect(targetCoversAllowedHost("app.example.com", "api.example.com")).toBe(false);
    expect(targetCoversAllowedHost("example.com", "api.example.com")).toBe(true);
    expect(targetCoversAllowedHost("notexample.com", "example.com")).toBe(false);
  });

  it("allows only explicitly configured exact hostnames to skip DNS proof", () => {
    expect(isDnsVerificationExempt("WA.example.com", "wa.example.com")).toBe(true);
    expect(isDnsVerificationExempt("wa.example.com.", "wa.example.com")).toBe(true);
    expect(isDnsVerificationExempt("api.wa.example.com", "wa.example.com")).toBe(false);
    expect(isDnsVerificationExempt("wa.example.com", "*.example.com")).toBe(false);
    expect(isDnsVerificationExempt("wa.example.com", "wa.example.com, staging.example.com")).toBe(true);
    expect(isDnsVerificationExempt("192.0.2.1", "192.0.2.1")).toBe(false);
  });

  it("skips proof only when the exact exempt hostname is itself in the authorized scope", () => {
    expect(canSkipDnsVerificationForTarget("wa.example.com", ["wa.example.com"], "wa.example.com")).toBe(true);
    expect(canSkipDnsVerificationForTarget("wa.example.com", ["*.example.com"], "wa.example.com")).toBe(false);
    expect(canSkipDnsVerificationForTarget("api.wa.example.com", ["wa.example.com"], "wa.example.com")).toBe(false);
    expect(canSkipDnsVerificationForTarget("wa.example.com", ["wa.example.com"], "*.example.com")).toBe(false);
  });
});
