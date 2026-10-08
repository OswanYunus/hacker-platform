import { describe, it, expect } from "vitest";
import { checkCookies } from "../checks/cookies.js";
import { mockExchange } from "./fixtures.js";

describe("checkCookies", () => {
  it("flags a session cookie missing HttpOnly and Secure as high severity", () => {
    const ex = mockExchange({
      url: "https://example.com/login",
      responseHeaders: { "set-cookie": "sessionid=abc123; Path=/" },
    });
    const findings = checkCookies(ex);
    const httpOnly = findings.find((f) => f.ruleId === "cookie-missing-httponly");
    const secure = findings.find((f) => f.ruleId === "cookie-missing-secure");
    expect(httpOnly?.severity).toBe("high");
    expect(secure?.severity).toBe("high");
  });

  it("does not flag a cookie that already has Secure, HttpOnly, and SameSite", () => {
    const ex = mockExchange({
      url: "https://example.com/login",
      responseHeaders: { "set-cookie": "sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax" },
    });
    expect(checkCookies(ex)).toHaveLength(0);
  });

  it("gives low severity to a non-session cookie missing Secure", () => {
    const ex = mockExchange({
      url: "https://example.com/",
      responseHeaders: { "set-cookie": "theme=dark; Path=/" },
    });
    const findings = checkCookies(ex);
    const secure = findings.find((f) => f.ruleId === "cookie-missing-secure");
    expect(secure?.severity).toBe("low");
  });

  it("does not misparse the Expires date as a second cookie", () => {
    const ex = mockExchange({
      url: "https://example.com/",
      responseHeaders: {
        "set-cookie": "sessionid=abc123; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/; Secure; HttpOnly",
      },
    });
    const findings = checkCookies(ex);
    // Only the SameSite gap should fire; Secure/HttpOnly are present and the
    // Expires date must not be parsed as an unrelated malformed cookie.
    expect(findings.every((f) => f.ruleId !== "cookie-missing-secure")).toBe(true);
    expect(findings.every((f) => f.ruleId !== "cookie-missing-httponly")).toBe(true);
  });

  it("returns nothing when no Set-Cookie header is present", () => {
    const ex = mockExchange({ url: "https://example.com/" });
    expect(checkCookies(ex)).toHaveLength(0);
  });
});
