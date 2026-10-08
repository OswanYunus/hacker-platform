import { describe, it, expect } from "vitest";
import { signSessionToken, verifySessionToken, hashPassword, verifyPassword } from "../lib/auth.js";

describe("session tokens", () => {
  it("round-trips a signed token", () => {
    const token = signSessionToken({ userId: "u1", email: "a@example.com" });
    const payload = verifySessionToken(token);
    expect(payload.userId).toBe("u1");
    expect(payload.email).toBe("a@example.com");
  });

  it("rejects a tampered token", () => {
    const token = signSessionToken({ userId: "u1", email: "a@example.com" });
    expect(() => verifySessionToken(token + "tampered")).toThrow();
  });
});

describe("password hashing", () => {
  it("verifies a correct password and rejects an incorrect one", async () => {
    const hash = await hashPassword("correct-horse-battery-staple");
    expect(await verifyPassword(hash, "correct-horse-battery-staple")).toBe(true);
    expect(await verifyPassword(hash, "wrong-password")).toBe(false);
  });
});
