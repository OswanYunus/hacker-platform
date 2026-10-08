import { describe, it, expect } from "vitest";
import { encryptSecret, decryptSecret, fingerprint } from "../lib/crypto.js";

describe("secret encryption", () => {
  it("round-trips a plaintext value", () => {
    const enc = encryptSecret("super-secret-session-cookie-value");
    const decrypted = decryptSecret(enc);
    expect(decrypted).toBe("super-secret-session-cookie-value");
  });

  it("never stores the plaintext inside the ciphertext bytes", () => {
    const plaintext = "sk_live_abcdef1234567890";
    const enc = encryptSecret(plaintext);
    expect(enc.ciphertext.toString("utf8")).not.toContain(plaintext);
  });

  it("fails to decrypt with a tampered auth tag", () => {
    const enc = encryptSecret("value");
    enc.authTag[0] ^= 0xff;
    expect(() => decryptSecret(enc)).toThrow();
  });

  it("produces a stable fingerprint for the same input", () => {
    expect(fingerprint("abc")).toBe(fingerprint("abc"));
    expect(fingerprint("abc")).not.toBe(fingerprint("abd"));
  });
});
