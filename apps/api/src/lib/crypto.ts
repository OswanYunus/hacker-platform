import { randomBytes, createCipheriv, createDecipheriv, createHash } from "node:crypto";

/**
 * Envelope encryption for anything sensitive we must store: test-account
 * passwords, session cookies, bearer tokens, CI webhook secrets.
 *
 * MASTER_KEY is read from the environment (32 bytes, base64). In a real
 * deployment this should come from a KMS (AWS KMS / GCP KMS / Vault) that
 * hands back a per-record data key; env-var storage of the master key is
 * the documented interface for local/dev and should be swapped for a KMS
 * call in `getMasterKey()` before production use with real customer data.
 */
function getMasterKey(): Buffer {
  const raw = process.env.MASTER_ENCRYPTION_KEY;
  if (!raw) {
    throw new Error(
      "MASTER_ENCRYPTION_KEY is not set. Generate one with `openssl rand -base64 32` and set it in your .env. " +
        "In production, replace this with a KMS-backed key provider.",
    );
  }
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) {
    throw new Error("MASTER_ENCRYPTION_KEY must decode to exactly 32 bytes.");
  }
  return key;
}

export interface EncryptedSecret {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

export function encryptSecret(plaintext: string): EncryptedSecret {
  const key = getMasterKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { ciphertext, iv, authTag };
}

export function decryptSecret(secret: EncryptedSecret): string {
  const key = getMasterKey();
  const decipher = createDecipheriv("aes-256-gcm", key, secret.iv);
  decipher.setAuthTag(secret.authTag);
  const plaintext = Buffer.concat([decipher.update(secret.ciphertext), decipher.final()]);
  return plaintext.toString("utf8");
}

/** Non-reversible fingerprint used for audit logs / dedup without storing
 * the raw secret value anywhere, even encrypted-and-displayed. */
export function fingerprint(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}
