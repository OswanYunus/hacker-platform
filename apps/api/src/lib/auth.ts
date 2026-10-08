import jwt from "jsonwebtoken";
import argon2 from "argon2";

function getSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("JWT_SECRET must be set to a random string of at least 32 characters.");
  }
  return secret;
}

export interface SessionTokenPayload {
  userId: string;
  email: string;
}

export function signSessionToken(payload: SessionTokenPayload): string {
  return jwt.sign(payload, getSecret(), { expiresIn: "12h" });
}

export function verifySessionToken(token: string): SessionTokenPayload {
  return jwt.verify(token, getSecret()) as SessionTokenPayload;
}

export function hashPassword(plain: string): Promise<string> {
  // argon2id: current OWASP-recommended default for password hashing.
  return argon2.hash(plain, { type: argon2.argon2id });
}

export function verifyPassword(hash: string, plain: string): Promise<boolean> {
  return argon2.verify(hash, plain);
}
