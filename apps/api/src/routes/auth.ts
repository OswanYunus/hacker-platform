import type { FastifyInstance } from "fastify";
import { prisma } from "../lib/prisma.js";
import { hashPassword, verifyPassword, signSessionToken } from "../lib/auth.js";
import { forgotPasswordSchema, loginSchema, registerSchema, resetPasswordSchema } from "../lib/schemas.js";
import { SESSION_COOKIE } from "../plugins/authPlugin.js";
import { recordAuditEvent } from "../services/auditLog.js";
import { createHash, randomBytes } from "node:crypto";

const COOKIE_OPTS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax" as const,
  path: "/",
  maxAge: 12 * 60 * 60,
};

export default async function authRoutes(app: FastifyInstance) {
  app.post("/api/auth/register", async (req, reply) => {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });
    const { email, password, name, organizationName } = parsed.data;

    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return reply.code(409).send({ error: "An account with this email already exists" });

    const passwordHash = await hashPassword(password);

    const { user, organization } = await prisma.$transaction(async (tx: any) => {
      const organization = await tx.organization.create({ data: { name: organizationName } });
      const user = await tx.user.create({ data: { email, passwordHash, name } });
      await tx.orgMembership.create({ data: { userId: user.id, organizationId: organization.id, role: "OWNER" } });
      return { user, organization };
    });

    await recordAuditEvent({
      organizationId: organization.id,
      actorId: user.id,
      action: "organization.created",
      targetType: "Organization",
      targetId: organization.id,
      ipAddress: req.ip,
    });

    const token = signSessionToken({ userId: user.id, email: user.email, sessionVersion: user.sessionVersion });
    reply.setCookie(SESSION_COOKIE, token, COOKIE_OPTS);
    return reply.code(201).send({ user: { id: user.id, email: user.email, name: user.name }, organization: { id: organization.id, name: organization.name } });
  });

  app.post("/api/auth/login", async (req, reply) => {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });
    const { email, password } = parsed.data;

    const user = await prisma.user.findUnique({ where: { email } });
    // Constant-shape response whether the user exists or not, to avoid
    // user-enumeration via timing/response differences.
    const valid = user ? await verifyPassword(user.passwordHash, password) : await verifyPassword(DUMMY_HASH, password);
    if (!user || !valid) return reply.code(401).send({ error: "Invalid email or password" });

    const token = signSessionToken({ userId: user.id, email: user.email, sessionVersion: user.sessionVersion });
    reply.setCookie(SESSION_COOKIE, token, COOKIE_OPTS);
    return reply.send({ user: { id: user.id, email: user.email, name: user.name } });
  });

  app.post("/api/auth/logout", async (req, reply) => {
    reply.clearCookie(SESSION_COOKIE, { path: "/" });
    return reply.send({ ok: true });
  });

  app.post("/api/auth/forgot-password", async (req, reply) => {
    const parsed = forgotPasswordSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const resendApiKey = process.env.RESEND_API_KEY;
    const emailFrom = process.env.PASSWORD_RESET_EMAIL_FROM;
    const publicAppUrl = process.env.PUBLIC_APP_URL;
    if (!resendApiKey || !emailFrom || !publicAppUrl) {
      return reply.code(503).send({ error: "Password reset email is not configured on this deployment." });
    }

    const user = await prisma.user.findUnique({ where: { email: parsed.data.email } });
    if (user) {
      const rawToken = randomBytes(32).toString("hex");
      const tokenHash = createHash("sha256").update(rawToken).digest("hex");
      const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
      await prisma.$transaction([
        prisma.passwordResetToken.deleteMany({ where: { userId: user.id, usedAt: null } }),
        prisma.passwordResetToken.create({ data: { userId: user.id, tokenHash, expiresAt } }),
      ]);

      const resetUrl = new URL("/reset-password", publicAppUrl);
      resetUrl.searchParams.set("token", rawToken);
      try {
        const response = await fetch("https://api.resend.com/emails", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${resendApiKey}`,
            "Content-Type": "application/json",
          },
          signal: AbortSignal.timeout(10_000),
          body: JSON.stringify({
            from: emailFrom,
            to: [user.email],
            subject: "Reset your Hacker account password",
            text: `Use this one-time link within 30 minutes to reset your password: ${resetUrl.toString()}`,
            html: `<p>Use this one-time link within 30 minutes to reset your password:</p><p><a href="${resetUrl.toString()}">Reset password</a></p><p>If you did not request this, you can ignore this email.</p>`,
          }),
        });
        if (!response.ok) req.log.error({ statusCode: response.status }, "Password reset email delivery failed");
      } catch {
        req.log.error("Password reset email delivery failed");
      }
    }

    return reply.send({ message: "If an account exists for that email, a password reset link has been sent." });
  });

  app.post("/api/auth/reset-password", async (req, reply) => {
    const parsed = resetPasswordSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: parsed.error.flatten() });

    const tokenHash = createHash("sha256").update(parsed.data.token).digest("hex");
    const now = new Date();
    const resetToken = await prisma.passwordResetToken.findUnique({ where: { tokenHash } });
    if (!resetToken || resetToken.usedAt || resetToken.expiresAt <= now) {
      return reply.code(400).send({ error: "This password reset link is invalid or expired." });
    }

    const passwordHash = await hashPassword(parsed.data.password);
    const completed = await prisma.$transaction(async (tx: any) => {
      const claimed = await tx.passwordResetToken.updateMany({
        where: { id: resetToken.id, usedAt: null, expiresAt: { gt: now } },
        data: { usedAt: now },
      });
      if (claimed.count !== 1) return false;
      await tx.user.update({
        where: { id: resetToken.userId },
        data: { passwordHash, sessionVersion: { increment: 1 } },
      });
      await tx.passwordResetToken.updateMany({
        where: { userId: resetToken.userId, usedAt: null },
        data: { usedAt: now },
      });
      return true;
    });
    if (!completed) return reply.code(400).send({ error: "This password reset link is invalid or expired." });
    return reply.send({ message: "Password updated. Sign in with your new password." });
  });

  app.get("/api/auth/me", async (req, reply) => {
    if (!req.currentUser) return reply.code(401).send({ error: "Not authenticated" });
    const memberships = await prisma.orgMembership.findMany({
      where: { userId: req.currentUser.id },
      include: { organization: true },
    });
    return reply.send({ user: req.currentUser, organizations: memberships.map((m: any) => ({ id: m.organization.id, name: m.organization.name, role: m.role })) });
  });
}

// Pre-computed argon2id hash of a random value, used only to equalize
// timing on login attempts against unknown emails.
const DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHR2YWx1ZQ$Z3K4b0p6b1n8t1N9qv2b1b1n8t1N9qv2b1b1n8t1N9o";
