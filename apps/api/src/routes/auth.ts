import type { FastifyInstance } from "fastify";
import { prisma } from "../lib/prisma.js";
import { hashPassword, verifyPassword, signSessionToken } from "../lib/auth.js";
import { registerSchema, loginSchema } from "../lib/schemas.js";
import { SESSION_COOKIE } from "../plugins/authPlugin.js";
import { recordAuditEvent } from "../services/auditLog.js";

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

    const token = signSessionToken({ userId: user.id, email: user.email });
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

    const token = signSessionToken({ userId: user.id, email: user.email });
    reply.setCookie(SESSION_COOKIE, token, COOKIE_OPTS);
    return reply.send({ user: { id: user.id, email: user.email, name: user.name } });
  });

  app.post("/api/auth/logout", async (req, reply) => {
    reply.clearCookie(SESSION_COOKIE, { path: "/" });
    return reply.send({ ok: true });
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
