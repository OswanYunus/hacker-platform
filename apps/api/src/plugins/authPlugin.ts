import fp from "fastify-plugin";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { verifySessionToken } from "../lib/auth.js";
import { prisma } from "../lib/prisma.js";

declare module "fastify" {
  interface FastifyRequest {
    currentUser?: { id: string; email: string; name: string };
  }
}

export const SESSION_COOKIE = "hacker_session";

export default fp(async function authPlugin(app: FastifyInstance) {
  app.decorateRequest("currentUser", undefined);

  app.addHook("onRequest", async (req: FastifyRequest) => {
    const token = req.cookies?.[SESSION_COOKIE] ?? bearerToken(req);
    if (!token) return;
    try {
      const payload = verifySessionToken(token);
      const user = await prisma.user.findUnique({
        where: { id: payload.userId },
        select: { id: true, email: true, name: true, sessionVersion: true },
      });
      if (user && user.sessionVersion === payload.sessionVersion) {
        req.currentUser = { id: user.id, email: user.email, name: user.name };
      }
    } catch {
      // invalid/expired token: leave currentUser unset, routes that
      // require auth will reject via requireAuth()
    }
  });
});

function bearerToken(req: FastifyRequest): string | undefined {
  const header = req.headers.authorization;
  if (header?.startsWith("Bearer ")) return header.slice(7);
  return undefined;
}

export function requireAuth(req: FastifyRequest, reply: FastifyReply): req is FastifyRequest & { currentUser: NonNullable<FastifyRequest["currentUser"]> } {
  if (!req.currentUser) {
    reply.code(401).send({ error: "Authentication required" });
    return false;
  }
  return true;
}

/** Confirms the current user belongs to the organization that owns
 * `projectId`, and returns the project (with org) if so. Every project-
 * scoped route must call this before touching project data — it is the
 * tenant-isolation boundary. */
export async function requireProjectAccess(req: FastifyRequest, reply: FastifyReply, projectId: string) {
  if (!req.currentUser) {
    reply.code(401).send({ error: "Authentication required" });
    return null;
  }
  const project = await prisma.project.findUnique({
    where: { id: projectId },
    include: { organization: true },
  });
  if (!project) {
    reply.code(404).send({ error: "Project not found" });
    return null;
  }
  const membership = await prisma.orgMembership.findUnique({
    where: { userId_organizationId: { userId: req.currentUser.id, organizationId: project.organizationId } },
  });
  if (!membership) {
    reply.code(403).send({ error: "You do not have access to this project" });
    return null;
  }
  return { project, membership };
}
