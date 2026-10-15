import Fastify from "fastify";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";

import { fileURLToPath } from "node:url";
import path from "node:path";
import authPlugin from "./plugins/authPlugin.js";
import authRoutes from "./routes/auth.js";
import projectRoutes from "./routes/projects.js";
import scopeRoutes from "./routes/scope.js";
import scanRoutes from "./routes/scans.js";
import reportRoutes from "./routes/reports.js";
import auditRoutes from "./routes/audit.js";

export function buildServer() {
  const app = Fastify({
    logger: {
      level: process.env.LOG_LEVEL ?? "info",
      redact: ["req.headers.authorization", "req.headers.cookie"],
    },
    trustProxy: true,
  });

  app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
  });

  app.register(cors, {
    origin: (process.env.WEB_ORIGIN ?? "http://localhost:3000")
      .split(",")
      .map((origin) => (origin.includes("://") ? origin : `https://${origin}`)),
    credentials: true,
  });

  app.register(rateLimit, {
    global: true,
    max: 300,
    timeWindow: "1 minute",
  });

  app.register(cookie);
  app.register(authPlugin);

  // Stricter limiter specifically for auth endpoints to slow credential
  // stuffing / brute force, applied inside authRoutes via a nested scope.
  app.register(async (scoped) => {
    await scoped.register(rateLimit, { max: 10, timeWindow: "1 minute" });
    await scoped.register(authRoutes);
  });

  app.register(projectRoutes);
  app.register(scopeRoutes);
  app.register(scanRoutes);
  app.register(reportRoutes);
  app.register(auditRoutes);

  app.get("/api/health", async () => ({ status: "ok", time: new Date().toISOString() }));

  return app;
}

async function main() {
  const app = buildServer();
  const port = Number(process.env.PORT ?? 4000);
  try {
    await app.listen({ port, host: "0.0.0.0" });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

// Only auto-start when run directly (not when imported by tests).
const isDirectRun =
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isDirectRun) {
  void main();
}
