import { PrismaClient } from "@prisma/client";

// Single shared Prisma instance. In dev with tsx watch this would normally
// be stashed on globalThis to survive hot-reload; omitted here for clarity
// since production runs a single long-lived process per worker/API node.
export const prisma = new PrismaClient({
  log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"],
});
