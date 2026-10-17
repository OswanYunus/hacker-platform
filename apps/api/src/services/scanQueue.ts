import { hostname } from "node:os";
import { randomUUID } from "node:crypto";
import { prisma } from "../lib/prisma.js";
import { executeScan } from "./scanOrchestrator.js";

const POLL_INTERVAL_MS = 2_000;
const LEASE_MS = 30_000;
const MAX_ATTEMPTS = 3;

export function recoveryDisposition(attempt: number, cancelRequested: boolean): "cancel" | "retry" | "fail" {
  if (cancelRequested) return "cancel";
  return attempt >= MAX_ATTEMPTS ? "fail" : "retry";
}

export interface ScanQueue {
  enqueue(scanId: string): Promise<void>;
  start(): Promise<void>;
  stop(): Promise<void>;
}

/** Atomically claim a persisted QUEUED job. Competing API processes may poll
 * the same row, but only the process that changes its state can execute it. */
export async function claimScan(scanId: string, workerId: string, now = new Date()): Promise<boolean> {
  const result = await prisma.scan.updateMany({
    where: { id: scanId, status: "QUEUED", cancelRequestedAt: null },
    data: {
      status: "RUNNING",
      workerId,
      heartbeatAt: now,
      leaseExpiresAt: new Date(now.getTime() + LEASE_MS),
      startedAt: now,
      completedAt: null,
      failureReason: null,
      currentStage: "scope_validation",
      progressPercent: 0,
      attempt: { increment: 1 },
    },
  });
  return result.count === 1;
}

/** Persist cancellation first so another worker or a restarted process sees it. */
export async function requestScanCancellation(scanId: string): Promise<boolean> {
  const now = new Date();
  const queued = await prisma.scan.updateMany({
    where: { id: scanId, status: "QUEUED" },
    data: { status: "CANCELLED", cancelRequestedAt: now, completedAt: now, stopReason: "cancelled_before_start" },
  });
  if (queued.count === 1) return true;

  const running = await prisma.scan.updateMany({
    where: { id: scanId, status: "RUNNING", cancelRequestedAt: null },
    data: { cancelRequestedAt: now },
  });
  return running.count === 1;
}

/**
 * Database-backed job queue. The Scan row is the durable queue record.
 * Expired jobs are restarted from the beginning after partial outputs are
 * removed; scan requests are read-only and the worker revalidates current
 * authorization and DNS control before any new target request.
 */
export class DatabaseScanQueue implements ScanQueue {
  private readonly workerId = `${hostname()}-${process.pid}-${randomUUID()}`;
  private readonly concurrency: number;
  private running = 0;
  private polling = false;
  private started = false;
  private timer?: NodeJS.Timeout;

  constructor(concurrency = Number(process.env.SCAN_WORKER_CONCURRENCY ?? 2)) {
    this.concurrency = Math.max(1, Math.floor(concurrency));
  }

  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;
    await this.poll();
    this.timer = setInterval(() => void this.poll(), POLL_INTERVAL_MS);
    this.timer.unref();
  }

  async stop(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    this.started = false;
  }

  async enqueue(_scanId: string): Promise<void> {
    // The row was committed as QUEUED before this call. Poll immediately so
    // a wake-up does not wait for the normal interval.
    if (!this.started) await this.start();
    else await this.poll();
  }

  private async poll(): Promise<void> {
    if (this.polling) return;
    this.polling = true;
    try {
      await this.recoverExpiredJobs();
      const capacity = this.concurrency - this.running;
      if (capacity <= 0) return;
      const queued = await prisma.scan.findMany({
        where: { status: "QUEUED", cancelRequestedAt: null },
        select: { id: true },
        orderBy: { createdAt: "asc" },
        take: capacity,
      });
      for (const scan of queued) {
        if (this.running >= this.concurrency) break;
        if (!(await claimScan(scan.id, this.workerId))) continue;
        this.running++;
        void executeScan(scan.id, this.workerId)
          .catch((error) => console.error(`Unhandled scan worker error for ${scan.id}:`, error))
          .finally(() => {
            this.running--;
            if (this.started) void this.poll();
          });
      }
    } finally {
      this.polling = false;
    }
  }

  private async recoverExpiredJobs(): Promise<void> {
    const now = new Date();
    const expired = await prisma.scan.findMany({
      where: {
        status: "RUNNING",
        OR: [{ leaseExpiresAt: null }, { leaseExpiresAt: { lt: now } }],
      },
      select: { id: true, leaseExpiresAt: true, attempt: true, cancelRequestedAt: true },
      take: 100,
    });

    for (const scan of expired) {
      const leaseFilter = scan.leaseExpiresAt === null ? null : { equals: scan.leaseExpiresAt };
      const disposition = recoveryDisposition(scan.attempt, Boolean(scan.cancelRequestedAt));
      if (disposition === "cancel") {
        await prisma.scan.updateMany({
          where: { id: scan.id, status: "RUNNING", leaseExpiresAt: leaseFilter },
          data: { status: "CANCELLED", completedAt: now, stopReason: "cancelled_during_worker_interruption", workerId: null, leaseExpiresAt: null },
        });
        continue;
      }
      if (disposition === "fail") {
        await prisma.scan.updateMany({
          where: { id: scan.id, status: "RUNNING", leaseExpiresAt: leaseFilter },
          data: {
            status: "FAILED",
            completedAt: now,
            failureReason: `Worker lease expired ${scan.attempt} times; automatic restart limit reached.`,
            stopReason: "worker_interruption_limit",
            workerId: null,
            leaseExpiresAt: null,
          },
        });
        continue;
      }

      await prisma.$transaction(async (tx) => {
        const updated = await tx.scan.updateMany({
          where: { id: scan.id, status: "RUNNING", leaseExpiresAt: leaseFilter },
          data: {
            status: "QUEUED",
            workerId: null,
            heartbeatAt: null,
            leaseExpiresAt: null,
            startedAt: null,
            completedAt: null,
            requestCount: 0,
            currentStage: null,
            progressPercent: 0,
            stopReason: "restarting_interrupted_read_only_scan",
            failureReason: "Worker lease expired; partial results cleared before restarting the scan.",
          },
        });
        if (updated.count !== 1) return;
        await tx.finding.deleteMany({ where: { scanId: scan.id } });
        await tx.discoveredEndpointRecord.deleteMany({ where: { scanId: scan.id } });
        await tx.technologyRecord.deleteMany({ where: { scanId: scan.id } });
        await tx.scanStageEvent.deleteMany({ where: { scanId: scan.id } });
      });
    }
  }
}

export const scanQueue: ScanQueue = new DatabaseScanQueue();
