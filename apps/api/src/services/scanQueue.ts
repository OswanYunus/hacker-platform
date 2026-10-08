import { executeScan } from "./scanOrchestrator.js";

/**
 * ScanQueue is the seam between "a scan was requested" and "a scan is
 * executing". The architecture document (Browser -> API -> Job Queue ->
 * Scan Workers) calls for this to be a durable, horizontally-scalable
 * queue in production — e.g. BullMQ backed by Redis, with workers running
 * as separate isolated processes/containers so a crashed or malicious-target
 * -triggered worker crash cannot take down the API.
 *
 * InMemoryScanQueue below is the default for local development and small
 * deployments: it runs scans in the same process with bounded concurrency.
 * It implements the same ScanQueue interface a Redis-backed queue would,
 * so swapping it out is a one-line change in server.ts, not a rewrite.
 * See queue.redis.md in this directory for the production adapter shape;
 * it is documented rather than shipped here because this environment has
 * no Redis to actually exercise it against, and we don't ship integrations
 * we haven't run.
 */
export interface ScanQueue {
  enqueue(scanId: string): Promise<void>;
}

export class InMemoryScanQueue implements ScanQueue {
  private running = 0;
  private pending: string[] = [];

  constructor(private readonly concurrency = 2) {}

  async enqueue(scanId: string): Promise<void> {
    this.pending.push(scanId);
    this.pump();
  }

  private pump(): void {
    while (this.running < this.concurrency && this.pending.length > 0) {
      const scanId = this.pending.shift()!;
      this.running++;
      executeScan(scanId)
        .catch((err) => {
          // executeScan already persists failure state; this catch only
          // guards against the queue loop itself throwing.
          // eslint-disable-next-line no-console
          console.error(`Unhandled error running scan ${scanId}:`, err);
        })
        .finally(() => {
          this.running--;
          this.pump();
        });
    }
  }
}

export const scanQueue: ScanQueue = new InMemoryScanQueue(
  Number(process.env.SCAN_WORKER_CONCURRENCY ?? 2),
);
