# Production queue adapter (BullMQ + Redis)

`InMemoryScanQueue` (see `scanQueue.ts`) is fine for local dev and small
single-node deployments. For production, swap it for a durable queue so
that:

- scans survive an API process restart
- scan execution can run in separate, isolated worker containers (per the
  architecture: Browser → Web API → Job Queue → Scan Workers)
- queue depth and worker count scale independently of the API

This file documents the adapter shape. It is **not wired into the app** in
this codebase because this environment has no Redis instance to test it
against — ship it once you've run it against a real Redis.

```ts
import { Queue, Worker, type Job } from "bullmq";
import { executeScan } from "./scanOrchestrator.js";
import type { ScanQueue } from "./scanQueue.js";

const connection = { host: process.env.REDIS_HOST, port: Number(process.env.REDIS_PORT) };

export class RedisScanQueue implements ScanQueue {
  private queue = new Queue("scans", { connection });

  async enqueue(scanId: string): Promise<void> {
    await this.queue.add("run-scan", { scanId }, {
      attempts: 1, // scans are not safely re-runnable mid-flight; a failed
                   // scan should be re-triggered deliberately by a user,
                   // not silently retried against a live target
      removeOnComplete: 500,
      removeOnFail: 1000,
    });
  }
}

// Runs in a separate worker process/container (`node worker.js`), never
// inside the API process.
export function startWorker(): Worker {
  return new Worker(
    "scans",
    async (job: Job<{ scanId: string }>) => {
      await executeScan(job.data.scanId);
    },
    { connection, concurrency: Number(process.env.SCAN_WORKER_CONCURRENCY ?? 4) },
  );
}
```

Worker isolation checklist before enabling this in production:
- run workers as a distinct, least-privileged container/process from the API
- no shared filesystem with the API beyond what's needed to read config
- workers get network egress only to scan targets + the database, not to
  internal infrastructure (enforce with network policy, not just the
  application-level SSRF guard in `scanner-core`)
- resource limits (CPU/memory/pids) on the worker container so a
  pathological target response can't exhaust the host
- `executeScan` already enforces request-count and duration budgets from
  scope, but container-level timeouts are a second, independent backstop
