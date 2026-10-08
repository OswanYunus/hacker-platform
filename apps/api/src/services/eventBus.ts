import { EventEmitter } from "node:events";
import type { ScanEvent } from "@hacker/scanner-core";

/**
 * Per-scan event stream. A single API process holds this in memory, which
 * is sufficient as long as the API and the worker that executes scans run
 * in the same process (the InMemoryScanQueue default — see scanQueue.ts).
 * If workers move to separate processes/containers, replace this with a
 * Redis pub/sub channel keyed by scanId; SSE route code does not need to
 * change, only the implementation of subscribe()/publish() below.
 */
class ScanEventBus {
  private emitter = new EventEmitter();
  private history = new Map<string, ScanEvent[]>();

  publish(scanId: string, event: ScanEvent): void {
    const list = this.history.get(scanId) ?? [];
    list.push(event);
    this.history.set(scanId, list);
    this.emitter.emit(scanId, event);
  }

  subscribe(scanId: string, onEvent: (event: ScanEvent) => void): () => void {
    this.emitter.on(scanId, onEvent);
    return () => this.emitter.off(scanId, onEvent);
  }

  replay(scanId: string): ScanEvent[] {
    return this.history.get(scanId) ?? [];
  }

  /** Drops buffered history once a scan is long complete, to bound memory. */
  clear(scanId: string): void {
    this.history.delete(scanId);
  }
}

export const scanEventBus = new ScanEventBus();
