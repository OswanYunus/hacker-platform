import { appendFile, mkdir, rm } from "node:fs/promises";
import path from "node:path";
import type { ScanEvent } from "@hacker/scanner-core";

const root = path.resolve(process.env.SCAN_LOG_DIR ?? path.join(process.cwd(), "data", "scan-logs"));

export function scanSessionDirectory(scanId: string): string {
  if (!/^[a-zA-Z0-9_-]+$/.test(scanId)) throw new Error("Invalid scan session ID");
  return path.join(root, scanId);
}

export function scanSessionLogPath(scanId: string, startedAt: Date): string {
  const stamp = startedAt.toISOString().replace(/[:.]/g, "-");
  return path.join(scanSessionDirectory(scanId), `events-${stamp}.jsonl`);
}

export async function removeScanSessionLog(scanId: string): Promise<void> {
  await rm(scanSessionDirectory(scanId), { recursive: true, force: true });
}

export class ScanSessionLogger {
  readonly filePath: string;
  private pendingWrite: Promise<void> = Promise.resolve();

  constructor(scanId: string, startedAt: Date) {
    this.filePath = scanSessionLogPath(scanId, startedAt);
  }

  async initialize(): Promise<void> {
    await mkdir(path.dirname(this.filePath), { recursive: true });
  }

  append(event: ScanEvent): void {
    const record = {
      timestamp: event.at,
      recordedAt: new Date().toISOString(),
      event: redactSecrets(event),
    };
    this.pendingWrite = this.pendingWrite.then(() =>
      appendFile(this.filePath, `${JSON.stringify(record)}\n`, "utf8"),
    ).catch((error: unknown) => {
      // A log disk error must not stop an authorized scan. Report it to the
      // container log so an operator can fix storage and rerun the session.
      console.error("Unable to append scan session log:", error);
    });
  }

  async flush(): Promise<void> {
    await this.pendingWrite;
  }
}

function redactSecrets(value: unknown, fieldName = ""): unknown {
  if (/password|secret|token|authorization|cookie|credential|api[_-]?key/i.test(fieldName)) return "[REDACTED]";
  if (typeof value === "string") return redactUrl(value);
  if (Array.isArray(value)) return value.map((item) => redactSecrets(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, redactSecrets(child, key)]),
    );
  }
  return value;
}

function redactUrl(value: string): string {
  return value.replace(/https?:\/\/[^\s"'<>]+/gi, (candidate) => {
    try {
      const url = new URL(candidate);
      for (const key of Array.from(url.searchParams.keys())) {
        if (/password|secret|token|authorization|cookie|credential|api[_-]?key/i.test(key)) {
          url.searchParams.set(key, "[REDACTED]");
        }
      }
      url.username = "";
      url.password = "";
      url.hash = "";
      return url.toString();
    } catch {
      return candidate;
    }
  });
}
