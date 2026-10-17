import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/prisma.js", () => ({
  prisma: { scan: { updateMany: vi.fn() } },
}));

import { prisma } from "../lib/prisma.js";
import { claimScan, recoveryDisposition, requestScanCancellation } from "../services/scanQueue.js";

describe("durable scan job state", () => {
  beforeEach(() => vi.clearAllMocks());

  it("uses a conditional QUEUED claim so concurrent workers cannot both claim a scan", async () => {
    let state = "QUEUED";
    vi.mocked(prisma.scan.updateMany).mockImplementation((async (args: any) => {
      if (state !== "QUEUED" || args.where.status !== "QUEUED") return { count: 0 } as never;
      state = "RUNNING";
      return { count: 1 } as never;
    }) as never);

    const results = await Promise.all([
      claimScan("scan_1", "worker_a"),
      claimScan("scan_1", "worker_b"),
    ]);

    expect(results.filter(Boolean)).toHaveLength(1);
    expect(prisma.scan.updateMany).toHaveBeenCalledTimes(2);
    expect(prisma.scan.updateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: { id: "scan_1", status: "QUEUED", cancelRequestedAt: null },
      data: expect.objectContaining({ status: "RUNNING", workerId: expect.any(String), attempt: { increment: 1 } }),
    }));
  });

  it("persists cancellation of queued work without starting a worker", async () => {
    vi.mocked(prisma.scan.updateMany).mockResolvedValueOnce({ count: 1 } as never);
    await expect(requestScanCancellation("scan_2")).resolves.toBe(true);
    expect(prisma.scan.updateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: { id: "scan_2", status: "QUEUED" },
      data: expect.objectContaining({ status: "CANCELLED", stopReason: "cancelled_before_start" }),
    }));
  });

  it("cancels interrupted jobs, retries read-only jobs a bounded number of times, then fails them", () => {
    expect(recoveryDisposition(1, true)).toBe("cancel");
    expect(recoveryDisposition(1, false)).toBe("retry");
    expect(recoveryDisposition(2, false)).toBe("retry");
    expect(recoveryDisposition(3, false)).toBe("fail");
  });
});
