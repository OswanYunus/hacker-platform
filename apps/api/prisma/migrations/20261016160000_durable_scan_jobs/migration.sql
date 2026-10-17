ALTER TABLE "Scan"
  ADD COLUMN "heartbeatAt" TIMESTAMP(3),
  ADD COLUMN "leaseExpiresAt" TIMESTAMP(3),
  ADD COLUMN "workerId" TEXT,
  ADD COLUMN "cancelRequestedAt" TIMESTAMP(3),
  ADD COLUMN "attempt" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "currentStage" TEXT,
  ADD COLUMN "progressPercent" INTEGER NOT NULL DEFAULT 0;

ALTER TABLE "Scan" ADD COLUMN "capabilityReport" JSONB;

CREATE INDEX "Scan_status_createdAt_idx" ON "Scan"("status", "createdAt");
CREATE INDEX "Scan_status_leaseExpiresAt_idx" ON "Scan"("status", "leaseExpiresAt");
