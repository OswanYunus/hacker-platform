ALTER TABLE "Target"
  ADD COLUMN "verificationRecordName" TEXT,
  ADD COLUMN "verificationTokenHash" BYTEA,
  ADD COLUMN "verifiedAt" TIMESTAMP(3);
