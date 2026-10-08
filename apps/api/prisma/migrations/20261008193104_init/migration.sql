-- CreateEnum
CREATE TYPE "OrgRole" AS ENUM ('OWNER', 'ADMIN', 'MEMBER', 'VIEWER');

-- CreateEnum
CREATE TYPE "TargetType" AS ENUM ('DOMAIN', 'URL', 'API_ENDPOINT', 'IP_RANGE');

-- CreateEnum
CREATE TYPE "Environment" AS ENUM ('PRODUCTION', 'STAGING', 'DEVELOPMENT', 'OTHER');

-- CreateEnum
CREATE TYPE "AuthMechanism" AS ENUM ('NONE', 'COOKIE', 'BEARER_TOKEN', 'LOGIN_FLOW', 'API_KEY');

-- CreateEnum
CREATE TYPE "ScanProfileEnum" AS ENUM ('QUICK', 'STANDARD', 'DEEP', 'CI');

-- CreateEnum
CREATE TYPE "ScanStatus" AS ENUM ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED');

-- CreateEnum
CREATE TYPE "RemediationState" AS ENUM ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'ACCEPTED_RISK', 'FALSE_POSITIVE');

-- CreateEnum
CREATE TYPE "ReportFormat" AS ENUM ('PDF', 'JSON', 'CSV', 'MARKDOWN');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Organization" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Organization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OrgMembership" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "role" "OrgRole" NOT NULL DEFAULT 'MEMBER',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OrgMembership_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Project" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "createdById" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "archivedAt" TIMESTAMP(3),

    CONSTRAINT "Project_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Target" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "type" "TargetType" NOT NULL,
    "value" TEXT NOT NULL,
    "label" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Target_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScopeVersion" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "allowedHosts" TEXT[],
    "allowedIpRanges" TEXT[],
    "allowedPaths" TEXT[],
    "excludedPaths" TEXT[],
    "environment" "Environment" NOT NULL,
    "activeTestingAllowed" BOOLEAN NOT NULL DEFAULT false,
    "maxRequestsPerSecond" DOUBLE PRECISION NOT NULL DEFAULT 2,
    "maxScanDurationSeconds" INTEGER NOT NULL DEFAULT 1800,
    "maxTotalRequests" INTEGER NOT NULL DEFAULT 2000,
    "isActive" BOOLEAN NOT NULL DEFAULT true,
    "authorizedById" TEXT NOT NULL,
    "authorizedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "authorizationStatement" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScopeVersion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuthenticationConfig" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "roleLabel" TEXT NOT NULL,
    "mechanism" "AuthMechanism" NOT NULL,
    "loginUrl" TEXT,
    "usernameField" TEXT,
    "secretId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuthenticationConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Secret" (
    "id" TEXT NOT NULL,
    "ciphertext" BYTEA NOT NULL,
    "iv" BYTEA NOT NULL,
    "authTag" BYTEA NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Secret_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanConfig" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "profile" "ScanProfileEnum" NOT NULL,
    "enabledModules" TEXT[],
    "ciFailPolicy" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScanConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Scan" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "scopeVersionId" TEXT NOT NULL,
    "scanConfigId" TEXT,
    "authConfigId" TEXT,
    "profile" "ScanProfileEnum" NOT NULL,
    "status" "ScanStatus" NOT NULL DEFAULT 'QUEUED',
    "triggeredById" TEXT NOT NULL,
    "triggerSource" TEXT NOT NULL DEFAULT 'manual',
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    "requestCount" INTEGER NOT NULL DEFAULT 0,
    "stopReason" TEXT,
    "failureReason" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Scan_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ScanStageEvent" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "stage" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "summary" TEXT,
    "occurredAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ScanStageEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DiscoveredEndpointRecord" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "url" TEXT NOT NULL,
    "methods" TEXT[],
    "statusCodes" INTEGER[],
    "queryParams" TEXT[],
    "formFields" TEXT[],
    "requiresAuth" TEXT NOT NULL,
    "sourceType" TEXT NOT NULL,
    "contentType" TEXT,
    "parentUrl" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DiscoveredEndpointRecord_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "TechnologyRecord" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "version" TEXT,
    "confidence" TEXT NOT NULL,
    "evidence" TEXT NOT NULL,

    CONSTRAINT "TechnologyRecord_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Finding" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "confidence" TEXT NOT NULL,
    "cwe" TEXT,
    "owaspCategory" TEXT,
    "affectedEndpoint" TEXT NOT NULL,
    "reproduction" TEXT NOT NULL,
    "rootCause" TEXT NOT NULL,
    "impact" TEXT NOT NULL,
    "remediation" TEXT NOT NULL,
    "references" TEXT[],
    "verification" TEXT NOT NULL,
    "occurrences" INTEGER NOT NULL DEFAULT 1,
    "module" TEXT NOT NULL,
    "firstSeenStage" TEXT NOT NULL,
    "riskScore" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Finding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "FindingEvidence" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "exchangeId" TEXT,
    "detail" TEXT,

    CONSTRAINT "FindingEvidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RemediationStatus" (
    "id" TEXT NOT NULL,
    "findingId" TEXT NOT NULL,
    "state" "RemediationState" NOT NULL DEFAULT 'OPEN',
    "note" TEXT,
    "updatedById" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "RemediationStatus_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Report" (
    "id" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "format" "ReportFormat" NOT NULL,
    "generatedById" TEXT NOT NULL,
    "generatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "storageRef" TEXT NOT NULL,

    CONSTRAINT "Report_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CiIntegration" (
    "id" TEXT NOT NULL,
    "projectId" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "webhookTokenId" TEXT,
    "failPolicy" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CiIntegration_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AuditEvent" (
    "id" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "projectId" TEXT,
    "actorId" TEXT,
    "action" TEXT NOT NULL,
    "targetType" TEXT NOT NULL,
    "targetId" TEXT NOT NULL,
    "metadata" JSONB,
    "ipAddress" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditEvent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_email_idx" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "OrgMembership_userId_organizationId_key" ON "OrgMembership"("userId", "organizationId");

-- CreateIndex
CREATE INDEX "Project_organizationId_idx" ON "Project"("organizationId");

-- CreateIndex
CREATE INDEX "Target_projectId_idx" ON "Target"("projectId");

-- CreateIndex
CREATE INDEX "ScopeVersion_projectId_isActive_idx" ON "ScopeVersion"("projectId", "isActive");

-- CreateIndex
CREATE UNIQUE INDEX "AuthenticationConfig_secretId_key" ON "AuthenticationConfig"("secretId");

-- CreateIndex
CREATE INDEX "Scan_projectId_createdAt_idx" ON "Scan"("projectId", "createdAt");

-- CreateIndex
CREATE INDEX "ScanStageEvent_scanId_idx" ON "ScanStageEvent"("scanId");

-- CreateIndex
CREATE INDEX "DiscoveredEndpointRecord_scanId_idx" ON "DiscoveredEndpointRecord"("scanId");

-- CreateIndex
CREATE INDEX "DiscoveredEndpointRecord_projectId_url_idx" ON "DiscoveredEndpointRecord"("projectId", "url");

-- CreateIndex
CREATE INDEX "TechnologyRecord_scanId_idx" ON "TechnologyRecord"("scanId");

-- CreateIndex
CREATE INDEX "Finding_scanId_idx" ON "Finding"("scanId");

-- CreateIndex
CREATE INDEX "Finding_projectId_severity_idx" ON "Finding"("projectId", "severity");

-- CreateIndex
CREATE INDEX "Finding_projectId_ruleId_affectedEndpoint_idx" ON "Finding"("projectId", "ruleId", "affectedEndpoint");

-- CreateIndex
CREATE INDEX "FindingEvidence_findingId_idx" ON "FindingEvidence"("findingId");

-- CreateIndex
CREATE UNIQUE INDEX "RemediationStatus_findingId_key" ON "RemediationStatus"("findingId");

-- CreateIndex
CREATE UNIQUE INDEX "CiIntegration_webhookTokenId_key" ON "CiIntegration"("webhookTokenId");

-- CreateIndex
CREATE INDEX "AuditEvent_organizationId_createdAt_idx" ON "AuditEvent"("organizationId", "createdAt");

-- CreateIndex
CREATE INDEX "AuditEvent_projectId_createdAt_idx" ON "AuditEvent"("projectId", "createdAt");

-- AddForeignKey
ALTER TABLE "OrgMembership" ADD CONSTRAINT "OrgMembership_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OrgMembership" ADD CONSTRAINT "OrgMembership_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Project" ADD CONSTRAINT "Project_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Project" ADD CONSTRAINT "Project_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Target" ADD CONSTRAINT "Target_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScopeVersion" ADD CONSTRAINT "ScopeVersion_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScopeVersion" ADD CONSTRAINT "ScopeVersion_authorizedById_fkey" FOREIGN KEY ("authorizedById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthenticationConfig" ADD CONSTRAINT "AuthenticationConfig_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuthenticationConfig" ADD CONSTRAINT "AuthenticationConfig_secretId_fkey" FOREIGN KEY ("secretId") REFERENCES "Secret"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanConfig" ADD CONSTRAINT "ScanConfig_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_scopeVersionId_fkey" FOREIGN KEY ("scopeVersionId") REFERENCES "ScopeVersion"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_scanConfigId_fkey" FOREIGN KEY ("scanConfigId") REFERENCES "ScanConfig"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_authConfigId_fkey" FOREIGN KEY ("authConfigId") REFERENCES "AuthenticationConfig"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Scan" ADD CONSTRAINT "Scan_triggeredById_fkey" FOREIGN KEY ("triggeredById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ScanStageEvent" ADD CONSTRAINT "ScanStageEvent_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveredEndpointRecord" ADD CONSTRAINT "DiscoveredEndpointRecord_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveredEndpointRecord" ADD CONSTRAINT "DiscoveredEndpointRecord_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Finding" ADD CONSTRAINT "Finding_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "FindingEvidence" ADD CONSTRAINT "FindingEvidence_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RemediationStatus" ADD CONSTRAINT "RemediationStatus_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "RemediationStatus" ADD CONSTRAINT "RemediationStatus_updatedById_fkey" FOREIGN KEY ("updatedById") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Report" ADD CONSTRAINT "Report_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Report" ADD CONSTRAINT "Report_generatedById_fkey" FOREIGN KEY ("generatedById") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CiIntegration" ADD CONSTRAINT "CiIntegration_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CiIntegration" ADD CONSTRAINT "CiIntegration_webhookTokenId_fkey" FOREIGN KEY ("webhookTokenId") REFERENCES "Secret"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_projectId_fkey" FOREIGN KEY ("projectId") REFERENCES "Project"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditEvent" ADD CONSTRAINT "AuditEvent_actorId_fkey" FOREIGN KEY ("actorId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;
