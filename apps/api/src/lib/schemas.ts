import { z } from "zod";

export const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .max(128, "Password must be no more than 128 characters")
  .regex(/[^A-Za-z0-9\s]/, "Password must include at least one special character");

export const registerSchema = z.object({
  email: z.string().email(),
  password: passwordSchema,
  name: z.string().min(1).max(200),
  organizationName: z.string().min(1).max(200),
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1).max(128),
});

export const forgotPasswordSchema = z.object({ email: z.string().email() });

export const resetPasswordSchema = z.object({
  token: z.string().regex(/^[a-f0-9]{64}$/i),
  password: passwordSchema,
});

export const createProjectSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().max(2000).optional(),
});

export const targetSchema = z.object({
  type: z.enum(["DOMAIN", "URL", "API_ENDPOINT", "IP_RANGE"]),
  value: z.string().min(1).max(500),
  label: z.string().max(200).optional(),
});

export const createScopeSchema = z.object({
  allowedHosts: z.array(z.string().min(1)).min(1, "At least one authorized host is required"),
  allowedIpRanges: z.array(z.string()).default([]),
  allowedPaths: z.array(z.string()).default([]),
  excludedPaths: z.array(z.string()).default([]),
  environment: z.enum(["PRODUCTION", "STAGING", "DEVELOPMENT", "OTHER"]),
  activeTestingAllowed: z.boolean().default(false),
  maxRequestsPerSecond: z.number().positive().max(100).default(2),
  maxScanDurationSeconds: z.number().int().positive().max(24 * 3600).default(1800),
  maxTotalRequests: z.number().int().positive().max(200_000).default(2000),
  // Required, explicit human confirmation — this is not a checkbox UX
  // afterthought, it's what gets stored verbatim in the audit trail as
  // evidence the operator attested to having authorization.
  authorizationStatement: z
    .string()
    .min(20, "Describe your authorization to test this target (who approved it, and how)"),
});

export const authConfigSchema = z.object({
  roleLabel: z.string().min(1).max(100),
  mechanism: z.enum(["NONE", "COOKIE", "BEARER_TOKEN", "LOGIN_FLOW", "API_KEY"]),
  loginUrl: z.string().url().optional(),
  usernameField: z.string().optional(),
  secretValue: z.string().optional(), // cookie header value / bearer token / API key — encrypted at rest
});

export const createScanSchema = z.object({
  profile: z.enum(["QUICK", "STANDARD", "DEEP", "CI"]),
  authConfigId: z.string().optional(),
  triggerSource: z.enum(["manual", "ci", "api", "schedule"]).default("manual"),
});

export const remediationUpdateSchema = z.object({
  state: z.enum(["OPEN", "IN_PROGRESS", "RESOLVED", "ACCEPTED_RISK", "FALSE_POSITIVE"]),
  note: z.string().max(2000).optional(),
});

export const ciPolicySchema = z.object({
  critical: z.number().int().min(0).optional(),
  high: z.number().int().min(0).optional(),
  medium: z.number().int().min(0).optional(),
  low: z.number().int().min(0).optional(),
});
