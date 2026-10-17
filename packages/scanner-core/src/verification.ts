import type { Confidence, RawObservation, VerificationStatus } from "./types.js";

type EvidencePolicy = (observation: RawObservation) => boolean;

const observedResponseRules = /^(missing-|cors-|cookie-|version-disclosure-|stack-trace-disclosure$|debug-mode-indicator$|exposed-file-|cacheable-authenticated-response$|client-side-secret-)/;
const probeResponseRules = /^(sqli-|reflected-xss$|path-traversal$|ssti$|open-redirect$|command-injection$|idor-sequential-id$|weak-session-token-|low-session-token-entropy$|password-in-url$)/;

const evidencePolicies: Array<{ matches: RegExp; validate: EvidencePolicy }> = [
  {
    matches: observedResponseRules,
    validate: (observation) => observation.evidence.some((item) =>
      Boolean(item.exchangeId && item.description.trim()),
    ),
  },
  {
    matches: /^privileged-path-no-auth$/,
    validate: (observation) => {
      const anonymous = observation.evidence.find((item) =>
        item.description.includes("Anonymous HTTP 200") && Boolean(item.exchangeId) &&
        /Probe URL:\s*https?:\/\/\S+/.test(item.detail ?? ""),
      );
      const baseline = observation.evidence.find((item) =>
        item.description.includes("public homepage baseline") && Boolean(item.exchangeId) &&
        /Baseline URL:\s*https?:\/\/\S+/.test(item.detail ?? ""),
      );
      if (!anonymous || !baseline) return false;
      try {
        return new URL(anonymous.detail!.match(/Probe URL:\s*(https?:\/\/\S+)/)![1]).origin ===
          new URL(baseline.detail!.match(/Baseline URL:\s*(https?:\/\/\S+)/)![1]).origin;
      } catch {
        return false;
      }
    },
  },
  {
    matches: probeResponseRules,
    validate: (observation) => observation.evidence.some((item) => {
      if (!item.description.trim() || !item.detail) return false;
      const probeUrl = item.detail.match(/Probe URL:\s*(https?:\/\/\S+)/i)?.[1];
      if (!probeUrl) return false;
      try {
        return new URL(probeUrl).origin === new URL(observation.affectedEndpoint).origin;
      } catch {
        return false;
      }
    }),
  },
  {
    matches: /^documented-api-route-anonymous-access$/,
    validate: (observation) => observation.evidence.some((item) =>
      item.description.includes("Authenticated and anonymous") &&
      /Authenticated HTTP \d+; anonymous HTTP \d+/.test(item.detail ?? ""),
    ),
  },
  {
    matches: /^public-/,
    validate: (observation) => observation.evidence.some((item) =>
      Boolean(item.description.trim() && item.detail?.trim()),
    ),
  },
];

/**
 * Apply rule-specific evidence requirements to a scanner observation.
 * Checks may suggest a status, but no current rule has an independent
 * verifier, so scan-produced findings cannot be labeled independently
 * verified. A missing or malformed evidence record is explicitly
 * inconclusive.
 */
export function assessVerification(observation: RawObservation): VerificationStatus {
  if (observation.verification === "false_positive") return "false_positive";

  const policy = evidencePolicies.find(({ matches }) => matches.test(observation.ruleId));
  if (!policy) return "suspected";

  let validEndpoint = false;
  try {
    const endpoint = new URL(observation.affectedEndpoint);
    validEndpoint = endpoint.protocol === "http:" || endpoint.protocol === "https:";
  } catch {
    validEndpoint = false;
  }

  return validEndpoint && policy.validate(observation) ? "evidence_supported" : "inconclusive";
}

/**
 * Cap heuristic confidence at medium until a rule has a separate validator.
 * Single timing observations and unsupported rules remain low confidence.
 */
export function calibrateConfidence(observation: RawObservation, status: VerificationStatus): Confidence {
  if (status === "inconclusive" || status === "suspected" || status === "false_positive") return "low";
  if (/^(sqli-time-based|sqli-time-based-pg|command-injection)$/.test(observation.ruleId)) return "low";
  if (/^(sqli-|reflected-xss$|path-traversal$|ssti$|open-redirect$|idor-sequential-id$|privileged-path-no-auth$|documented-api-route-anonymous-access$)/.test(observation.ruleId)) {
    return observation.confidence === "low" ? "low" : "medium";
  }
  return observation.confidence;
}
