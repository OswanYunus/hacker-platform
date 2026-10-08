import type { Finding, RawObservation } from "./types.js";

/**
 * Groups raw per-request observations into unique findings. Two
 * observations are considered the same finding when they share a ruleId
 * and an affected endpoint "family" (same path, ignoring query string) —
 * e.g. 50 requests to /api/items?id=1..50 all missing a header collapse
 * into a single finding against /api/items, with occurrences=50, rather
 * than flooding the report with 50 near-identical rows.
 */
export function correlateFindings(observations: RawObservation[]): Finding[] {
  const groups = new Map<string, RawObservation[]>();

  for (const obs of observations) {
    const key = groupKey(obs);
    const list = groups.get(key) ?? [];
    list.push(obs);
    groups.set(key, list);
  }

  const findings: Finding[] = [];
  let counter = 0;
  for (const [key, obsList] of groups) {
    const primary = obsList[0];
    const allEvidence = obsList.flatMap((o) => o.evidence).slice(0, 10); // cap evidence stored per finding
    counter++;
    findings.push({
      ...primary,
      id: `fnd_${counter}_${key.slice(0, 24).replace(/[^a-z0-9]/gi, "")}`,
      evidence: allEvidence,
      occurrences: obsList.length,
      affectedEndpoint:
        obsList.length > 1 ? summarizeEndpoints(obsList.map((o) => o.affectedEndpoint)) : primary.affectedEndpoint,
    });
  }

  return findings.sort((a, b) => severityWeight(b.severity) - severityWeight(a.severity));
}

function groupKey(obs: RawObservation): string {
  let pathFamily: string;
  try {
    const u = new URL(obs.affectedEndpoint);
    pathFamily = u.hostname + u.pathname.replace(/\/\d+(\/|$)/g, "/{id}$1");
  } catch {
    pathFamily = obs.affectedEndpoint;
  }
  return `${obs.ruleId}::${pathFamily}`;
}

function summarizeEndpoints(endpoints: string[]): string {
  const unique = Array.from(new Set(endpoints));
  if (unique.length <= 3) return unique.join(", ");
  return `${unique.slice(0, 3).join(", ")} and ${unique.length - 3} more`;
}

export function severityWeight(s: Finding["severity"]): number {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s];
}
