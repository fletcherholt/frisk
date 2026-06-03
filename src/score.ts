import type { Finding, Score, Severity } from "./types";

const WEIGHT: Record<Severity, number> = {
  critical: 100,
  high: 40,
  medium: 10,
  low: 2,
  info: 0,
};

export function scoreFindings(findings: Finding[]): Score {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  let points = 0;
  for (const f of findings) {
    counts[f.severity]++;
    points += WEIGHT[f.severity];
  }

  let level: Score["level"];
  if (counts.critical > 0 || counts.high >= 3) level = "critical";
  else if (counts.high >= 1 || counts.medium >= 12) level = "high";
  else if (counts.medium >= 1) level = "medium";
  else if (counts.low >= 1) level = "low";
  else level = "clean";

  return { level, points, counts };
}
