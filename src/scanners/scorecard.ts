import type { Finding } from "../types";

interface ScorecardCheck {
  name: string;
  score: number;
  reason?: string;
}

interface ScorecardResult {
  score?: number;
  checks?: ScorecardCheck[];
}

const NOTABLE = new Set([
  "Dangerous-Workflow",
  "Token-Permissions",
  "Branch-Protection",
  "Code-Review",
  "Maintained",
  "Pinned-Dependencies",
  "Vulnerabilities",
  "Security-Policy",
]);

export async function scanScorecard(
  owner: string,
  repo: string,
): Promise<Finding[]> {
  let data: ScorecardResult;
  try {
    const r = await fetch(
      `https://api.securityscorecards.dev/projects/github.com/${owner}/${repo}`,
      { signal: AbortSignal.timeout(8000) },
    );
    if (!r.ok) return [];
    data = (await r.json()) as ScorecardResult;
  } catch {
    return [];
  }

  if (typeof data.score !== "number") return [];

  const findings: Finding[] = [
    {
      severity: "info",
      category: "health",
      title: `Repo health: ${data.score.toFixed(1)}/10 (OpenSSF Scorecard)`,
      file: `${owner}/${repo}`,
      detail: `OpenSSF Scorecard rates this repository's security practices. See securityscorecards.dev/viewer/?uri=github.com/${owner}/${repo}`,
    },
  ];

  for (const c of data.checks ?? []) {
    if (!NOTABLE.has(c.name) || c.score < 0 || c.score > 4) continue;
    findings.push({
      severity: "info",
      category: "health",
      title: `Weak practice: ${c.name} (${c.score}/10)`,
      file: `${owner}/${repo}`,
      detail: c.reason ?? "",
    });
  }
  return findings;
}
