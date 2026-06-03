import type { Env, Report } from "./types";

const TTL = 86400;
const TTL_PARTIAL = 3600;

function key(owner: string, repo: string, sha: string): string {
  return `${owner}/${repo}@${sha}`.toLowerCase();
}

export async function getCached(
  env: Env,
  owner: string,
  repo: string,
  sha: string,
): Promise<Report | null> {
  try {
    return (await env.SCAN_CACHE.get(key(owner, repo, sha), "json")) as
      | Report
      | null;
  } catch {
    return null;
  }
}

export function putCached(env: Env, report: Report): Promise<void> {
  return env.SCAN_CACHE.put(
    key(report.owner, report.repo, report.sha),
    JSON.stringify(report),
    { expirationTtl: report.truncated ? TTL_PARTIAL : TTL },
  ).catch(() => {});
}
