import type { Env, Report } from "./types";

const TTL = 86400; // 24h

export async function getCached(
  env: Env,
  owner: string,
  repo: string,
  sha: string,
): Promise<Report | null> {
  const r = (await env.SCAN_CACHE.get(`${owner}/${repo}@${sha}`, "json")) as
    | Report
    | null;
  return r;
}

export function putCached(env: Env, report: Report): Promise<void> {
  return env.SCAN_CACHE.put(
    `${report.owner}/${report.repo}@${report.sha}`,
    JSON.stringify(report),
    { expirationTtl: TTL },
  );
}
