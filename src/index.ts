import type { Env, Report } from "./types";
import { resolveSha, fetchRepo } from "./fetchRepo";
import { scanSecrets } from "./scanners/secrets";
import { scanPatterns } from "./scanners/patterns";
import { scanDeps } from "./scanners/deps";
import { scanBinaries } from "./scanners/binaries";
import { scoreFindings } from "./score";
import { getCached, putCached } from "./cache";
import { checkRateLimit } from "./ratelimit";
import { renderReport, landingPage, errorPage, scanningPage } from "./report";
import { htmlResponse, jsonResponse, HttpError } from "./util";

// GitHub owner and repo names are limited to this set. Validating against it
// rejects junk paths and blocks any HTML/script injection through the URL.
const NAME = /^[A-Za-z0-9._-]+$/;

export async function runScan(
  owner: string,
  repo: string,
  sha: string,
  env: Env,
  ctx: ExecutionContext,
): Promise<Report> {
  const { files, truncated } = await fetchRepo(owner, repo, sha, env);
  const notes: string[] = [];
  if (truncated)
    notes.push("Repository exceeded the size cap, so only part of it was scanned.");

  const findings = [
    ...scanSecrets(files),
    ...scanPatterns(files),
    ...(await scanDeps(files)),
    ...(await scanBinaries(files, env, notes)),
  ];

  const report: Report = {
    owner,
    repo,
    sha,
    scannedAt: new Date().toISOString(),
    fileCount: files.length,
    truncated,
    findings,
    score: scoreFindings(findings),
    cached: false,
    notes,
  };

  ctx.waitUntil(putCached(env, report));
  return report;
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/^\/+|\/+$/g, "");

    if (path === "" || path === "index.html")
      return htmlResponse(landingPage());
    if (path === "favicon.ico") return new Response(null, { status: 204 });

    // Match owner/repo, tolerating deeper GitHub URL paths (/tree/main, etc.).
    const apiMatch = path.match(/^api\/scan\/([^/]+)\/([^/]+)(?:\/.*)?$/);
    const wantJson = !!apiMatch;
    const m = apiMatch ?? path.match(/^([^/]+)\/([^/]+)(?:\/.*)?$/);
    if (!m) return htmlResponse(landingPage(), 404);

    const owner = m[1];
    const repo = m[2].replace(/\.git$/, "");
    if (!NAME.test(owner) || !NAME.test(repo))
      return htmlResponse(landingPage(), 404);

    // Browser hitting the repo page (no ?view) gets the scanning interstitial.
    // Its JS runs the scan via /api/scan, then redirects here with ?view=1.
    if (!wantJson && !url.searchParams.has("view")) {
      return htmlResponse(scanningPage(owner, repo));
    }

    try {
      const sha = await resolveSha(owner, repo, env);
      let report = await getCached(env, owner, repo, sha);
      if (report) {
        report = { ...report, cached: true };
      } else {
        // Only a real scan (cache miss) costs a rate-limit token.
        const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
        const rl = await checkRateLimit(ip, env);
        if (!rl.ok) {
          const msg = "Rate limit exceeded. Try again in a few minutes.";
          return wantJson
            ? jsonResponse({ error: msg }, 429)
            : htmlResponse(errorPage(owner, repo, msg), 429);
        }
        report = await runScan(owner, repo, sha, env, ctx);
      }
      return wantJson
        ? jsonResponse(report)
        : htmlResponse(renderReport(report));
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      const msg =
        e instanceof Error ? e.message : "Unexpected error during scan.";
      return wantJson
        ? jsonResponse({ error: msg }, status)
        : htmlResponse(errorPage(owner, repo, msg), status);
    }
  },
};
