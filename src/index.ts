import type { Env, Finding, Report } from "./types";
import {
  resolveSha,
  openTarball,
  looksBinary,
  BINARY_EXT,
  MAX_DECODE,
} from "./fetchRepo";
import { streamTar, type FileKind, type TarStats } from "./tar";
import { scanSecretsText } from "./scanners/secrets";
import { scanPatternsText } from "./scanners/patterns";
import { parseManifest, isManifest, queryOsv, type Dep } from "./scanners/deps";
import {
  SCAN_BINARY_EXT,
  MAX_BINARIES,
  sha256,
  lookupBinaries,
  type BinTarget,
} from "./scanners/binaries";
import { scoreFindings } from "./score";
import { getCached, putCached } from "./cache";
import { checkRateLimit, checkGlobalCapacity } from "./ratelimit";
import {
  renderReport,
  landingPage,
  errorPage,
  scanningPage,
  busyPage,
} from "./report";
import { htmlResponse, jsonResponse, HttpError } from "./util";

function busyResponse(wantJson: boolean, owner: string, repo: string): Response {
  if (wantJson)
    return new Response(JSON.stringify({ busy: true }), {
      status: 503,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "retry-after": "5",
        "cache-control": "no-store",
      },
    });
  return htmlResponse(busyPage(owner, repo), 503);
}

// GitHub owner and repo names are limited to this set. Validating against it
// rejects junk paths and blocks any HTML/script injection through the URL.
const NAME = /^[A-Za-z0-9._-]+$/;

// Streaming removes the memory wall, but scanning still costs CPU time, which
// Cloudflare caps per request. These keep the work inside that budget; bigger
// repos are scanned up to the cap and then truncated gracefully.
const MAX_FILES = 7000;
const MAX_BYTES = 90 * 1024 * 1024; // decompressed bytes scanned before truncating
const MAX_BINARY_BYTES = 32 * 1024 * 1024; // largest binary we will hash

const DECODER = new TextDecoder();

function classify(name: string, size: number): FileKind | "skip" {
  if (SCAN_BINARY_EXT.test(name))
    return size <= MAX_BINARY_BYTES ? "binary" : "skip";
  if (BINARY_EXT.test(name)) return "skip"; // images, archives, fonts, media
  if (size > MAX_DECODE) return "skip"; // oversized text / minified bundles
  return "text";
}

export async function runScan(
  owner: string,
  repo: string,
  sha: string,
  env: Env,
  ctx: ExecutionContext,
): Promise<Report> {
  const stream = await openTarball(owner, repo, sha);
  const stats: TarStats = { files: 0, bytes: 0, truncated: false };
  const findings: Finding[] = [];
  const deps: Dep[] = [];
  const binTargets: BinTarget[] = [];
  let binCount = 0;
  const notes: string[] = [];

  for await (const f of streamTar(
    stream,
    classify,
    { maxFiles: MAX_FILES, maxBytes: MAX_BYTES },
    stats,
  )) {
    if (f.kind === "binary") {
      binCount++;
      if (binTargets.length < MAX_BINARIES)
        binTargets.push({ path: f.name, hash: await sha256(f.bytes) });
      continue;
    }
    if (looksBinary(f.bytes)) continue; // unknown extension, actually binary
    const text = DECODER.decode(f.bytes);
    findings.push(...scanSecretsText(f.name, text));
    findings.push(...scanPatternsText(f.name, text));
    if (isManifest(f.name)) deps.push(...parseManifest(f.name, text));
  }

  findings.push(...(await queryOsv(deps)));
  findings.push(...(await lookupBinaries(binTargets, binCount, env, notes)));

  if (stats.truncated)
    notes.push("Repository is very large, so only part of it was scanned.");

  const report: Report = {
    owner,
    repo,
    sha,
    scannedAt: new Date().toISOString(),
    fileCount: stats.files,
    truncated: stats.truncated,
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
        // Site-wide capacity: ask the user to wait when we are slammed.
        if (!(await checkGlobalCapacity(env)))
          return busyResponse(wantJson, owner, repo);
        report = await runScan(owner, repo, sha, env, ctx);
      }
      return wantJson
        ? jsonResponse(report)
        : htmlResponse(renderReport(report));
    } catch (e) {
      // A GitHub budget exhaustion means the shared capacity is used up, which
      // for users is the same "too busy, wait" situation.
      if (e instanceof HttpError && e.status === 429)
        return busyResponse(wantJson, owner, repo);
      const status = e instanceof HttpError ? e.status : 500;
      const msg =
        e instanceof Error ? e.message : "Unexpected error during scan.";
      return wantJson
        ? jsonResponse({ error: msg }, status)
        : htmlResponse(errorPage(owner, repo, msg), status);
    }
  },
};
