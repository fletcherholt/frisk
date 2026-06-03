import type { Env, Finding, Report } from "./types";
import {
  resolveSha,
  openTarball,
  looksBinary,
  BINARY_EXT,
  MAX_DECODE,
} from "./fetchRepo";
import { isLowSignalPath } from "./util";
import { streamTar, type FileKind, type TarStats } from "./tar";
import { scanSecretsText } from "./scanners/secrets";
import { scanPatternsText } from "./scanners/patterns";
import { parseManifest, isManifest, queryOsv, type Dep } from "./scanners/deps";
import { scanTyposquat } from "./scanners/typosquat";
import {
  SCAN_BINARY_EXT,
  MAX_BINARIES,
  sha256,
  lookupBinaries,
  type BinTarget,
} from "./scanners/binaries";
import { scoreFindings } from "./score";
import { getCached, putCached } from "./cache";
import { checkRateLimit } from "./ratelimit";
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

const NAME = /^[A-Za-z0-9._-]+$/;

const MAX_FILES = 7000;
const MAX_BYTES = 90 * 1024 * 1024;
const MAX_BINARY_BYTES = 32 * 1024 * 1024;
const MAX_FINDINGS = 1000;

const DECODER = new TextDecoder();

function classify(name: string, size: number): FileKind | "skip" {
  if (SCAN_BINARY_EXT.test(name)) {
    if (isLowSignalPath(name) || size > MAX_BINARY_BYTES) return "skip";
    return "binary";
  }
  if (BINARY_EXT.test(name)) return "skip";
  if (size > MAX_DECODE) return "skip";
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
    } else if (!looksBinary(f.bytes)) {
      const text = DECODER.decode(f.bytes);
      findings.push(...scanSecretsText(f.name, text));
      findings.push(...scanPatternsText(f.name, text));
      if (isManifest(f.name)) deps.push(...parseManifest(f.name, text));
    }
  }

  const [osv, typo, bins] = await Promise.all([
    queryOsv(deps),
    scanTyposquat(deps),
    lookupBinaries(binTargets, binCount, env, notes),
  ]);
  findings.push(...osv, ...typo, ...bins);

  if (stats.truncated)
    notes.push("Repository is very large, so only part of it was scanned.");

  const score = scoreFindings(findings);
  let shown = findings;
  if (findings.length > MAX_FINDINGS) {
    const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    shown = [...findings]
      .sort((a, b) => rank[a.severity] - rank[b.severity])
      .slice(0, MAX_FINDINGS);
    notes.push(
      `This repository produced ${findings.length} findings; showing the ${MAX_FINDINGS} most severe.`,
    );
  }

  const report: Report = {
    owner,
    repo,
    sha,
    scannedAt: new Date().toISOString(),
    fileCount: stats.files,
    truncated: stats.truncated,
    findings: shown,
    score,
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

    const apiMatch = path.match(/^api\/scan\/([^/]+)\/([^/]+)(?:\/.*)?$/);
    const wantJson = !!apiMatch;
    const m = apiMatch ?? path.match(/^([^/]+)\/([^/]+)(?:\/.*)?$/);
    if (!m) return htmlResponse(landingPage(), 404);

    const owner = m[1];
    const repo = m[2].replace(/\.git$/, "");
    if (!NAME.test(owner) || !NAME.test(repo))
      return htmlResponse(landingPage(), 404);

    if (!wantJson && !url.searchParams.has("view")) {
      return htmlResponse(scanningPage(owner, repo));
    }

    try {
      const sha = await resolveSha(owner, repo, env);
      let report = await getCached(env, owner, repo, sha);
      if (report) {
        report = { ...report, cached: true };
      } else {
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
      if (e instanceof HttpError && e.status === 429)
        return busyResponse(wantJson, owner, repo);
      const status = e instanceof HttpError ? e.status : 500;
      const msg = e instanceof HttpError
        ? e.message
        : "Something went wrong while scanning. Please try again.";
      return wantJson
        ? jsonResponse({ error: msg }, status)
        : htmlResponse(errorPage(owner, repo, msg), status);
    }
  },
};
