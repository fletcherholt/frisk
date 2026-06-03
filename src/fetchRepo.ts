import type { Env } from "./types";
import { HttpError } from "./util";

// Kept for the array-based scanner wrappers and unit tests. The streaming scan
// path does not build these; it processes one file at a time.
export interface RepoFile {
  path: string;
  bytes: Uint8Array;
  text: string | null;
  isBinary: boolean;
}

export const MAX_DECODE = 2 * 1024 * 1024; // don't decode text files larger than 2 MB

// Extensions we treat as binary (never decode to text).
export const BINARY_EXT =
  /\.(exe|dll|so|dylib|bin|o|a|node|wasm|class|jar|apk|deb|rpm|msi|dmg|pkg|zip|gz|tgz|7z|rar|png|jpe?g|gif|webp|ico|bmp|pdf|mp4|mov|mp3|wav|woff2?|ttf|otf|eot)$/i;

function ghHeaders(env: Env): HeadersInit {
  const h: Record<string, string> = {
    "User-Agent": "frisk",
    Accept: "application/vnd.github+json",
  };
  if (env.GITHUB_TOKEN) h.Authorization = `Bearer ${env.GITHUB_TOKEN}`;
  return h;
}

/** Resolve the latest commit SHA, doubling as an existence/visibility check. */
export async function resolveSha(
  owner: string,
  repo: string,
  env: Env,
): Promise<string> {
  // Cache the SHA briefly so repeated requests for the same repo (notably the
  // interstitial's /api/scan followed by ?view=1) make one GitHub call, not two.
  const cacheKey = `sha:${owner}/${repo}`.toLowerCase();
  const cached = await env.SCAN_CACHE.get(cacheKey);
  if (cached) return cached;

  const r = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/commits?per_page=1`,
    { headers: ghHeaders(env) },
  );
  if (r.status === 404)
    throw new HttpError(404, "Repository not found, empty, or private.");
  if (r.status === 403 || r.status === 429)
    throw new HttpError(429, "GitHub rate limit reached. Please try again in a few minutes.");
  if (!r.ok) throw new HttpError(502, `GitHub API error ${r.status}.`);
  const commits = (await r.json()) as Array<{ sha: string }>;
  if (!Array.isArray(commits) || commits.length === 0)
    throw new HttpError(404, "Repository has no commits.");

  const sha = commits[0].sha;
  await env.SCAN_CACHE.put(cacheKey, sha, { expirationTtl: 300 });
  return sha;
}

/** A NUL byte in the first chunk means the content is binary, not text. */
export function looksBinary(bytes: Uint8Array): boolean {
  const n = Math.min(bytes.length, 8000);
  for (let i = 0; i < n; i++) if (bytes[i] === 0) return true;
  return false;
}

/** Fetch the repo tarball and return its gzip-decompressed byte stream. */
export async function openTarball(
  owner: string,
  repo: string,
  sha: string,
): Promise<ReadableStream<Uint8Array>> {
  const r = await fetch(
    `https://codeload.github.com/${owner}/${repo}/tar.gz/${sha}`,
    { headers: { "User-Agent": "frisk" } },
  );
  if (!r.ok) throw new HttpError(502, `Tarball download failed (${r.status}).`);
  if (!r.body) throw new HttpError(502, "Empty tarball response.");
  return r.body.pipeThrough(new DecompressionStream("gzip"));
}
