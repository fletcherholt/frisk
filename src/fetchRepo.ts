import { parseTar } from "nanotar";
import type { Env } from "./types";
import { HttpError } from "./util";

export interface RepoFile {
  path: string;
  bytes: Uint8Array;
  text: string | null; // null for binaries / oversized files
  isBinary: boolean;
}

export interface FetchResult {
  files: RepoFile[];
  truncated: boolean;
  sizeBytes: number;
}

const MAX_FILES = 2000;
const MAX_TOTAL = 50 * 1024 * 1024; // 50 MB decompressed
const MAX_DECODE = 1024 * 1024; // don't TextDecode files larger than 1 MB

// Extensions we treat as binary (never decode to text).
const BINARY_EXT =
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
  const r = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/commits?per_page=1`,
    { headers: ghHeaders(env) },
  );
  if (r.status === 404)
    throw new HttpError(404, "Repository not found, empty, or private.");
  if (r.status === 403)
    throw new HttpError(429, "GitHub rate limit hit — set GITHUB_TOKEN or retry later.");
  if (!r.ok) throw new HttpError(502, `GitHub API error ${r.status}.`);
  const commits = (await r.json()) as Array<{ sha: string }>;
  if (!Array.isArray(commits) || commits.length === 0)
    throw new HttpError(404, "Repository has no commits.");
  return commits[0].sha;
}

async function gunzip(buf: ArrayBuffer): Promise<Uint8Array> {
  const stream = new Response(buf).body!.pipeThrough(
    new DecompressionStream("gzip"),
  );
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Strip the leading `repo-sha/` path segment GitHub adds to tarball entries. */
function stripTop(name: string): string {
  const i = name.indexOf("/");
  return i === -1 ? "" : name.slice(i + 1);
}

/** Heuristic: a NUL byte in the first chunk means binary. */
function looksBinary(bytes: Uint8Array): boolean {
  const n = Math.min(bytes.length, 8000);
  for (let i = 0; i < n; i++) if (bytes[i] === 0) return true;
  return false;
}

export async function fetchRepo(
  owner: string,
  repo: string,
  sha: string,
  env: Env,
): Promise<FetchResult> {
  const r = await fetch(
    `https://codeload.github.com/${owner}/${repo}/tar.gz/${sha}`,
    { headers: { "User-Agent": "frisk" } },
  );
  if (!r.ok) throw new HttpError(502, `Tarball download failed (${r.status}).`);

  const tar = await gunzip(await r.arrayBuffer());
  const entries = parseTar(tar);

  const files: RepoFile[] = [];
  let total = 0;
  let truncated = false;

  for (const e of entries) {
    if (e.type !== "file" || !e.data) continue;
    const path = stripTop(e.name);
    if (!path) continue;

    const data = e.data instanceof Uint8Array ? e.data : new Uint8Array(e.data);
    total += data.length;
    if (files.length >= MAX_FILES || total > MAX_TOTAL) {
      truncated = true;
      break;
    }

    const isBinary = BINARY_EXT.test(path) || looksBinary(data);
    const text =
      !isBinary && data.length <= MAX_DECODE
        ? new TextDecoder().decode(data)
        : null;

    files.push({ path, bytes: data, text, isBinary });
  }

  return { files, truncated, sizeBytes: total };
}
