import type { Env, Finding } from "../types";
import type { RepoFile } from "../fetchRepo";

// Executable/library formats worth a VirusTotal lookup.
const SCAN_BINARY_EXT =
  /\.(exe|dll|so|dylib|bin|node|wasm|msi|apk|jar|deb|rpm|dmg|pkg|scr|com|elf)$/i;

const MAX_BINARIES = 10; // per scan, to respect VT free quota (4/min, 500/day)
const DAILY_CAP = 480;
const VT_CACHE_TTL = 7 * 86400;

interface VtResult {
  found: boolean;
  malicious: number;
  total: number;
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}

async function quotaLeft(env: Env): Promise<boolean> {
  const key = `vtq:${today()}`;
  const used = Number((await env.RATELIMIT.get(key)) ?? "0");
  return used < DAILY_CAP;
}

async function bumpQuota(env: Env): Promise<void> {
  const key = `vtq:${today()}`;
  const used = Number((await env.RATELIMIT.get(key)) ?? "0");
  await env.RATELIMIT.put(key, String(used + 1), { expirationTtl: 2 * 86400 });
}

async function lookup(hash: string, env: Env): Promise<VtResult | null> {
  const cached = await env.VT_CACHE.get(hash, "json");
  if (cached) return cached as VtResult;

  if (!env.VT_API_KEY || !(await quotaLeft(env))) return null;

  const r = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
    headers: { "x-apikey": env.VT_API_KEY },
  });
  await bumpQuota(env);

  let result: VtResult;
  if (r.status === 404) {
    result = { found: false, malicious: 0, total: 0 };
  } else if (r.ok) {
    const stats =
      ((await r.json()) as any)?.data?.attributes?.last_analysis_stats ?? {};
    const malicious = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
    const total = Object.values(stats).reduce(
      (a: number, b) => a + (Number(b) || 0),
      0,
    );
    result = { found: true, malicious, total };
  } else {
    return null; // 401/429/5xx — don't cache, treat as "not checked"
  }

  await env.VT_CACHE.put(hash, JSON.stringify(result), {
    expirationTtl: VT_CACHE_TTL,
  });
  return result;
}

export async function scanBinaries(
  files: RepoFile[],
  env: Env,
  notes: string[],
): Promise<Finding[]> {
  const bins = files.filter((f) => f.isBinary && SCAN_BINARY_EXT.test(f.path));
  if (bins.length === 0) return [];

  if (!env.VT_API_KEY) {
    notes.push(
      `${bins.length} binary file(s) found but VirusTotal is not configured, so they were not checked.`,
    );
    return [];
  }

  const findings: Finding[] = [];
  const targets = bins.slice(0, MAX_BINARIES);
  if (bins.length > MAX_BINARIES) {
    notes.push(
      `Only the first ${MAX_BINARIES} of ${bins.length} binaries were checked against VirusTotal (quota limit).`,
    );
  }

  for (const f of targets) {
    const hash = await sha256(f.bytes);
    const vt = await lookup(hash, env);
    if (vt === null) {
      notes.push(`Could not check ${f.path} (VirusTotal quota/error).`);
      findings.push({
        severity: "info",
        category: "binary",
        title: "Binary not checked",
        file: f.path,
        detail: `SHA-256 ${hash}. VirusTotal lookup unavailable.`,
      });
      continue;
    }
    if (vt.found && vt.malicious > 0) {
      findings.push({
        severity: vt.malicious >= 5 ? "critical" : "high",
        category: "binary",
        title: `Malicious binary (${vt.malicious}/${vt.total} engines)`,
        file: f.path,
        detail: `VirusTotal flagged this file. SHA-256 ${hash}. https://www.virustotal.com/gui/file/${hash}`,
      });
    } else if (vt.found) {
      findings.push({
        severity: "info",
        category: "binary",
        title: "Binary known-clean on VirusTotal",
        file: f.path,
        detail: `0/${vt.total} engines flagged it. SHA-256 ${hash}.`,
      });
    } else {
      findings.push({
        severity: "low",
        category: "binary",
        title: "Unknown binary (not in VirusTotal)",
        file: f.path,
        detail: `VirusTotal has never seen this file. Committed binaries of unknown provenance are a risk. SHA-256 ${hash}.`,
      });
    }
  }
  return findings;
}
