import type { Env, Finding } from "../types";

export const SCAN_BINARY_EXT =
  /\.(exe|dll|so|dylib|bin|node|wasm|msi|apk|jar|deb|rpm|dmg|pkg|scr|com|elf)$/i;

export const MAX_BINARIES = 10;
const DAILY_CAP = 480;
const VT_CACHE_TTL = 7 * 86400;

export interface BinTarget {
  path: string;
  hash: string;
}

interface VtResult {
  found: boolean;
  malicious: number;
  total: number;
}

export async function sha256(bytes: Uint8Array): Promise<string> {
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
  await env.RATELIMIT.put(key, String(used + 1), {
    expirationTtl: 2 * 86400,
  }).catch(() => {});
}

async function lookup(hash: string, env: Env): Promise<VtResult | null> {
  try {
    const cached = await env.VT_CACHE.get(hash, "json");
    if (cached) return cached as VtResult;

    if (!env.VT_API_KEY || !(await quotaLeft(env))) return null;

    const r = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { "x-apikey": env.VT_API_KEY },
      signal: AbortSignal.timeout(8000),
    });
    await bumpQuota(env);

    let result: VtResult;
    if (r.status === 404) {
      result = { found: false, malicious: 0, total: 0 };
    } else if (r.ok) {
      const body = (await r.json()) as {
        data?: { attributes?: { last_analysis_stats?: Record<string, number> } };
      };
      const stats = body.data?.attributes?.last_analysis_stats ?? {};
      const malicious = (stats.malicious ?? 0) + (stats.suspicious ?? 0);
      const total = Object.values(stats).reduce((a, b) => a + (Number(b) || 0), 0);
      result = { found: true, malicious, total };
    } else {
      return null;
    }

    await env.VT_CACHE.put(hash, JSON.stringify(result), {
      expirationTtl: VT_CACHE_TTL,
    }).catch(() => {});
    return result;
  } catch {
    return null;
  }
}

export async function lookupBinaries(
  targets: BinTarget[],
  totalSeen: number,
  env: Env,
  notes: string[],
): Promise<Finding[]> {
  if (totalSeen === 0) return [];

  if (!env.VT_API_KEY) {
    notes.push(
      `${totalSeen} binary file(s) found but VirusTotal is not configured, so they were not checked.`,
    );
    return [];
  }
  if (totalSeen > targets.length) {
    notes.push(
      `Only the first ${targets.length} of ${totalSeen} binaries were checked against VirusTotal (quota limit).`,
    );
  }

  const findings: Finding[] = [];
  const looked = await Promise.all(
    targets.map((t) => lookup(t.hash, env).then((vt) => ({ ...t, vt }))),
  );
  for (const { path, hash, vt } of looked) {
    if (vt === null) {
      notes.push(`Could not check ${path} (VirusTotal quota/error).`);
      findings.push({
        severity: "info",
        category: "binary",
        title: "Binary not checked",
        file: path,
        detail: `SHA-256 ${hash}. VirusTotal lookup unavailable.`,
      });
      continue;
    }
    if (vt.found && vt.malicious > 0) {
      findings.push({
        severity: vt.malicious >= 5 ? "critical" : "high",
        category: "binary",
        title: `Malicious binary (${vt.malicious}/${vt.total} engines)`,
        file: path,
        detail: `VirusTotal flagged this file. SHA-256 ${hash}. https://www.virustotal.com/gui/file/${hash}`,
      });
    } else if (vt.found) {
      findings.push({
        severity: "info",
        category: "binary",
        title: "Binary known-clean on VirusTotal",
        file: path,
        detail: `0/${vt.total} engines flagged it. SHA-256 ${hash}.`,
      });
    } else {
      findings.push({
        severity: "info",
        category: "binary",
        title: "Unknown binary (not in VirusTotal)",
        file: path,
        detail: `VirusTotal has never seen this file. Worth a glance, but most committed binaries are harmless. SHA-256 ${hash}.`,
      });
    }
  }
  return findings;
}
