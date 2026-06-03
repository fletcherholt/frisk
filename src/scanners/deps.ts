import type { Finding } from "../types";
import { isLowSignalPath } from "../util";

export interface Dep {
  name: string;
  ecosystem: string;
  version: string;
  file: string;
}

const MAX_QUERIES = 500;

function pinVersion(spec: string): string | null {
  const m = spec.match(/\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?/);
  return m ? m[0] : null;
}

const NON_REGISTRY =
  /^(?:file:|link:|workspace:|git\+|git:|https?:|github:|portal:|patch:|catalog:|\.{0,2}\/)/i;

function resolveNpm(name: string, spec: string): { name: string; version: string } | null {
  const alias = spec.match(/^npm:(@?[^@/][^@]*(?:\/[^@]+)?)@(.+)$/);
  if (alias) {
    const v = pinVersion(alias[2]);
    return v ? { name: alias[1], version: v } : null;
  }
  if (NON_REGISTRY.test(spec)) return null;
  const v = pinVersion(spec);
  return v ? { name, version: v } : null;
}

function parsePackageJson(text: string, file: string): Dep[] {
  const out: Dep[] = [];
  try {
    const j = JSON.parse(text) as Record<string, unknown>;
    for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
      const deps = j[field] as Record<string, string> | undefined;
      if (!deps) continue;
      for (const [name, spec] of Object.entries(deps)) {
        const real = resolveNpm(name, String(spec));
        if (real) out.push({ name: real.name, ecosystem: "npm", version: real.version, file });
      }
    }
  } catch {
    return out;
  }
  return out;
}

function parseRequirements(text: string, file: string): Dep[] {
  const out: Dep[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) continue;
    const m = line.match(/^([A-Za-z0-9._-]+)\s*==\s*([0-9][0-9A-Za-z.\-+]*)/);
    if (m) out.push({ name: m[1], ecosystem: "PyPI", version: m[2], file });
  }
  return out;
}

function parseGoMod(text: string, file: string): Dep[] {
  const out: Dep[] = [];
  const re = /^\s*([\w.\-/]+)\s+v([0-9][0-9A-Za-z.\-+]*)/gm;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (m[1] === "module" || m[1] === "go") continue;
    out.push({ name: m[1], ecosystem: "Go", version: m[2], file });
  }
  return out;
}

function parseCargo(text: string, file: string): Dep[] {
  const out: Dep[] = [];
  let inDeps = false;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line.startsWith("[")) {
      inDeps = /^\[(?:dev-|build-)?dependencies\]/.test(line);
      continue;
    }
    if (!inDeps || !line || line.startsWith("#")) continue;
    const m = line.match(/^([A-Za-z0-9._-]+)\s*=\s*(?:"([^"]+)"|\{[^}]*version\s*=\s*"([^"]+)")/);
    if (m) {
      const v = pinVersion(m[2] ?? m[3] ?? "");
      if (v) out.push({ name: m[1], ecosystem: "crates.io", version: v, file });
    }
  }
  return out;
}

export function parseManifest(path: string, text: string): Dep[] {
  if (/(^|\/)package\.json$/.test(path)) return parsePackageJson(text, path);
  if (/(^|\/)requirements[\w.-]*\.txt$/.test(path)) return parseRequirements(text, path);
  if (/(^|\/)go\.mod$/.test(path)) return parseGoMod(text, path);
  if (/(^|\/)Cargo\.toml$/.test(path)) return parseCargo(text, path);
  return [];
}

export function isManifest(path: string): boolean {
  return /(^|\/)(package\.json|requirements[\w.-]*\.txt|go\.mod|Cargo\.toml)$/.test(path);
}

export async function queryOsv(collected: Dep[]): Promise<Finding[]> {
  const seen = new Set<string>();
  const deps = collected
    .filter((d) => {
      const key = `${d.ecosystem}:${d.name}@${d.version}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, MAX_QUERIES);
  if (deps.length === 0) return [];

  let results: Array<{ vulns?: Array<{ id: string }> }> = [];
  try {
    const r = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        queries: deps.map((d) => ({
          package: { name: d.name, ecosystem: d.ecosystem },
          version: d.version,
        })),
      }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!r.ok) return [];
    results = ((await r.json()) as { results?: typeof results }).results ?? [];
  } catch {
    return [];
  }

  const findings: Finding[] = [];
  results.forEach((res, i) => {
    const vulns = res.vulns;
    if (!vulns || vulns.length === 0) return;
    const d = deps[i];
    if (!d) return;
    const ids = vulns.map((v) => v.id);
    const malicious = ids.filter((id) => id.startsWith("MAL-"));

    if (malicious.length > 0) {
      findings.push({
        severity: "critical",
        category: "dependency",
        title: `Known-malicious package: ${d.name}@${d.version}`,
        file: d.file,
        detail: `Flagged as malicious in the OSSF malicious-packages feed: ${malicious.slice(0, 5).join(", ")} (${d.ecosystem}). See osv.dev/${malicious[0]}`,
      });
    }

    const advisories = ids.filter((id) => !id.startsWith("MAL-"));
    if (advisories.length > 0) {
      const severity = isLowSignalPath(d.file)
        ? "low"
        : advisories.length >= 3
          ? "high"
          : "medium";
      findings.push({
        severity,
        category: "dependency",
        title: `Vulnerable dependency: ${d.name}@${d.version}`,
        file: d.file,
        detail: `${advisories.length} known advisory(ies): ${advisories.slice(0, 5).join(", ")}${advisories.length > 5 ? "…" : ""} (${d.ecosystem}). See osv.dev/${advisories[0]}`,
      });
    }
  });
  return findings;
}
