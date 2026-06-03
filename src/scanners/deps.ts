import type { Finding } from "../types";
import type { RepoFile } from "../fetchRepo";

interface Dep {
  name: string;
  ecosystem: string;
  version: string;
  file: string;
}

const MAX_QUERIES = 500;

/** Pull the first concrete semver out of a version spec; null for pure ranges. */
function pinVersion(spec: string): string | null {
  const m = spec.match(/\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?/);
  return m ? m[0] : null;
}

function parsePackageJson(text: string, file: string): Dep[] {
  const out: Dep[] = [];
  try {
    const j = JSON.parse(text) as Record<string, unknown>;
    for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
      const deps = j[field] as Record<string, string> | undefined;
      if (!deps) continue;
      for (const [name, spec] of Object.entries(deps)) {
        const v = pinVersion(String(spec));
        if (v) out.push({ name, ecosystem: "npm", version: v, file });
      }
    }
  } catch {
    /* malformed package.json — ignore */
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

function collectDeps(files: RepoFile[]): Dep[] {
  const deps: Dep[] = [];
  for (const f of files) {
    if (!f.text) continue;
    if (/(^|\/)package\.json$/.test(f.path)) deps.push(...parsePackageJson(f.text, f.path));
    else if (/(^|\/)requirements[\w.-]*\.txt$/.test(f.path)) deps.push(...parseRequirements(f.text, f.path));
    else if (/(^|\/)go\.mod$/.test(f.path)) deps.push(...parseGoMod(f.text, f.path));
    else if (/(^|\/)Cargo\.toml$/.test(f.path)) deps.push(...parseCargo(f.text, f.path));
  }
  // Dedupe identical packages (same name, version and ecosystem) so a dep
  // listed in several manifests or sections is only reported once.
  const seen = new Set<string>();
  const unique = deps.filter((d) => {
    const key = `${d.ecosystem}:${d.name}@${d.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return unique.slice(0, MAX_QUERIES);
}

export async function scanDeps(files: RepoFile[]): Promise<Finding[]> {
  const deps = collectDeps(files);
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
    const ids = vulns.map((v) => v.id);
    findings.push({
      severity: vulns.length >= 3 ? "high" : "medium",
      category: "dependency",
      title: `Vulnerable dependency: ${d.name}@${d.version}`,
      file: d.file,
      detail: `${ids.length} known advisory(ies): ${ids.slice(0, 5).join(", ")}${ids.length > 5 ? "…" : ""} (${d.ecosystem}). See osv.dev/${ids[0]}`,
    });
  });
  return findings;
}
