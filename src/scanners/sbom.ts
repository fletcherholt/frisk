import type { Report } from "../types";

const PURL_TYPE: Record<string, string> = {
  npm: "npm",
  PyPI: "pypi",
  Go: "golang",
  "crates.io": "cargo",
};

export function toCycloneDX(report: Report): object {
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    metadata: {
      timestamp: report.scannedAt,
      tools: [{ vendor: "friskit.dev", name: "frisk" }],
      component: {
        type: "application",
        name: `${report.owner}/${report.repo}`,
        version: report.sha.slice(0, 12),
        ...(report.license
          ? { licenses: [{ license: { name: report.license } }] }
          : {}),
      },
    },
    components: report.components.map((c) => ({
      type: "library",
      name: c.name,
      version: c.version,
      purl: `pkg:${PURL_TYPE[c.ecosystem] ?? c.ecosystem.toLowerCase()}/${c.name.replace(/^@/, "%40")}@${c.version}`,
    })),
  };
}

export function parseRepoLicense(path: string, text: string): string | null {
  if (path === "package.json") {
    try {
      const j = JSON.parse(text) as { license?: unknown };
      if (typeof j.license === "string") return j.license;
    } catch {
      return null;
    }
  }
  if (path === "Cargo.toml") {
    const m = text.match(/^\s*license\s*=\s*"([^"]+)"/m);
    if (m) return m[1];
  }
  if (path === "pyproject.toml") {
    const m = text.match(/^\s*license\s*=\s*["']([^"'\n]+)["']/m);
    if (m) return m[1].trim();
  }
  return null;
}
