import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const corpus = JSON.parse(
  readFileSync(join(root, "test", "corpus.json"), "utf8"),
);

const base = process.env.FRISK_BASE ?? "https://friskit.dev";
const fresh = process.argv.includes("--fresh");
const heuristic = new Set(corpus.heuristicCategories);

function scanCacheId() {
  const toml = readFileSync(join(root, "wrangler.toml"), "utf8");
  const m = toml.match(/binding\s*=\s*"SCAN_CACHE"\s*\n\s*id\s*=\s*"([^"]+)"/);
  if (!m) throw new Error("SCAN_CACHE id not found in wrangler.toml");
  return m[1];
}

async function fetchReport(repo) {
  let last;
  for (let attempt = 0; attempt < 3; attempt++) {
    const r = await fetch(`${base}/api/scan/${repo}?view=1`, {
      signal: AbortSignal.timeout(150000),
    });
    if (r.ok) return r.json();
    last = `HTTP ${r.status}`;
    if (r.status < 500) break;
    await new Promise((res) => setTimeout(res, 3000));
  }
  throw new Error(last);
}

async function scan(repo) {
  if (!fresh) return fetchReport(repo);
  const first = await fetchReport(repo);
  if (first.sha) {
    execFileSync(
      "npx",
      ["wrangler", "kv", "key", "delete", "--remote",
        "--namespace-id", scanCacheId(), `${repo}@${first.sha}`],
      { cwd: root, stdio: "ignore" },
    );
  }
  return fetchReport(repo);
}

function check(c, report) {
  if (report.error) return [`scan error: ${report.error}`];
  const fails = [];
  if (c.expect === "critical") {
    if (report.score.level !== "critical")
      fails.push(`control should be critical, got ${report.score.level}`);
    return fails;
  }
  const loudHeuristic = report.findings.filter(
    (f) =>
      heuristic.has(f.category) &&
      (f.severity === "critical" || f.severity === "high"),
  );
  for (const f of loudHeuristic)
    fails.push(`heuristic ${f.severity}: "${f.title}" @ ${f.file}`);
  return fails;
}

let failed = 0;
for (const c of corpus.cases) {
  try {
    const report = await scan(c.repo);
    const fails = check(c, report);
    if (fails.length) {
      failed++;
      console.log(`FAIL  ${c.repo}`);
      for (const f of fails) console.log(`        ${f}`);
    } else {
      console.log(`ok    ${c.repo}  (${report.score.level})`);
    }
  } catch (e) {
    failed++;
    console.log(`FAIL  ${c.repo}  ${e.message}`);
  }
}

console.log(
  failed ? `\n${failed} regression(s)` : `\nall ${corpus.cases.length} clean`,
);
process.exit(failed ? 1 : 0);
