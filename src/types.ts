export interface Env {
  SCAN_CACHE: KVNamespace;
  VT_CACHE: KVNamespace;
  RATELIMIT: KVNamespace;
  GITHUB_TOKEN?: string;
  VT_API_KEY?: string;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Category =
  | "secret"
  | "pattern"
  | "infrastructure"
  | "dependency"
  | "binary"
  | "health";

export interface Finding {
  severity: Severity;
  category: Category;
  title: string;
  file: string;
  line?: number;
  detail: string;
  snippet?: string;
}

export interface Score {
  level: "critical" | "high" | "medium" | "low" | "clean";
  points: number;
  counts: Record<Severity, number>;
}

export interface Component {
  name: string;
  version: string;
  ecosystem: string;
}

export interface Report {
  owner: string;
  repo: string;
  sha: string;
  scannedAt: string;
  fileCount: number;
  truncated: boolean;
  findings: Finding[];
  score: Score;
  cached: boolean;
  notes: string[];
  components: Component[];
  license: string | null;
}
