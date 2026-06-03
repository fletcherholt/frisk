import type { Finding, Severity } from "../types";
import { lineOf, snippetAt, shannon, isLowSignalPath } from "../util";

interface Rule {
  id: string;
  title: string;
  re: RegExp;
  severity: Severity;
  /** If set, only fire when the matched group's entropy clears this bar. */
  minEntropy?: number;
  group?: number; // which capture group to entropy-check (default 0)
}

const RULES: Rule[] = [
  { id: "aws-akid", title: "AWS access key ID", severity: "high", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: "aws-secret", title: "AWS secret access key", severity: "critical", re: /\baws_secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+]{40})['"]?/gi, minEntropy: 4.0, group: 1 },
  { id: "gh-pat", title: "GitHub personal access token", severity: "critical", re: /\bghp_[0-9A-Za-z]{36}\b/g },
  { id: "gh-pat-fine", title: "GitHub fine-grained token", severity: "critical", re: /\bgithub_pat_[0-9A-Za-z_]{82}\b/g },
  { id: "gh-oauth", title: "GitHub OAuth/refresh token", severity: "high", re: /\bgh[osru]_[0-9A-Za-z]{36}\b/g },
  { id: "slack", title: "Slack token", severity: "high", re: /\bxox[baprs]-[0-9A-Za-z-]{10,72}\b/g },
  { id: "stripe", title: "Stripe live secret key", severity: "critical", re: /\bsk_live_[0-9A-Za-z]{24,}\b/g },
  { id: "google-api", title: "Google API key", severity: "high", re: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { id: "private-key", title: "Private key block", severity: "critical", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { id: "jwt", title: "JSON Web Token", severity: "medium", re: /\beyJ[A-Za-z0-9_-]{8,1024}\.[A-Za-z0-9_-]{8,1024}\.[A-Za-z0-9_-]{8,1024}\b/g },
  { id: "slack-webhook", title: "Slack webhook URL", severity: "high", re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g },
  { id: "npm-token", title: "npm access token", severity: "high", re: /\bnpm_[0-9A-Za-z]{36}\b/g },
  // Generic key=value with a high-entropy value.
  { id: "generic-secret", title: "Hardcoded credential", severity: "medium", re: /(?:api[_-]?key|secret|token|passwd|password|client[_-]?secret)\s*[:=]\s*['"]([0-9A-Za-z\-_./+]{16,64})['"]/gi, minEntropy: 3.5, group: 1 },
];

export function scanSecretsText(path: string, text: string): Finding[] {
  const findings: Finding[] = [];
  const dampen = isLowSignalPath(path);
  const seen = new Set<string>();
  for (const rule of RULES) {
    rule.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    let perRule = 0;
    while ((m = rule.re.exec(text)) !== null) {
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++; // zero-width guard
      const probe = m[rule.group ?? 0] ?? m[0];
      if (rule.minEntropy && shannon(probe) < rule.minEntropy) continue;
      const line = lineOf(text, m.index);
      const key = `${rule.id}:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      let severity = rule.severity;
      if (dampen)
        severity = severity === "critical" ? "medium" : severity === "high" ? "low" : "info";
      findings.push({
        severity,
        category: "secret",
        title: dampen ? `${rule.title} (in docs, tests or examples)` : rule.title,
        file: path,
        line,
        detail: "Possible credential committed to the repository.",
        snippet: snippetAt(text, m.index),
      });
      if (++perRule >= 25) break; // cap noisy files
    }
  }
  return findings;
}
