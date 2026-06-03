import type { Finding, Severity } from "../types";
import type { RepoFile } from "../fetchRepo";
import { lineOf, snippetAt } from "../util";

interface Rule {
  id: string;
  title: string;
  re: RegExp;
  severity: Severity;
  detail: string;
  /** Context sensitive: drop to info in docs, examples and tests. */
  soft?: boolean;
}

const RULES: Rule[] = [
  { id: "eval-atob", title: "Obfuscated eval (eval/atob)", severity: "critical", detail: "Decodes and executes a hidden payload at runtime. Classic stager.", re: /\b(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(/g },
  { id: "eval-fromcharcode", title: "Obfuscated eval (fromCharCode)", severity: "high", detail: "Builds code from character codes and executes it.", re: /\b(?:eval|Function)\s*\(\s*String\.fromCharCode/g },
  { id: "py-exec-b64", title: "Python exec of base64", severity: "critical", detail: "Decodes base64 and executes it. Common malware loader.", re: /\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|__import__\(\s*['"]base64)/g },
  { id: "py-marshal", title: "Python marshal/pickle loader", severity: "high", detail: "Loads marshalled or pickled code, which can hide arbitrary execution.", re: /\bmarshal\.loads\s*\(|\bpickle\.loads\s*\(/g },
  { id: "powershell-enc", title: "Encoded PowerShell command", severity: "high", detail: "Runs a base64 encoded PowerShell payload.", re: /powershell(?:\.exe)?\s+.*-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}/gi },
  { id: "base64-blob", title: "Large embedded base64 blob", severity: "medium", detail: "A long base64 string can hide an embedded binary or payload.", re: /['"`][A-Za-z0-9+/]{350,}={0,2}['"`]/g },
  { id: "hex-blob", title: "Large hex/byte blob", severity: "medium", detail: "A long escaped byte sequence can hide shellcode.", re: /(?:\\x[0-9a-fA-F]{2}){80,}/g },
  // Context sensitive rules below: normal in docs and tooling, suspicious in untrusted code.
  { id: "curl-pipe-sh", title: "Pipe remote script to shell", severity: "medium", soft: true, detail: "Downloads and runs a remote script. Standard in install docs and CI, only risky when it runs automatically from untrusted code.", re: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/g },
  { id: "ssh-read", title: "Reads SSH private keys", severity: "high", soft: true, detail: "Accesses SSH private keys. Suspicious outside of SSH tooling.", re: /(?:\.ssh\/id_(?:rsa|ed25519|ecdsa|dsa)|\/\.ssh\/authorized_keys)/g },
  { id: "cloud-creds-read", title: "Reads cloud credentials file", severity: "low", soft: true, detail: "Reads the cloud credentials file. Normal for cloud SDKs and CLIs, only a concern in untrusted code.", re: /(?:\.aws\/credentials|\.config\/gcloud|\.azure\/credentials)/g },
  { id: "wallet-read", title: "Targets crypto wallets/keystores", severity: "high", soft: true, detail: "References crypto wallet or keystore files. Common in crypto stealers.", re: /\b(?:wallet\.dat|MetaMask|Exodus wallet|Electrum|ledgerlive)\b/g },
  { id: "browser-steal", title: "Targets browser login data", severity: "high", soft: true, detail: "Reads browser login data or cookies. Credential stealer behaviour.", re: /\b(?:Login Data|Cookies|Local Storage)\b[^\n]{0,60}(?:Chrome|Chromium|Edge|Brave|Firefox|Opera)/gi },
  { id: "discord-token", title: "Targets Discord tokens", severity: "high", soft: true, detail: "Reads Discord tokens. Info stealer behaviour.", re: /discord[^\n]{0,40}(?:leveldb|\.ldb)/gi },
];

// Documentation, examples, tests and CI: where commands are described or run by
// the project itself, not executed on someone who clones the repo.
const SOFT_PATH =
  /\.(md|mdx|markdown|rst|adoc|txt)$|(^|\/)(docs?|wiki|examples?|tests?|spec|specs|__tests__|fixtures?|mocks?|samples?|benches?|benchmarks?|e2e|\.github)\/|(^|\/)Dockerfile/i;

// package.json install-hook check (these run automatically on `npm install`).
const INSTALL_HOOKS = /"(pre|post)?install"\s*:/g;

export function scanPatterns(files: RepoFile[]): Finding[] {
  const findings: Finding[] = [];
  for (const f of files) {
    if (!f.text) continue;
    const text = f.text;
    const soft = SOFT_PATH.test(f.path);

    for (const rule of RULES) {
      // In docs, examples, tests and CI, context sensitive rules are just
      // describing or running normal commands. Skip them entirely.
      if (rule.soft && soft) continue;
      rule.re.lastIndex = 0;
      let m: RegExpExecArray | null;
      let perRule = 0;
      const seen = new Set<number>();
      while ((m = rule.re.exec(text)) !== null) {
        if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
        const line = lineOf(text, m.index);
        if (seen.has(line)) continue;
        seen.add(line);
        findings.push({
          severity: rule.severity,
          category: "pattern",
          title: rule.title,
          file: f.path,
          line,
          detail: rule.detail,
          snippet: snippetAt(text, m.index),
        });
        if (++perRule >= 15) break;
      }
    }

    // Install hooks only matter in package.json.
    if (/(^|\/)package\.json$/.test(f.path)) {
      INSTALL_HOOKS.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = INSTALL_HOOKS.exec(text)) !== null) {
        findings.push({
          severity: soft ? "low" : "medium",
          category: "pattern",
          title: "npm install lifecycle hook",
          file: f.path,
          line: lineOf(text, m.index),
          detail: "preinstall and postinstall scripts run automatically on `npm install`, a common supply chain vector. Review the command.",
          snippet: snippetAt(text, m.index),
        });
      }
    }
  }
  return findings;
}
