import type { Finding, Severity } from "../types";
import type { RepoFile } from "../fetchRepo";
import { lineOf, snippetAt } from "../util";

interface Rule {
  id: string;
  title: string;
  re: RegExp;
  severity: Severity;
  detail: string;
}

const RULES: Rule[] = [
  { id: "eval-atob", title: "Obfuscated eval (eval/atob)", severity: "critical", detail: "Decodes and executes a hidden payload at runtime — classic stager.", re: /\b(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(/g },
  { id: "eval-fromcharcode", title: "Obfuscated eval (fromCharCode)", severity: "high", detail: "Builds code from char codes and executes it.", re: /\b(?:eval|Function)\s*\(\s*String\.fromCharCode/g },
  { id: "py-exec-b64", title: "Python exec of base64", severity: "critical", detail: "Decodes base64 and executes it — common malware loader.", re: /\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|__import__\(\s*['"]base64)/g },
  { id: "py-marshal", title: "Python marshal/pickle loader", severity: "high", detail: "Loads marshalled/pickled code — can hide arbitrary execution.", re: /\bmarshal\.loads\s*\(|\bpickle\.loads\s*\(/g },
  { id: "curl-pipe-sh", title: "Pipe remote script to shell", severity: "high", detail: "Downloads and runs a remote script unverified.", re: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/g },
  { id: "powershell-enc", title: "Encoded PowerShell command", severity: "high", detail: "Runs a base64-encoded PowerShell payload.", re: /powershell(?:\.exe)?\s+.*-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}/gi },
  { id: "base64-blob", title: "Large embedded base64 blob", severity: "medium", detail: "A long base64 string may hide an embedded binary or payload.", re: /['"`][A-Za-z0-9+/]{350,}={0,2}['"`]/g },
  { id: "hex-blob", title: "Large hex/byte blob", severity: "medium", detail: "A long \\x escaped sequence often hides shellcode.", re: /(?:\\x[0-9a-fA-F]{2}){80,}/g },
  { id: "ssh-read", title: "Reads SSH private keys", severity: "high", detail: "Accesses ~/.ssh — possible key theft.", re: /(?:\.ssh\/id_(?:rsa|ed25519|ecdsa|dsa)|\/\.ssh\/authorized_keys)/g },
  { id: "cloud-creds-read", title: "Reads cloud credential files", severity: "high", detail: "Accesses AWS/GCP credential files — possible exfiltration.", re: /(?:\.aws\/credentials|\.config\/gcloud|\.azure\/credentials)/g },
  { id: "wallet-read", title: "Targets crypto wallets/keystores", severity: "high", detail: "References wallet files — common in crypto stealers.", re: /\b(?:wallet\.dat|keystore|MetaMask|Exodus|Electrum|ledgerlive)\b/g },
  { id: "browser-steal", title: "Targets browser login data", severity: "high", detail: "Reads browser 'Login Data' / cookies — credential stealer behaviour.", re: /\b(?:Login Data|Cookies|Local Storage)\b[^\n]{0,60}(?:Chrome|Chromium|Edge|Brave|Firefox|Opera)/gi },
  { id: "discord-token", title: "Targets Discord tokens", severity: "high", detail: "Reads Discord leveldb tokens — info stealer behaviour.", re: /discord[^\n]{0,40}(?:leveldb|\.ldb|token)/gi },
  { id: "hardcoded-ip", title: "Hardcoded public IP", severity: "low", detail: "A hardcoded IP can be a C2 / exfiltration endpoint.", re: /\b(?!127\.0\.0\.1|0\.0\.0\.0|255\.255)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b(?::\d{2,5})?/g },
];

// package.json install-hook check (these run automatically on `npm install`).
const INSTALL_HOOKS = /"(pre|post)?install"\s*:/g;

export function scanPatterns(files: RepoFile[]): Finding[] {
  const findings: Finding[] = [];
  for (const f of files) {
    if (!f.text) continue;
    const text = f.text;

    for (const rule of RULES) {
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
          severity: "medium",
          category: "pattern",
          title: "npm install lifecycle hook",
          file: f.path,
          line: lineOf(text, m.index),
          detail: "preinstall/postinstall scripts run automatically on `npm install` — a common supply-chain vector. Review the command.",
          snippet: snippetAt(text, m.index),
        });
      }
    }
  }
  return findings;
}
