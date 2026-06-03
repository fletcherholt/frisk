import type { Finding, Severity } from "../types";
import { lineOf, snippetAt, isLowSignalPath } from "../util";

interface Rule {
  id: string;
  title: string;
  re: RegExp;
  severity: Severity;
  detail: string;
  soft?: boolean;
}

const RULES: Rule[] = [
  { id: "eval-atob", title: "Obfuscated eval (eval/atob)", severity: "critical", detail: "Decodes and executes a hidden payload at runtime. Classic stager.", re: /\b(?:eval|Function)\s*\(\s*(?:atob|unescape|decodeURIComponent)\s*\(/g },
  { id: "eval-fromcharcode", title: "Obfuscated eval (fromCharCode)", severity: "high", detail: "Builds code from character codes and executes it.", re: /\b(?:eval|Function)\s*\(\s*String\.fromCharCode/g },
  { id: "py-exec-b64", title: "Python exec of base64", severity: "critical", detail: "Decodes base64 and executes it. Common malware loader.", re: /\b(?:exec|eval)\s*\(\s*(?:base64\.b64decode|__import__\(\s*['"]base64)/g },
  { id: "py-marshal", title: "Python marshal/pickle loader", severity: "medium", soft: true, detail: "Loads marshalled or pickled data, which can run arbitrary code if the input is untrusted.", re: /\bmarshal\.loads\s*\(|\bpickle\.loads\s*\(/g },
  { id: "powershell-enc", title: "Encoded PowerShell command", severity: "high", detail: "Runs a base64 encoded PowerShell payload.", re: /powershell(?:\.exe)?\s+.{0,300}-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{40,4096}/gi },
  { id: "base64-blob", title: "Large embedded base64 blob", severity: "low", soft: true, detail: "A long base64 string. Usually embedded data, occasionally a hidden payload.", re: /['"`][A-Za-z0-9+/]{350,}/g },
  { id: "hex-blob", title: "Large hex/byte blob", severity: "low", soft: true, detail: "A long escaped byte sequence. Occasionally hides shellcode.", re: /(?:\\x[0-9a-fA-F]{2}){80,}/g },
  { id: "curl-pipe-sh", title: "Pipe remote script to shell", severity: "medium", soft: true, detail: "Downloads and runs a remote script. Standard in install docs and CI, only risky when it runs automatically from untrusted code.", re: /\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/g },
  { id: "ssh-read", title: "Reads SSH private keys", severity: "medium", soft: true, detail: "Accesses SSH private keys. Normal for SSH, git and deployment tooling, only a concern in untrusted code.", re: /(?:\.ssh\/id_(?:rsa|ed25519|ecdsa|dsa)|\/\.ssh\/authorized_keys)/g },
  { id: "cloud-creds-read", title: "Reads cloud credentials file", severity: "low", soft: true, detail: "Reads the cloud credentials file. Normal for cloud SDKs and CLIs, only a concern in untrusted code.", re: /(?:\.aws\/credentials|\.config\/gcloud|\.azure\/credentials)/g },
  { id: "wallet-file", title: "References a crypto wallet file", severity: "medium", soft: true, detail: "References a wallet file such as wallet.dat. Normal in wallet software, a concern in untrusted code.", re: /\bwallet\.dat\b/gi },
  { id: "wallet-steal", title: "Targets crypto wallet storage", severity: "high", soft: true, detail: "Reaches into a wallet's on-disk storage in a user profile directory, the behaviour of a crypto stealer.", re: /(?:AppData|Roaming|Application Support|Local Extension Settings|\.config|\.ethereum|\.electrum)[\\/][^\n'"`]{0,80}(?:MetaMask|Exodus|Electrum|Ledger\s*Live|Atomic|Coinbase|wallet)|(?:MetaMask|Exodus|Electrum|Ledger\s*Live|Atomic\s*Wallet)[^\n'"`]{0,40}(?:Local Storage|Extension Settings|leveldb|\.ldb|keystore|\.wallet)/gi },
  { id: "browser-steal", title: "Targets browser login data", severity: "high", soft: true, detail: "Reads the browser credential store. Credential stealer behaviour.", re: /(?:Google[\\/]Chrome|BraveSoftware|Microsoft[\\/]Edge|Chromium)[\\/]User Data|\bLogin Data\b[^\n]{0,40}(?:sqlite|SELECT |encrypted_value|password_value|origin_url)/gi },
  { id: "discord-token", title: "Targets Discord tokens", severity: "high", soft: true, detail: "Reads Discord tokens. Info stealer behaviour.", re: /discord[^\n]{0,40}(?:leveldb|\.ldb)/gi },
];

const CI_BUILD = /(^|\/)\.github\/|(^|\/)Dockerfile/i;

const INSTALL_HOOKS = /"(pre|post)?install"\s*:/g;

const COMMENT_LINE = /^\s*(?:\/\/|\/\*|\*\/?|#|<!--|;|--)/;

function isCommentAt(text: string, index: number): boolean {
  const start = text.lastIndexOf("\n", index) + 1;
  let end = text.indexOf("\n", index);
  if (end === -1) end = text.length;
  return COMMENT_LINE.test(text.slice(start, end));
}

function downgrade(s: Severity): Severity {
  return s === "critical" || s === "high" ? "low" : "info";
}

export function scanPatternsText(path: string, text: string): Finding[] {
  const findings: Finding[] = [];
  const soft = isLowSignalPath(path) || CI_BUILD.test(path);

  for (const rule of RULES) {
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
      const commented = isCommentAt(text, m.index);
      const dampened = soft || commented;
      findings.push({
        severity: dampened ? downgrade(rule.severity) : rule.severity,
        category: "pattern",
        title: commented
          ? `${rule.title} (in a comment)`
          : soft
            ? `${rule.title} (in vendored, test or example code)`
            : rule.title,
        file: path,
        line,
        detail: rule.detail,
        snippet: snippetAt(text, m.index),
      });
      if (++perRule >= 15) break;
    }
  }

  if (/(^|\/)package\.json$/.test(path)) {
    INSTALL_HOOKS.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = INSTALL_HOOKS.exec(text)) !== null) {
      findings.push({
        severity: soft ? "low" : "medium",
        category: "pattern",
        title: "npm install lifecycle hook",
        file: path,
        line: lineOf(text, m.index),
        detail: "preinstall and postinstall scripts run automatically on `npm install`, a common supply chain vector. Review the command.",
        snippet: snippetAt(text, m.index),
      });
    }
  }
  return findings;
}
