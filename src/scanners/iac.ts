import type { Finding, Severity } from "../types";
import { lineOf, snippetAt, isLowSignalPath } from "../util";

interface Rule {
  title: string;
  severity: Severity;
  detail: string;
  re: RegExp;
}

const DOCKERFILE_RULES: Rule[] = [
  { title: "Dockerfile ADD from a remote URL", severity: "low", detail: "ADD of a remote URL pulls unverified content into the image. Prefer COPY, or download with a checksum.", re: /^\s*ADD\s+https?:\/\//gim },
  { title: "Secret baked into an image layer", severity: "medium", detail: "A credential set in ENV or ARG is persisted in the image and visible to anyone who pulls it.", re: /^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY)\w*\s*[=\s]\s*\S/gim },
];

const INFRA_RULES: Rule[] = [
  { title: "Privileged container", severity: "medium", detail: "A privileged container has near-root access to the host. Common and often intentional in infrastructure manifests, worth confirming.", re: /^\s*privileged:\s*true/gim },
  { title: "Mounts the Docker socket", severity: "medium", detail: "Mounting /var/run/docker.sock gives the container full control of the Docker daemon, equivalent to host root. Common in dev and CI tooling, worth confirming.", re: /\/var\/run\/docker\.sock/g },
  { title: "Host networking", severity: "medium", detail: "Host networking removes network isolation between the container and the host.", re: /^\s*(?:network_mode:\s*["']?host|hostNetwork:\s*true)/gim },
  { title: "hostPath volume mount", severity: "medium", detail: "A hostPath mount exposes a host directory to the pod.", re: /^\s*hostPath:/gim },
  { title: "Open to the whole internet (0.0.0.0/0)", severity: "high", detail: "An ingress rule allowing 0.0.0.0/0 exposes the resource to the entire internet.", re: /0\.0\.0\.0\/0/g },
  { title: "Publicly readable storage", severity: "medium", detail: "A public-read ACL makes the bucket or object world-readable.", re: /acl\s*[=:]\s*["']public-read/gi },
];

const WORKFLOW_RULES: Rule[] = [
  { title: "Workflow triggered by pull_request_target", severity: "low", detail: "pull_request_target runs with repository secrets while checking out untrusted PR code, a common privilege-escalation path. Review it carefully.", re: /pull_request_target/g },
];

const INJECT_FIELD =
  /\$\{\{\s*github\.(?:event\.(?:issue|pull_request|comment|review)\.(?:title|body)|event\.pull_request\.head\.ref|head_ref)[^}]*\}\}/;

function scanWorkflowInjection(
  path: string,
  text: string,
  soft: boolean,
  findings: Finding[],
): void {
  const lines = text.split("\n");
  let inRun = false;
  let runIndent = -1;
  let count = 0;
  let offset = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineStart = offset;
    offset += line.length + 1;
    if (count >= 10 || !line.trim()) continue;
    const indent = line.length - line.trimStart().length;
    const runMatch = /^\s*(?:-\s+)?run:\s*(.*)$/.exec(line);
    let danger = false;
    if (runMatch) {
      runIndent = indent;
      const rest = runMatch[1].trim();
      danger = INJECT_FIELD.test(line);
      inRun = rest === "" || rest.startsWith("|") || rest.startsWith(">");
    } else if (inRun) {
      if (indent > runIndent) danger = INJECT_FIELD.test(line);
      else inRun = false;
    }
    if (danger) {
      findings.push({
        severity: soft ? "low" : "high",
        category: "infrastructure",
        title: "Possible workflow script injection",
        file: path,
        line: i + 1,
        detail: "Interpolating an attacker-controlled field straight into a run step lets a PR or issue inject shell commands. Pass it through an env var instead.",
        snippet: snippetAt(text, lineStart),
      });
      count++;
    }
  }
}

function applyRules(
  rules: Rule[],
  path: string,
  text: string,
  soft: boolean,
  findings: Finding[],
): void {
  for (const rule of rules) {
    rule.re.lastIndex = 0;
    let m: RegExpExecArray | null;
    let count = 0;
    const seen = new Set<number>();
    while ((m = rule.re.exec(text)) !== null) {
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
      const line = lineOf(text, m.index);
      if (seen.has(line)) continue;
      seen.add(line);
      findings.push({
        severity: soft ? "low" : rule.severity,
        category: "infrastructure",
        title: rule.title,
        file: path,
        line,
        detail: rule.detail,
        snippet: snippetAt(text, m.index),
      });
      if (++count >= 10) break;
    }
  }
}

export function scanIacText(path: string, text: string): Finding[] {
  const base = path.split("/").pop()?.toLowerCase() ?? "";
  const isDockerfile =
    base === "dockerfile" ||
    base.endsWith(".dockerfile") ||
    base.startsWith("dockerfile.");
  const isYaml = /\.ya?ml$/.test(path);
  const isTf = path.endsWith(".tf");
  const isWorkflow = /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(path);

  if (!isDockerfile && !isYaml && !isTf) return [];

  const findings: Finding[] = [];
  const soft = isLowSignalPath(path);

  if (isDockerfile) {
    applyRules(DOCKERFILE_RULES, path, text, soft, findings);
    if (/^\s*FROM\s/im.test(text) && !/^\s*USER\s/im.test(text)) {
      findings.push({
        severity: "info",
        category: "infrastructure",
        title: "Container runs as root",
        file: path,
        detail: "This Dockerfile sets no USER, so the container runs as root. Add a non-root USER.",
      });
    }
  }
  if (isYaml || isTf) applyRules(INFRA_RULES, path, text, soft, findings);
  if (isWorkflow) {
    applyRules(WORKFLOW_RULES, path, text, soft, findings);
    scanWorkflowInjection(path, text, soft, findings);
  }

  return findings;
}
