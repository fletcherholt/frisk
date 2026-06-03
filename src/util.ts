const LOW_SIGNAL_DIR =
  /(^|\/)(tests?|testdata|test[-_]data|specs?|__tests__|examples?|fixtures?|mocks?|samples?|docs?|docs_src|documentation|wiki|benches?|benchmarks?|e2e|vendor|vendored|third[-_]party|node_modules)\//i;
const DOC_FILE = /\.(md|mdx|markdown|rst|adoc|txt)$|(^|\/)readme[^/]*$/i;
const TEST_FILE =
  /(?:^|\/)(?:test_[^/]+|[^/]+[._-](?:test|spec)s?)\.[A-Za-z0-9]+$/i;
const GENERATED_FILE =
  /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|bun\.lockb?|go\.sum|gradle\.lockfile)$|\.lock$|\.(?:min\.(?:js|css|mjs)|map)$|(?:\.pb\.go|_pb2\.py|\.generated\.[A-Za-z0-9]+|\.g\.dart)$/i;

export function isLowSignalPath(path: string): boolean {
  return (
    LOW_SIGNAL_DIR.test(path) ||
    DOC_FILE.test(path) ||
    TEST_FILE.test(path) ||
    GENERATED_FILE.test(path)
  );
}

export function isGeneratedFile(path: string): boolean {
  return GENERATED_FILE.test(path);
}

export class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function lineOf(text: string, index: number): number {
  let line = 1;
  const n = Math.min(index, text.length);
  for (let i = 0; i < n; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

export function snippetAt(text: string, index: number, max = 160): string {
  const start = text.lastIndexOf("\n", index) + 1;
  let end = text.indexOf("\n", index);
  if (end === -1) end = text.length;
  const line = text.slice(start, end).trim();
  return line.length > max ? line.slice(0, max) + "…" : line;
}

export function shannon(s: string): number {
  if (!s) return 0;
  const freq: Record<string, number> = {};
  for (const ch of s) freq[ch] = (freq[ch] ?? 0) + 1;
  let h = 0;
  for (const k in freq) {
    const p = freq[k] / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function htmlResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
    },
  });
}

export function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
