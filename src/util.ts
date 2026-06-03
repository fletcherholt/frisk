export class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** 1-based line number of a character index within text. */
export function lineOf(text: string, index: number): number {
  let line = 1;
  const n = Math.min(index, text.length);
  for (let i = 0; i < n; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/** The single source line containing `index`, trimmed and length-capped. */
export function snippetAt(text: string, index: number, max = 160): string {
  const start = text.lastIndexOf("\n", index) + 1;
  let end = text.indexOf("\n", index);
  if (end === -1) end = text.length;
  const line = text.slice(start, end).trim();
  return line.length > max ? line.slice(0, max) + "…" : line;
}

/** Shannon entropy (bits per char) of a string — high for keys/tokens. */
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
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

export function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}
