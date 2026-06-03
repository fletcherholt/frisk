const DEC = new TextDecoder();

export type FileKind = "text" | "binary";

export interface TarFile {
  name: string;
  bytes: Uint8Array;
  kind: FileKind;
  size: number;
}

export interface TarLimits {
  maxFiles: number;
  maxBytes: number;
}

export interface TarStats {
  files: number;
  bytes: number;
  truncated: boolean;
}

class ByteSource {
  private reader: ReadableStreamDefaultReader<Uint8Array>;
  private queue: Uint8Array[] = [];
  private queued = 0;
  private done = false;

  constructor(stream: ReadableStream<Uint8Array>) {
    this.reader = stream.getReader();
  }

  private async pull(): Promise<boolean> {
    if (this.done) return false;
    const { done, value } = await this.reader.read();
    if (done) {
      this.done = true;
      return false;
    }
    if (value && value.length) {
      this.queue.push(value);
      this.queued += value.length;
    }
    return true;
  }

  async read(n: number): Promise<Uint8Array> {
    while (this.queued < n && (await this.pull())) {}
    const take = Math.min(n, this.queued);
    const out = new Uint8Array(take);
    let off = 0;
    while (off < take) {
      const head = this.queue[0];
      const need = take - off;
      if (head.length <= need) {
        out.set(head, off);
        off += head.length;
        this.queue.shift();
        this.queued -= head.length;
      } else {
        out.set(head.subarray(0, need), off);
        off += need;
        this.queue[0] = head.subarray(need);
        this.queued -= need;
      }
    }
    return out;
  }

  async skip(n: number): Promise<void> {
    let remaining = n;
    while (remaining > 0) {
      while (this.queued === 0 && (await this.pull())) {}
      if (this.queued === 0) break;
      const head = this.queue[0];
      if (head.length <= remaining) {
        remaining -= head.length;
        this.queued -= head.length;
        this.queue.shift();
      } else {
        this.queue[0] = head.subarray(remaining);
        this.queued -= remaining;
        remaining = 0;
      }
    }
  }

  async cancel(): Promise<void> {
    try {
      await this.reader.cancel();
    } catch {}
  }
}

function isZeroBlock(b: Uint8Array): boolean {
  for (let i = 0; i < 512; i++) if (b[i] !== 0) return false;
  return true;
}

function readCStr(buf: Uint8Array, off: number, len: number): string {
  let end = off;
  const max = Math.min(off + len, buf.length);
  while (end < max && buf[end] !== 0) end++;
  return DEC.decode(buf.subarray(off, end));
}

function parseSize(h: Uint8Array): number {
  if (h[124] & 0x80) {
    let n = 0;
    for (let i = 125; i < 136; i++) n = n * 256 + h[i];
    return n;
  }
  let s = "";
  for (let i = 124; i < 136; i++) {
    const c = h[i];
    if (c === 0 || c === 32) break;
    s += String.fromCharCode(c);
  }
  return parseInt(s.trim() || "0", 8) || 0;
}

function stripTop(name: string): string {
  const i = name.indexOf("/");
  return i === -1 ? "" : name.slice(i + 1);
}

function paxPath(data: Uint8Array): string | null {
  let i = 0;
  while (i < data.length) {
    let j = i;
    while (j < data.length && data[j] !== 0x20) j++;
    const len = parseInt(readCStr(data, i, j - i), 10);
    if (!len || i + len > data.length) break;
    const rec = data.subarray(j + 1, i + len - 1);
    const eq = rec.indexOf(0x3d);
    if (eq > 0 && DEC.decode(rec.subarray(0, eq)) === "path")
      return DEC.decode(rec.subarray(eq + 1));
    i += len;
  }
  return null;
}

export async function* streamTar(
  stream: ReadableStream<Uint8Array>,
  classify: (name: string, size: number) => FileKind | "skip",
  limits: TarLimits,
  stats: TarStats,
): AsyncGenerator<TarFile> {
  const src = new ByteSource(stream);
  let pending: string | null = null;
  try {
    while (true) {
      if (stats.bytes >= limits.maxBytes || stats.files >= limits.maxFiles) {
        stats.truncated = true;
        break;
      }
      const header = await src.read(512);
      if (header.length < 512 || isZeroBlock(header)) break;
      stats.bytes += 512;

      const size = parseSize(header);
      const type = header[156];
      const padded = Math.ceil(size / 512) * 512;
      const pad = padded - size;

      if (type === 0x78 || type === 0x58) {
        const data = await src.read(size);
        await src.skip(pad);
        stats.bytes += padded;
        const p = paxPath(data);
        if (p) pending = p;
        continue;
      }
      if (type === 0x4c) {
        const data = await src.read(size);
        await src.skip(pad);
        stats.bytes += padded;
        pending = readCStr(data, 0, data.length).replace(/\0+$/, "");
        continue;
      }
      if (type === 0x67) {
        await src.skip(padded);
        stats.bytes += padded;
        continue;
      }

      const name = stripTop(pending ?? readCStr(header, 0, 100));
      pending = null;
      stats.bytes += padded;

      const isFile = type === 0 || type === 0x30;
      if (!isFile || !name) {
        await src.skip(padded);
        continue;
      }

      const kind = classify(name, size);
      if (kind === "skip") {
        await src.skip(padded);
        continue;
      }

      const bytes = await src.read(size);
      await src.skip(pad);
      stats.files++;
      yield { name, bytes, kind, size };
    }
  } finally {
    await src.cancel();
  }
}
