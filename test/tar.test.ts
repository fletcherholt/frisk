import { describe, it, expect } from "vitest";
import { createTar } from "nanotar";
import { streamTar, type FileKind, type TarStats } from "../src/tar";

const enc = new TextEncoder();
const dec = new TextDecoder();

function streamOf(data: Uint8Array, chunk = 64): ReadableStream<Uint8Array> {
  let i = 0;
  return new ReadableStream<Uint8Array>({
    pull(c) {
      if (i >= data.length) {
        c.close();
        return;
      }
      const end = Math.min(i + chunk, data.length);
      c.enqueue(data.subarray(i, end));
      i = end;
    },
  });
}

async function collect(
  data: Uint8Array,
  classify: (n: string, s: number) => FileKind | "skip",
  chunk = 64,
) {
  const stats: TarStats = { files: 0, bytes: 0, truncated: false };
  const out: { name: string; text: string }[] = [];
  for await (const f of streamTar(streamOf(data, chunk), classify, { maxFiles: 1000, maxBytes: 1 << 30 }, stats)) {
    out.push({ name: f.name, text: dec.decode(f.bytes) });
  }
  return { out, stats };
}

function hdr(name: string, size: number, type: string): Uint8Array {
  const h = new Uint8Array(512);
  h.set(enc.encode(name.slice(0, 100)), 0);
  h.set(enc.encode(size.toString(8).padStart(11, "0")), 124);
  h[135] = 0;
  h[156] = type.charCodeAt(0);
  h.set(enc.encode("ustar\0" + "00"), 257);
  return h;
}
function pad512(d: Uint8Array): Uint8Array {
  const p = new Uint8Array(Math.ceil(d.length / 512) * 512);
  p.set(d);
  return p;
}
function concat(arrs: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const a of arrs) n += a.length;
  const o = new Uint8Array(n);
  let off = 0;
  for (const a of arrs) {
    o.set(a, off);
    off += a.length;
  }
  return o;
}
function paxRec(key: string, val: string): Uint8Array {
  const body = `${key}=${val}\n`;
  let len = body.length + 2;
  while (`${len} ${body}`.length !== len) len = `${len} ${body}`.length;
  return enc.encode(`${len} ${body}`);
}

describe("streamTar", () => {
  const all = () => "text" as const;

  it("reads files, strips the top dir, handles nesting and empty files", async () => {
    const tar = createTar([
      { name: "repo-abc/a.txt", data: "hello" },
      { name: "repo-abc/dir/b.js", data: "eval(1)" },
      { name: "repo-abc/empty.txt", data: "" },
    ]);
    const { out } = await collect(tar, all);
    expect(out).toEqual([
      { name: "a.txt", text: "hello" },
      { name: "dir/b.js", text: "eval(1)" },
      { name: "empty.txt", text: "" },
    ]);
  });

  it("gives identical results across tiny and large chunk sizes", async () => {
    const tar = createTar([
      { name: "r/one.txt", data: "x".repeat(600) },
      { name: "r/two.txt", data: "y" },
    ]);
    const tiny = await collect(tar, all, 3);
    const big = await collect(tar, all, 100000);
    expect(tiny.out).toEqual(big.out);
    expect(tiny.out[0].text.length).toBe(600);
  });

  it("skips files the classifier rejects", async () => {
    const tar = createTar([
      { name: "r/keep.txt", data: "a" },
      { name: "r/skip.png", data: "binarydata" },
      { name: "r/also.txt", data: "b" },
    ]);
    const { out } = await collect(tar, (n) => (n.endsWith(".png") ? "skip" : "text"));
    expect(out.map((f) => f.name)).toEqual(["keep.txt", "also.txt"]);
  });

  it("resolves long paths from a pax extended header", async () => {
    const longName = "repo-abc/" + "x".repeat(120) + "/deep/file.js";
    const data = enc.encode("payload");
    const rec = paxRec("path", longName);
    const tar = concat([
      hdr("paxheader", rec.length, "x"),
      pad512(rec),
      hdr("repo-abc/file.js", data.length, "0"),
      pad512(data),
      new Uint8Array(1024),
    ]);
    const { out } = await collect(tar, all);
    expect(out).toEqual([
      { name: "x".repeat(120) + "/deep/file.js", text: "payload" },
    ]);
  });

  it("stops and marks truncated at the file limit", async () => {
    const tar = createTar([
      { name: "r/1.txt", data: "a" },
      { name: "r/2.txt", data: "b" },
      { name: "r/3.txt", data: "c" },
    ]);
    const stats: TarStats = { files: 0, bytes: 0, truncated: false };
    const names: string[] = [];
    for await (const f of streamTar(streamOf(tar), all, { maxFiles: 2, maxBytes: 1 << 30 }, stats)) {
      names.push(f.name);
    }
    expect(names).toEqual(["1.txt", "2.txt"]);
    expect(stats.truncated).toBe(true);
  });
});
