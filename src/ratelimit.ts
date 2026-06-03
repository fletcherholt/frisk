import type { Env } from "./types";

const LIMIT = 20;
const WINDOW_SEC = 600;

export async function checkRateLimit(
  ip: string,
  env: Env,
): Promise<{ ok: boolean; remaining: number }> {
  const bucket = Math.floor(Date.now() / 1000 / WINDOW_SEC);
  const key = `rl:${ip}:${bucket}`;
  const count = Number((await env.RATELIMIT.get(key)) ?? "0");
  if (count >= LIMIT) return { ok: false, remaining: 0 };
  await env.RATELIMIT.put(key, String(count + 1), {
    expirationTtl: WINDOW_SEC,
  }).catch(() => {});
  return { ok: true, remaining: LIMIT - count - 1 };
}
