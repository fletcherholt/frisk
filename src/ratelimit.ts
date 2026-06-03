import type { Env } from "./types";

const LIMIT = 20; // scans per window
const WINDOW_SEC = 600; // 10 minutes

/**
 * Fixed-window per-IP limiter keyed on CF-Connecting-IP.
 * NEVER use the leftmost X-Forwarded-For here — a client can spoof it.
 * CF-Connecting-IP is set by Cloudflare and is trustworthy.
 */
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
  });
  return { ok: true, remaining: LIMIT - count - 1 };
}

const GLOBAL_WINDOW = 10; // seconds
const GLOBAL_CAP = 60; // new scans started per window before the site reports busy

/**
 * Soft site-wide capacity gate. Counts scans started across all users in a
 * short window; when too many start at once we ask later arrivals to wait,
 * which (with the GitHub-budget fallback) is what makes the busy screen appear.
 */
export async function checkGlobalCapacity(env: Env): Promise<boolean> {
  const bucket = Math.floor(Date.now() / 1000 / GLOBAL_WINDOW);
  const key = `gl:${bucket}`;
  const count = Number((await env.RATELIMIT.get(key)) ?? "0");
  if (count >= GLOBAL_CAP) return false;
  await env.RATELIMIT.put(key, String(count + 1), {
    expirationTtl: GLOBAL_WINDOW * 2,
  });
  return true;
}
