import type { SecretCandidate, ValidatableType } from "./secrets";

export type SecretStatus = "live" | "dead" | "unknown";

const TIMEOUT = 7000;

async function validateOne(
  type: ValidatableType,
  value: string,
): Promise<SecretStatus> {
  try {
    if (type === "github") {
      const r = await fetch("https://api.github.com/user", {
        headers: { Authorization: `Bearer ${value}`, "User-Agent": "frisk" },
        signal: AbortSignal.timeout(TIMEOUT),
      });
      if (r.status === 200) return "live";
      if (r.status === 401) return "dead";
      return "unknown";
    }
    if (type === "slack") {
      const r = await fetch("https://slack.com/api/auth.test", {
        method: "POST",
        headers: { Authorization: `Bearer ${value}` },
        signal: AbortSignal.timeout(TIMEOUT),
      });
      if (!r.ok) return "unknown";
      const j = (await r.json()) as { ok?: boolean };
      return j.ok ? "live" : "dead";
    }
    if (type === "stripe") {
      const r = await fetch("https://api.stripe.com/v1/account", {
        headers: { Authorization: `Bearer ${value}` },
        signal: AbortSignal.timeout(TIMEOUT),
      });
      if (r.status === 200) return "live";
      if (r.status === 401) return "dead";
      return "unknown";
    }
    if (type === "npm") {
      const r = await fetch("https://registry.npmjs.org/-/whoami", {
        headers: { Authorization: `Bearer ${value}` },
        signal: AbortSignal.timeout(TIMEOUT),
      });
      if (r.status === 200) return "live";
      if (r.status === 401) return "dead";
      return "unknown";
    }
  } catch {
    return "unknown";
  }
  return "unknown";
}

export async function validateSecrets(
  candidates: SecretCandidate[],
): Promise<Map<string, SecretStatus>> {
  const byValue = new Map<string, SecretCandidate>();
  for (const c of candidates) byValue.set(`${c.type}:${c.value}`, c);
  const unique = [...byValue.values()].slice(0, 10);

  const result = new Map<string, SecretStatus>();
  await Promise.all(
    unique.map(async (c) => {
      const status = await validateOne(c.type, c.value);
      if (status !== "unknown")
        result.set(`${c.file}:${c.line}`, status);
    }),
  );
  return result;
}
