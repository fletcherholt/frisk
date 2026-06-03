# frisk

**Frisk it before you clone it.** Static threat scan for any **public**
GitHub repo — swap `github.com/owner/repo` → `friskit.dev/owner/repo` and get a
security report without cloning.

Runs entirely on a Cloudflare Worker, in-memory at the edge. **Code is never stored.**

## What it checks

| Layer | How |
|---|---|
| 🔑 Leaked secrets | regex + Shannon entropy (AWS, GitHub, Stripe, Slack, private keys, JWTs) |
| ⚠️ Suspicious code | obfuscated eval, base64/shellcode blobs, `curl \| sh`, credential/wallet stealers, npm install hooks |
| 📦 Vulnerable deps | npm / PyPI / Go / Cargo manifests → [OSV.dev](https://osv.dev) |
| 🦠 Malicious binaries | committed executables hashed (SHA-256) → VirusTotal (hash-only, no upload) |

The wedge vs ScanRepo / CheckMyGitHub: **VirusTotal binary hashing**, **no login**, **open source**.

## Endpoints

- `/` — landing + scan box
- `/:owner/:repo` — HTML report
- `/api/scan/:owner/:repo` — JSON report

## Setup

```sh
npm install

# create KV namespaces, paste the ids into wrangler.toml
wrangler kv namespace create SCAN_CACHE
wrangler kv namespace create VT_CACHE
wrangler kv namespace create RATELIMIT

# secrets
wrangler secret put GITHUB_TOKEN   # public_repo scope — raises GitHub API 60 -> 5000/hr
wrangler secret put VT_API_KEY     # free VirusTotal API key (binary layer; optional)

npm run dev      # local
npm run deploy   # ship
```

For local dev, put secrets in `.dev.vars`:

```
GITHUB_TOKEN=ghp_xxx
VT_API_KEY=xxx
```

## Test

```sh
npm test         # unit tests for the secrets/patterns/score logic
```

End-to-end smoke (after `wrangler dev`): hit
`http://localhost:8787/rubenmarcus/malicious-repositories` — a known-bad corpus —
and expect secret + pattern findings. A small clean lib should report low/clean.

## Limits

- Public repos only; capped at 2000 files / 50 MB decompressed.
- VirusTotal free tier: 4 lookups/min, 500/day — binaries are capped at 10/scan and cached by hash.
- Per-IP rate limit: 20 scans / 10 min.
- Findings are heuristic — verify before trusting.
