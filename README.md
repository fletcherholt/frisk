<div align="center">

<img src="assets/favicon-source.png" width="104" alt="frisk logo">

# frisk

**frisk it before you clone it.**

Scan any public GitHub repo for threats without ever cloning it. Just swap the domain.

<p>
<code>github.com/<b>owner/repo</b></code> &nbsp;→&nbsp; <code>friskit.dev/<b>owner/repo</b></code>
</p>

[![live](https://img.shields.io/badge/live-friskit.dev-cba6f7?style=flat-square)](https://friskit.dev)
[![Cloudflare Workers](https://img.shields.io/badge/runs%20on-Cloudflare%20Workers-f38020?style=flat-square&logo=cloudflare&logoColor=white)](https://workers.cloudflare.com)
[![TypeScript](https://img.shields.io/badge/TypeScript-89b4fa?style=flat-square&logo=typescript&logoColor=white)](#)
[![licence](https://img.shields.io/github/license/fletcherholt/frisk?style=flat-square&color=a6e3a1)](LICENSE)

</div>

---

## What it finds

| Layer | What it catches |
| :-- | :-- |
| **Leaked secrets** | API keys, tokens, private keys and high entropy credentials committed to the repo. |
| **Malicious code** | Obfuscated eval, base64 and shellcode blobs, curl piped to shell, credential and wallet stealers, npm install hooks. |
| **Vulnerable dependencies** | npm, PyPI, Go and Cargo manifests checked against the [OSV](https://osv.dev) advisory database. |
| **Bad binaries** | Committed executables hashed (SHA&#8209;256) and looked up on [VirusTotal](https://www.virustotal.com). No upload, no download to you. |

Everything is scored into a single verdict, from **looks clean** to **critical risk**.

## How it works

1. You open `friskit.dev/owner/repo`, or swap the domain on any GitHub URL.
2. A Cloudflare Worker fetches the repo tarball from GitHub and unpacks it in memory at the edge.
3. Four scanners sweep the files. Binaries are hashed and checked against VirusTotal, dependencies against OSV.
4. You get a clean report in under a second on cached repos.

**Your code is never stored.** It is fetched, scanned in memory, and discarded.

## Why it exists

Two tools already scan repos for malware, both closed source and one of them gated behind a login. frisk adds the parts they miss: VirusTotal hashing of committed binaries, no login, and an open codebase you can actually read before you trust it.

## Self host

```sh
npm install

# create the KV namespaces, paste the ids into wrangler.toml
wrangler kv namespace create SCAN_CACHE
wrangler kv namespace create VT_CACHE
wrangler kv namespace create RATELIMIT

# secrets (stored on Cloudflare, never in the repo)
wrangler secret put GITHUB_TOKEN   # public repo read, lifts GitHub API to 5000/hr
wrangler secret put VT_API_KEY     # free VirusTotal key, powers the binary layer

npm run deploy
```

For local development, drop the same two values into `.dev.vars` (gitignored) and run `npm run dev`.

## Develop

```sh
npm test        # unit tests for the secrets, patterns and scoring logic
npm run dev     # local worker on http://localhost:8787
```

Try it against a known bad corpus: `localhost:8787/rubenmarcus/malicious-repositories`.

## Limits

* Public repos only, capped at 2000 files and 50 MB unpacked.
* VirusTotal free tier allows 500 lookups a day, so binaries are capped at 10 per scan and cached by hash.
* Twenty scans per IP every ten minutes.
* Findings are heuristic. Read the report, do not trust it blindly.

## Built by

[Fletcher Holt](https://github.com/fletcherholt) · live at [friskit.dev](https://friskit.dev)

## Licence

[MIT](LICENSE)
