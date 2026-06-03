<div align="center">

<img src="assets/favicon-source.png" width="96" alt="frisk">

# frisk

**frisk it before you clone it.**

Scan any public GitHub repo for threats. No clone, no login.

[![live](https://img.shields.io/badge/live-friskit.dev-cba6f7?style=flat-square)](https://friskit.dev)
[![licence](https://img.shields.io/github/license/fletcherholt/frisk?style=flat-square&color=a6e3a1)](LICENSE)

</div>

## Use it

Swap the domain on any GitHub repo:

```
github.com/owner/repo   →   friskit.dev/owner/repo
```

Or paste a repo at [friskit.dev](https://friskit.dev). You get a report in about a second. Your code is never stored.

## What it checks

- **Secrets** committed to the repo: API keys, tokens, private keys.
- **Malicious code**: obfuscated eval, shellcode blobs, curl piped to shell, credential and wallet stealers.
- **Vulnerable dependencies** via [OSV](https://osv.dev): npm, PyPI, Go, Cargo.
- **Bad binaries**: executables hashed and checked on [VirusTotal](https://www.virustotal.com).

## Run your own

<details>
<summary>Self host on Cloudflare Workers</summary>

```sh
npm install

wrangler kv namespace create SCAN_CACHE   # paste each id into wrangler.toml
wrangler kv namespace create VT_CACHE
wrangler kv namespace create RATELIMIT

wrangler secret put GITHUB_TOKEN          # public repo read
wrangler secret put VT_API_KEY            # free VirusTotal key

npm run deploy
```

`npm run dev` runs it locally, `npm test` runs the tests.

</details>

## Licence

MIT, by [Fletcher Holt](https://github.com/fletcherholt).
