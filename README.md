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

Or paste a repo at [friskit.dev](https://friskit.dev). You get a report in about a second. Your code is never stored. Detected secrets are checked against their provider to confirm whether they are live, and committed binaries are hashed for VirusTotal.

## What it checks

- **Secrets** committed to the repo: API keys, tokens, private keys.
- **Malicious code**: obfuscated eval, shellcode blobs, curl piped to shell, credential and wallet stealers.
- **Vulnerable dependencies** via [OSV](https://osv.dev): npm, PyPI, Go, Cargo.
- **Bad binaries**: executables hashed and checked on [VirusTotal](https://www.virustotal.com).

## Reading the results

frisk is a first pass. Findings are heuristic, so read them and check before you act on them.

One thing that surprises people: **security tools come back critical when you scan them, including frisk itself.** A scanner's own source and tests are full of the exact things it hunts for, obfuscated eval, fake API keys, malware keywords like MetaMask or wallet.dat, because those are the detection rules and the test fixtures. So pointing frisk at frisk reports critical. The rules are matching the rules, and frisk is fine. The same happens with any antivirus, linter or scanner.

Every finding is a flag to investigate. Open the file, look at the line, and decide for yourself. Use frisk to find what is worth a closer look, then actually look.

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
