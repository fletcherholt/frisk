import type { Finding, Report, Severity } from "./types";
import { escapeHtml } from "./util";
import { FAVICON } from "./favicon";
import { CUR_NORMAL, CUR_LINK, CUR_TEXT } from "./cursors";

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

// Catppuccin Mocha accents
const SEV_COLOR: Record<Severity, string> = {
  critical: "#f38ba8", // red
  high: "#fab387", // peach
  medium: "#f9e2af", // yellow
  low: "#89b4fa", // blue
  info: "#6c7086", // overlay
};

const LEVEL_LABEL: Record<Report["score"]["level"], string> = {
  critical: "CRITICAL RISK",
  high: "HIGH RISK",
  medium: "MEDIUM RISK",
  low: "LOW RISK",
  clean: "LOOKS CLEAN",
};

const LEVEL_COLOR: Record<Report["score"]["level"], string> = {
  critical: "#f38ba8",
  high: "#fab387",
  medium: "#f9e2af",
  low: "#89b4fa",
  clean: "#a6e3a1", // green
};

const CSS = `
:root{
  --base:#1e1e2e;--mantle:#181825;--crust:#11111b;
  --surface0:#313244;--surface1:#45475a;
  --text:#cdd6f4;--subtext0:#a6adc8;--overlay:#6c7086;
  --blue:#89b4fa;--lavender:#b4befe;--green:#a6e3a1;--mauve:#cba6f7;
}
*{box-sizing:border-box}
html,body{margin:0;background:var(--base);color:var(--text)}
body{font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","Noto Sans",Helvetica,Arial,sans-serif;cursor:url("${CUR_NORMAL}"),auto}
a,button,summary{cursor:url("${CUR_LINK}"),pointer}
input,textarea{cursor:url("${CUR_TEXT}"),text}
code,.snip,.mono{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}

.page{min-height:100vh;display:flex;flex-direction:column}
.wrap{max-width:720px;width:100%;margin:0 auto;padding:56px 20px 24px;flex:1}
.bottom{max-width:720px;width:100%;margin:0 auto;padding:0 20px 36px}
/* landing: centre the scanner, drop the toggle to the bottom of the main area */
.page-landing .wrap{display:flex;flex-direction:column;padding-top:24px}
.page-landing .hero{flex:1;display:flex;flex-direction:column;justify-content:center}
.page-landing .explain{margin-top:0;padding-top:8px}

/* entrance animation: logo blurs/scales in, the rest rises in just after */
@keyframes logoIn{0%{opacity:0;transform:translateY(18px) scale(.94);filter:blur(10px)}100%{opacity:1;transform:none;filter:none}}
@keyframes riseIn{0%{opacity:0;transform:translateY(12px)}100%{opacity:1;transform:none}}
.page-landing .logobar{animation:logoIn .85s cubic-bezier(.2,.7,.2,1) both}
.page-landing .tag{animation:riseIn .7s cubic-bezier(.2,.7,.2,1) .18s both}
.page-landing .box{animation:riseIn .7s cubic-bezier(.2,.7,.2,1) .3s both}
.page-landing .hero .sub{animation:riseIn .7s cubic-bezier(.2,.7,.2,1) .4s both}
@media (prefers-reduced-motion:reduce){
  .page-landing .logo,.page-landing .tag,.page-landing .box,.page-landing .hero .sub{animation:none}
}
.logobar{text-align:center}
.logo{display:inline-block;font-size:46px;font-weight:800;letter-spacing:-1px;color:var(--text);text-decoration:none;transition:color .2s ease,transform .2s ease}
.logo:hover{color:var(--mauve);transform:translateY(-2px)}
.logo-hint{display:block;margin-top:8px;font-size:13px;font-weight:600;color:var(--blue);opacity:0;transform:translateY(-4px);transition:opacity .25s ease,transform .25s ease;pointer-events:none}
.logobar:hover .logo-hint{opacity:1;transform:none}
.logo b{color:var(--mauve)}
.tag{color:var(--subtext0);margin-top:6px;font-size:15px;text-align:center}

h1{font-size:20px;margin:26px 0 4px;font-weight:600;word-break:break-all}
.sub{color:var(--overlay);font-size:13px;margin-bottom:20px}
code{background:var(--mantle);padding:2px 6px;border-radius:6px;color:var(--lavender);font-size:13px}

.box{margin-top:24px;display:flex;gap:8px}
.box.mini{max-width:440px;margin:16px auto 6px}
input{flex:1;background:var(--mantle);border:1px solid var(--surface0);color:var(--text);padding:11px 13px;border-radius:8px;font:inherit}
input:focus{outline:none;border-color:var(--blue)}
button{background:var(--mauve);color:var(--crust);border:0;padding:11px 18px;border-radius:8px;font:inherit;font-weight:700;cursor:pointer}
button:hover{filter:brightness(1.08)}

.explain{margin-top:56px;text-align:center}
.explain summary{display:inline-block;cursor:pointer;list-style:none;background:var(--surface0);color:var(--text);padding:9px 18px;border-radius:8px;font-weight:600;font-size:14px;user-select:none}
.explain summary::-webkit-details-marker{display:none}
.explain summary:hover{background:var(--surface1)}
.explain[open] summary{margin-bottom:14px}
.checks{text-align:left;border-top:1px solid var(--surface0)}
.row{display:flex;gap:13px;padding:12px 2px;border-bottom:1px solid var(--surface0)}
.row .dot{width:9px;height:9px;border-radius:50%;margin-top:7px;flex:none}
.row b{color:var(--text);font-weight:600}
.row span{color:var(--subtext0);font-size:14px}

.badge{display:inline-block;padding:12px 20px;border-radius:10px;font-weight:800;font-size:18px;letter-spacing:.5px;color:var(--crust)}
.counts{margin:16px 0 8px;display:flex;gap:8px;flex-wrap:wrap}
.pill{padding:4px 11px;border-radius:20px;font-size:12px;font-weight:700;color:var(--crust)}
.note{background:var(--mantle);border-left:3px solid var(--mauve);padding:8px 12px;margin:6px 0;border-radius:6px;font-size:13px;color:var(--subtext0)}

.cat{margin-top:28px;font-size:12px;text-transform:uppercase;letter-spacing:1.2px;color:var(--overlay)}
.f{background:var(--mantle);border:1px solid var(--surface0);border-radius:10px;padding:13px 15px;margin:10px 0}
.f .top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.sev{font-size:11px;font-weight:700;padding:2px 8px;border-radius:5px;color:var(--crust)}
.ftitle{font-weight:600}
.floc{color:var(--overlay);font-size:12px}
.fdetail{color:var(--subtext0);font-size:13px;margin-top:6px}
.snip{background:var(--crust);border:1px solid var(--surface0);border-radius:7px;padding:8px 11px;margin-top:8px;font-size:12px;color:var(--green);overflow-x:auto;white-space:pre}

.clean{text-align:center;padding:40px 0;color:var(--green);font-size:17px}

/* scanning interstitial: two counter-rotating gradient rings round the logo */
.scanner{position:relative;width:132px;height:132px;margin:0 auto;display:flex;align-items:center;justify-content:center}
.ring{position:absolute;inset:0;border-radius:50%;
  background:conic-gradient(from 0deg,transparent 0 55%,var(--blue) 82%,var(--mauve) 100%);
  -webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 5px),#000 calc(100% - 5px));
  mask:radial-gradient(farthest-side,transparent calc(100% - 5px),#000 calc(100% - 5px));
  animation:spin 1s linear infinite}
.ring2{inset:20px;
  background:conic-gradient(from 180deg,transparent 0 55%,var(--mauve) 82%,var(--green) 100%);
  animation:spin 1.5s linear infinite reverse}
@keyframes spin{to{transform:rotate(1turn)}}
.scan-logo{position:relative;z-index:1;font-size:22px;font-weight:800;letter-spacing:-.5px;color:var(--text);animation:pulse 1.2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:.8;transform:scale(1)}50%{opacity:1;transform:scale(1.07)}}
.scan-label{margin-top:26px;text-align:center;color:var(--subtext0);font-size:15px}
.scan-label b{color:var(--text);font-weight:600}
.dots::after{content:"";animation:dots 1.4s steps(1,end) infinite}
@keyframes dots{0%{content:""}25%{content:"."}50%{content:".."}75%{content:"..."}}
.foot{color:var(--overlay);font-size:12px;text-align:center}
.powered{margin-top:8px;color:var(--overlay);font-size:12px;text-align:center}
.copy{margin-top:10px;color:var(--surface1);font-size:12px;text-align:center}
`;

function shell(inner: string, landing = false, title = "friskit"): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<link rel="icon" href="${FAVICON}">
<style>${CSS}</style></head>
<body><div class="page${landing ? " page-landing" : ""}">
<main class="wrap">${inner}</main>
<footer class="bottom">
<div class="foot">Code is never stored. Fetched and scanned in memory at the edge. Results are heuristic. · <a href="/">scan another repo</a></div>
<div class="powered">binary checks powered by <a href="https://www.virustotal.com">VirusTotal</a> · dependency data from <a href="https://osv.dev">OSV</a></div>
<div class="copy">© 2026 Fletcher Holt · <a href="https://github.com/fletcherholt">github.com/fletcherholt</a></div>
</footer>
</div></body></html>`;
}

function findingHtml(f: Finding): string {
  const loc = f.line ? `${escapeHtml(f.file)}:${f.line}` : escapeHtml(f.file);
  return `<div class="f">
  <div class="top">
    <span class="sev" style="background:${SEV_COLOR[f.severity]}">${f.severity.toUpperCase()}</span>
    <span class="ftitle">${escapeHtml(f.title)}</span>
    <span class="floc">${loc}</span>
  </div>
  <div class="fdetail">${escapeHtml(f.detail)}</div>
  ${f.snippet ? `<div class="snip">${escapeHtml(f.snippet)}</div>` : ""}
</div>`;
}

export function renderReport(r: Report): string {
  const sorted = [...r.findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity),
  );

  const catNames: Record<string, string> = {
    secret: "Leaked secrets",
    pattern: "Suspicious code",
    dependency: "Vulnerable dependencies",
    binary: "Binaries (VirusTotal)",
  };

  let body = "";
  for (const cat of ["secret", "pattern", "dependency", "binary"]) {
    const items = sorted.filter((f) => f.category === cat);
    if (items.length === 0) continue;
    body += `<div class="cat">${catNames[cat]} (${items.length})</div>`;
    body += items.map(findingHtml).join("");
  }

  const counts = SEV_ORDER.filter((s) => r.score.counts[s] > 0)
    .map(
      (s) =>
        `<span class="pill" style="background:${SEV_COLOR[s]}">${r.score.counts[s]} ${s}</span>`,
    )
    .join("");

  const notes = r.notes.map((n) => `<div class="note">${escapeHtml(n)}</div>`).join("");

  const inner = `
<div class="logobar"><a class="logo" href="https://github.com/fletcherholt/frisk">frisk</a><span class="logo-hint">check out the repo ↗</span></div>
<form class="box mini" onsubmit="go(event)">
  <input id="u" placeholder="scan another repo: owner/repo" autocomplete="off" autocapitalize="off" spellcheck="false">
  <button type="submit">frisk</button>
</form>
<h1>${escapeHtml(r.owner)}/${escapeHtml(r.repo)}</h1>
<div class="sub">commit ${r.sha.slice(0, 10)} · ${r.fileCount} files scanned${r.truncated ? " (truncated)" : ""} · <a href="https://github.com/${escapeHtml(r.owner)}/${escapeHtml(r.repo)}">GitHub</a>${r.cached ? " · cached" : ""}</div>
<div class="badge" style="background:${LEVEL_COLOR[r.score.level]}">${LEVEL_LABEL[r.score.level]}</div>
<div class="counts">${counts || '<span class="pill" style="background:#a6e3a1">no findings</span>'}</div>
${notes}
${r.findings.length === 0 ? '<div class="clean">Nothing flagged. No secrets, suspicious code, vulnerable deps, or bad binaries.</div>' : body}
<script>
function go(e){e.preventDefault();var v=document.getElementById('u').value.trim();
var m=v.match(/(?:github\\.com\\/)?([^\\/\\s]+)\\/([^\\/\\s#?]+)/);
if(m)location.href='/'+m[1]+'/'+m[2].replace(/\\.git$/,'');}
</script>
`;
  return shell(inner, false, `✓ ${r.owner}/${r.repo}`);
}

export function landingPage(): string {
  const inner = `
<div class="hero">
<div class="logobar"><a class="logo" href="https://github.com/fletcherholt/frisk">frisk</a><span class="logo-hint">check out the repo ↗</span></div>
<div class="tag">frisk it before you clone it.</div>
<form class="box" onsubmit="go(event)">
  <input id="u" placeholder="github.com/owner/repo" autofocus autocapitalize="off" autocomplete="off" spellcheck="false">
  <button type="submit">frisk</button>
</form>
<div class="sub" style="margin-top:12px">Or just swap <code>github.com</code> → <code>friskit.dev</code> in any repo URL.</div>
</div>

<details class="explain">
  <summary>What does it do?</summary>
  <div class="checks">
    <div class="row"><span class="dot" style="background:#f38ba8"></span><div><b>Leaked secrets</b><br><span>API keys, tokens, private keys committed to the repo.</span></div></div>
    <div class="row"><span class="dot" style="background:#fab387"></span><div><b>Malicious code</b><br><span>Obfuscated eval, shellcode blobs, curl-pipe-sh, credential and wallet stealers.</span></div></div>
    <div class="row"><span class="dot" style="background:#89b4fa"></span><div><b>Vulnerable deps</b><br><span>npm, PyPI, Go and Cargo checked against the OSV advisory database.</span></div></div>
    <div class="row"><span class="dot" style="background:#cba6f7"></span><div><b>Bad binaries</b><br><span>Committed executables hashed and looked up on VirusTotal.</span></div></div>
  </div>
</details>
<script>
function go(e){e.preventDefault();var v=document.getElementById('u').value.trim();
var m=v.match(/(?:github\\.com\\/)?([^\\/\\s]+)\\/([^\\/\\s#?]+)/);
if(m)location.href='/'+m[1]+'/'+m[2].replace(/\\.git$/,'');}
</script>`;
  return shell(inner, true);
}

export function scanningPage(owner: string, repo: string): string {
  const path = JSON.stringify(`/${owner}/${repo}`);
  const inner = `
<div class="hero">
  <div class="scanner">
    <span class="ring"></span>
    <span class="ring ring2"></span>
    <span class="scan-logo">frisk</span>
  </div>
  <div class="scan-label">scanning <b>${escapeHtml(owner)}/${escapeHtml(repo)}</b><span class="dots"></span></div>
</div>
<script>
(function(){
  var p=${path};
  var seq=['','.','..','...','..','.'];var i=0;   // dots grow then shrink
  setInterval(function(){document.title='scanning'+seq[i];i=(i+1)%seq.length;},350);
  var delay=100+Math.random()*3400;            // hold 0.1s to 3.5s
  var t0=Date.now();
  function go(){var w=Math.max(0,delay-(Date.now()-t0));setTimeout(function(){location.replace(p+'?view=1');},w);}
  fetch('/api/scan'+p).then(go,go);
})();
</script>`;
  return shell(inner, true, "scanning");
}

export function errorPage(owner: string, repo: string, message: string): string {
  const inner = `
<div class="logobar"><a class="logo" href="https://github.com/fletcherholt/frisk">frisk</a><span class="logo-hint">check out the repo ↗</span></div>
<h1>${escapeHtml(owner)}/${escapeHtml(repo)}</h1>
<div class="f"><div class="ftitle" style="color:#fab387">Could not scan</div>
<div class="fdetail">${escapeHtml(message)}</div></div>`;
  return shell(inner);
}
