import type { Finding, Report, Severity } from "./types";
import { escapeHtml } from "./util";
import { FAVICON } from "./favicon";
import { CUR_NORMAL, CUR_LINK, CUR_TEXT } from "./cursors";

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEV_COLOR: Record<Severity, string> = {
  critical: "#f38ba8",
  high: "#fab387",
  medium: "#f9e2af",
  low: "#89b4fa",
  info: "#6c7086",
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
  clean: "#a6e3a1",
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
.page-landing .wrap{display:flex;flex-direction:column;padding-top:24px}
.page-landing .hero{flex:1;display:flex;flex-direction:column;justify-content:center}
.page-landing .explain{margin-top:0;padding-top:8px}

@keyframes logoIn{0%{opacity:0;transform:translateY(18px) scale(.94);filter:blur(10px)}100%{opacity:1;transform:none;filter:none}}
@keyframes riseIn{0%{opacity:0;transform:translateY(14px) scale(.985);filter:blur(6px)}100%{opacity:1;transform:none;filter:none}}
.page-landing .logobar{animation:logoIn .85s cubic-bezier(.2,.7,.2,1) both}
.page-landing .tag{animation:riseIn .7s cubic-bezier(.2,.7,.2,1) .18s both}
.page-landing .box{animation:riseIn .7s cubic-bezier(.2,.7,.2,1) .3s both}
.page-landing .hero .sub{animation:riseIn .7s cubic-bezier(.2,.7,.2,1) .4s both}
.page-landing .more{animation:riseIn .7s cubic-bezier(.2,.7,.2,1) .5s both}
.page-landing .bottom{animation:riseIn .7s cubic-bezier(.2,.7,.2,1) .62s both}
@media (prefers-reduced-motion:reduce){
  .page-landing .logo,.page-landing .tag,.page-landing .box,.page-landing .hero .sub,.page-landing .more,.page-landing .bottom{animation:none}
}
.logobar{text-align:center}
.logo{display:inline-block;font-size:46px;font-weight:800;letter-spacing:-1px;color:var(--text);text-decoration:none;transition:color .2s ease,transform .2s ease}
.logo:hover{color:var(--mauve);transform:translateY(-2px)}
.logo-hint{display:block;margin-top:8px;font-size:13px;font-weight:600;color:var(--blue);opacity:0;transform:translateY(-4px);transition:opacity .25s ease,transform .25s ease;pointer-events:none}
.logobar:hover .logo-hint{opacity:1;transform:none}
.logo b{color:var(--mauve)}
.tag{color:var(--subtext0);margin:6px 0 0;font-size:15px;font-weight:600;text-align:center}

h1{font-size:20px;margin:26px 0 4px;font-weight:600;word-break:break-all}
.sub{color:var(--overlay);font-size:13px;margin-bottom:20px}
code{background:var(--mantle);padding:2px 6px;border-radius:6px;color:var(--lavender);font-size:13px}

.box{margin-top:24px;display:flex;gap:8px}
.back{display:inline-block;color:var(--subtext0);font-size:14px;font-weight:600;text-decoration:none;margin-bottom:8px;transition:color .15s ease}
.back:hover{color:var(--text);text-decoration:none}
input{flex:1;background:var(--mantle);border:1px solid var(--surface0);color:var(--text);padding:11px 13px;border-radius:8px;font:inherit}
input:focus{outline:none;border-color:var(--blue)}
button{background:var(--mauve);color:var(--crust);border:0;padding:11px 18px;border-radius:8px;font:inherit;font-weight:700;cursor:pointer}
button:hover{filter:brightness(1.08)}

.more{display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-top:34px}
.chip{background:var(--surface0);color:var(--text);border:0;padding:8px 16px;border-radius:9px;font:inherit;font-weight:600;font-size:13px;cursor:pointer;transition:background .15s ease,transform .15s ease}
.chip:hover{background:var(--surface1);transform:translateY(-1px)}

.modal{position:fixed;inset:0;z-index:60;display:none;align-items:center;justify-content:center;padding:20px;background:rgba(17,17,27,.62)}
.modal.open{display:flex;animation:overlayIn .18s ease both}
.modal-card{background:var(--base);border:1px solid var(--surface0);border-radius:16px;width:100%;max-width:520px;max-height:82vh;overflow:auto;box-shadow:0 24px 60px rgba(0,0,0,.5);animation:cardIn .26s cubic-bezier(.2,.8,.2,1) both}
.modal-head{position:sticky;top:0;background:var(--base);display:flex;align-items:center;justify-content:space-between;gap:12px;padding:16px 20px;border-bottom:1px solid var(--surface0);font-weight:700;font-size:15px;color:var(--text)}
.modal-x{background:none;border:0;color:var(--overlay);font-size:15px;line-height:1;cursor:pointer;padding:5px 8px;border-radius:7px}
.modal-x:hover{color:var(--text);background:var(--surface0)}
.modal-body{padding:6px 20px 18px;text-align:left}
@keyframes overlayIn{from{opacity:0}to{opacity:1}}
@keyframes cardIn{from{opacity:0;transform:translateY(12px) scale(.97)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion:reduce){.modal.open,.modal-card{animation:none}}
body.modal-open{overflow:hidden}
.checks{text-align:left}
.row{display:flex;gap:13px;padding:12px 2px;border-bottom:1px solid var(--surface0)}
.row:last-child,.qa:last-child{border-bottom:0}
.row .dot{width:9px;height:9px;border-radius:50%;margin-top:7px;flex:none}
.row b{color:var(--text);font-weight:600}
.row span{color:var(--subtext0);font-size:14px}
.qa{padding:12px 2px;border-bottom:1px solid var(--surface0)}
.qa .q{color:var(--text);font-weight:600;font-size:14px}
.qa .a{color:var(--subtext0);font-size:14px;margin-top:5px;line-height:1.55}

.badge{display:inline-block;padding:12px 20px;border-radius:10px;font-weight:800;font-size:18px;letter-spacing:.5px;color:var(--crust)}
.counts{margin:16px 0 8px;display:flex;gap:8px;flex-wrap:wrap}
.pill{padding:4px 11px;border-radius:20px;font-size:12px;font-weight:700;color:var(--crust)}
.note{background:var(--mantle);border-left:3px solid var(--mauve);padding:8px 12px;margin:6px 0;border-radius:6px;font-size:13px;color:var(--subtext0)}

.cat{margin-top:28px;font-size:12px;text-transform:uppercase;letter-spacing:1.2px;color:var(--overlay)}
.f{background:var(--mantle);border:1px solid var(--surface0);border-radius:10px;padding:13px 15px;margin:10px 0}
.f .top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.sev{font-size:11px;font-weight:700;padding:2px 8px;border-radius:5px;color:var(--crust)}
.ftitle{font-weight:600;overflow-wrap:anywhere}
.floc{color:var(--overlay);font-size:12px;overflow-wrap:anywhere}
.fdetail{color:var(--subtext0);font-size:13px;margin-top:6px}
.snip{background:var(--crust);border:1px solid var(--surface0);border-radius:7px;padding:8px 11px;margin-top:8px;font-size:12px;color:var(--green);overflow-x:auto;white-space:pre-wrap;word-break:break-all}

.clean{text-align:center;padding:40px 0;color:var(--green);font-size:17px}

.loader{display:block;width:64px;height:64px;margin:0 auto;position:relative}
.loader:after{content:"";position:absolute;inset:0;margin:auto;width:34px;height:34px;border-radius:50%;background:var(--text)}
.loader:before{content:"";position:absolute;left:50%;top:0;margin:-7px;width:14px;height:14px;border-radius:50%;background:var(--text);transform-origin:7px 39px;animation:spin 1.1s infinite linear}
@keyframes spin{100%{transform:rotate(360deg)}}
.scan-label{margin-top:30px;text-align:center;color:var(--subtext0);font-size:15px;line-height:1.7}
.scan-label b{color:var(--text);font-weight:600}
.dim{color:var(--overlay);font-size:13px}
.dots::after{content:"";animation:dots 1.4s steps(1,end) infinite}
@keyframes dots{0%{content:""}25%{content:"."}50%{content:".."}75%{content:"..."}}
.foot{color:var(--subtext0);font-size:12px;text-align:center}
.powered{margin-top:8px;color:var(--overlay);font-size:12px;text-align:center}
.copy{margin-top:10px;color:var(--overlay);font-size:12px;text-align:center}
.sub{overflow-wrap:anywhere}
.copy .kofi{color:#f5c2e7}
.copy .kofi:hover{color:#f5c2e7;text-decoration:underline}
`;

const SITE = "https://friskit.dev";
const SEO_TITLE =
  "frisk — scan any GitHub repo for secrets, malware & vulnerabilities";
const SEO_DESC =
  "Free, no-login security scanner for any public GitHub repository. Swap github.com for friskit.dev, or paste a repo, to check for leaked secrets, malware, malicious packages and vulnerable dependencies in seconds — no clone required.";
const JSON_LD = JSON.stringify({
  "@context": "https://schema.org",
  "@type": "WebApplication",
  name: "frisk",
  alternateName: "friskit",
  url: SITE,
  applicationCategory: "SecurityApplication",
  operatingSystem: "Any",
  browserRequirements: "Requires JavaScript",
  description: SEO_DESC,
  offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
  creator: {
    "@type": "Person",
    name: "Fletcher Holt",
    url: "https://github.com/fletcherholt",
  },
  sameAs: ["https://github.com/fletcherholt/frisk"],
  isAccessibleForFree: true,
  featureList: [
    "Leaked secret detection with live credential validation",
    "Malware and stealer pattern detection",
    "Malicious package detection via OSV",
    "Vulnerable dependency scanning",
    "Committed binary scanning via VirusTotal",
  ],
});

const FAQ: { q: string; a: string }[] = [
  {
    q: "Is it safe to clone a GitHub repo?",
    a: "Cloning is usually fine, but installing or running an unknown repo can execute its code on your machine through install scripts and build steps. frisk checks a repository for leaked secrets, malware, malicious packages and known vulnerabilities first, so you can decide before you clone or run it.",
  },
  {
    q: "How do I scan a GitHub repository for secrets or malware?",
    a: "Swap github.com for friskit.dev in any repository URL, or paste the repo on the home page. frisk reads the latest commit, scans it and returns a report in seconds, instantly if it has scanned that repo recently. There is no login and nothing to install.",
  },
  {
    q: "Is frisk free?",
    a: "Yes. frisk is completely free, needs no account, and the source is open on GitHub.",
  },
  {
    q: "Does frisk store my code?",
    a: "frisk does not retain your source. It caches the report so repeat scans are instant, and that report includes short snippets of the lines it flagged. To run its checks it sends a few things off the edge: detected GitHub, Slack, Stripe and npm tokens go to their own provider to test whether they are live, committed binary hashes go to VirusTotal, and dependency names go to OSV.",
  },
  {
    q: "What does frisk check for?",
    a: "Leaked secrets and API keys, obfuscated or malicious code, credential and wallet stealers, malicious and typosquatted packages, vulnerable dependencies, risky infrastructure configuration, and committed binaries flagged on VirusTotal.",
  },
  {
    q: "Why does scanning a security tool come back critical?",
    a: "A scanner's own source and tests contain the exact patterns it hunts for, so pointing frisk at a security tool, including frisk itself, can report critical. Open the flagged files and judge for yourself. Critical is reserved for high-confidence signals such as a verified-live secret, a known-malicious package, a flagged binary, or an unambiguous malware pattern; low-confidence heuristics are capped below it.",
  },
];

const FAQ_LD = JSON.stringify({
  "@context": "https://schema.org",
  "@type": "FAQPage",
  mainEntity: FAQ.map((f) => ({
    "@type": "Question",
    name: f.q,
    acceptedAnswer: { "@type": "Answer", text: f.a },
  })),
});

function seoHead(landing: boolean, canonical: string): string {
  if (!landing) return `<meta name="robots" content="noindex,follow">`;
  return `<meta name="description" content="${escapeHtml(SEO_DESC)}">
<link rel="canonical" href="${canonical}">
<meta name="robots" content="index,follow,max-image-preview:large">
<meta name="theme-color" content="#1e1e2e">
<meta property="og:locale" content="en_GB">
<meta property="og:type" content="website">
<meta property="og:site_name" content="frisk">
<meta property="og:title" content="${escapeHtml(SEO_TITLE)}">
<meta property="og:description" content="${escapeHtml(SEO_DESC)}">
<meta property="og:url" content="${canonical}">
<meta property="og:image" content="${SITE}/og.svg">
<meta property="og:image:type" content="image/svg+xml">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${escapeHtml(SEO_TITLE)}">
<meta name="twitter:description" content="${escapeHtml(SEO_DESC)}">
<meta name="twitter:image" content="${SITE}/og.svg">
<script type="application/ld+json">${JSON_LD.replace(/</g, "\\u003c")}</script>
<script type="application/ld+json">${FAQ_LD.replace(/</g, "\\u003c")}</script>`;
}

function shell(inner: string, landing = false, title = "friskit"): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(landing && title === "friskit" ? SEO_TITLE : title)}</title>
${seoHead(landing, `${SITE}/`)}
<link rel="icon" href="${FAVICON}">
<style>${CSS}</style></head>
<body><div class="page${landing ? " page-landing" : ""}">
<main class="wrap">${inner}</main>
<footer class="bottom">
<div class="foot">Source is not retained. Detected GitHub, Slack, Stripe and npm tokens are checked against their own provider to confirm whether they are live. Results are heuristic. · <a href="/">scan another repo</a></div>
<div class="powered">binary checks powered by <a href="https://www.virustotal.com">VirusTotal</a> · dependency data from <a href="https://osv.dev">OSV</a></div>
<div class="copy">© 2026 Fletcher Holt · <a href="https://github.com/fletcherholt">github.com/fletcherholt</a> · <a class="kofi" href="https://ko-fi.com/fletcherholt">support on Ko-fi</a></div>
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
    infrastructure: "Infrastructure",
    dependency: "Dependencies",
    binary: "Binaries (VirusTotal)",
    health: "Repo health",
  };

  let body = "";
  for (const cat of ["secret", "pattern", "infrastructure", "dependency", "binary", "health"]) {
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
<a class="back" href="/">← back</a>
<div class="logobar"><a class="logo" href="https://github.com/fletcherholt/frisk">frisk</a><span class="logo-hint">check out the repo ↗</span></div>
<h1>${escapeHtml(r.owner)}/${escapeHtml(r.repo)}</h1>
<div class="sub">commit ${r.sha.slice(0, 10)} · ${r.fileCount} files scanned${r.truncated ? " (truncated)" : ""}${r.license ? ` · ${escapeHtml(r.license)}` : ""} · <a href="https://github.com/${escapeHtml(r.owner)}/${escapeHtml(r.repo)}">GitHub</a>${r.components.length ? ` · <a href="/api/sbom/${escapeHtml(r.owner)}/${escapeHtml(r.repo)}">SBOM</a>` : ""}${r.cached ? " · cached" : ""}</div>
<div class="badge" style="background:${LEVEL_COLOR[r.score.level]}">${LEVEL_LABEL[r.score.level]}</div>
${counts ? `<div class="counts">${counts}</div>` : ""}
${notes}
${r.findings.length === 0 ? '<div class="clean">Nothing flagged. No secrets, suspicious code, vulnerable deps, or bad binaries.</div>' : body}
`;
  return shell(inner, false, `✓ ${r.owner}/${r.repo}`);
}

export function ogImage(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
<rect width="1200" height="630" fill="#1e1e2e"/>
<rect x="0" y="0" width="1200" height="8" fill="#cba6f7"/>
<text x="80" y="250" font-family="Helvetica,Arial,sans-serif" font-size="150" font-weight="800" fill="#cdd6f4">fr<tspan fill="#cba6f7">i</tspan>sk</text>
<text x="84" y="330" font-family="Helvetica,Arial,sans-serif" font-size="44" font-weight="600" fill="#a6adc8">frisk it before you clone it.</text>
<text x="84" y="430" font-family="Helvetica,Arial,sans-serif" font-size="34" fill="#6c7086">Free, no-login security scan for any public GitHub repo —</text>
<text x="84" y="478" font-family="Helvetica,Arial,sans-serif" font-size="34" fill="#6c7086">secrets, malware, malicious packages &amp; vulnerable deps.</text>
<text x="84" y="566" font-family="Menlo,monospace" font-size="30" fill="#89b4fa">github.com/owner/repo  →  friskit.dev/owner/repo</text>
</svg>`;
}

export function landingPage(notice?: string): string {
  const inner = `
<div class="hero">
<div class="logobar"><a class="logo" href="https://github.com/fletcherholt/frisk">frisk</a><span class="logo-hint">check out the repo ↗</span></div>
${notice ? `<div class="note" style="text-align:center;border-left-color:#fab387">${escapeHtml(notice)}</div>` : ""}
<h1 class="tag">frisk it before you clone it.</h1>
<form class="box" onsubmit="go(event)">
  <input id="u" placeholder="github.com/owner/repo" autofocus autocapitalize="off" autocomplete="off" spellcheck="false" aria-label="GitHub repository to scan">
  <button type="submit">frisk</button>
</form>
<div class="sub" style="margin-top:12px">Or just swap <code>github.com</code> → <code>friskit.dev</code> in any repo URL.</div>
<div class="more">
  <button type="button" class="chip" onclick="openModal('m-about')">What does it do?</button>
  <button type="button" class="chip" onclick="openModal('m-faq')">Common questions</button>
</div>
</div>

<div class="modal" id="m-about" onclick="if(event.target===this)closeModal()">
  <div class="modal-card" role="dialog" aria-modal="true" aria-label="What does it do?">
    <div class="modal-head">What does it do?<button type="button" class="modal-x" onclick="closeModal()" aria-label="Close">✕</button></div>
    <div class="modal-body"><div class="checks">
      <div class="row"><span class="dot" style="background:#f38ba8"></span><div><b>Leaked secrets</b><br><span>API keys, tokens and private keys. GitHub, Slack, Stripe and npm tokens are checked against their provider to see if they are still live.</span></div></div>
      <div class="row"><span class="dot" style="background:#fab387"></span><div><b>Malicious code</b><br><span>Obfuscated eval, shellcode blobs, curl-pipe-sh, credential and wallet stealers.</span></div></div>
      <div class="row"><span class="dot" style="background:#a6e3a1"></span><div><b>Supply chain</b><br><span>Confirmed-malicious and typosquatted packages, plus vulnerable deps via OSV (npm, PyPI, Go, Cargo).</span></div></div>
      <div class="row"><span class="dot" style="background:#cba6f7"></span><div><b>Bad binaries</b><br><span>Committed executables hashed and looked up on VirusTotal.</span></div></div>
      <div class="row"><span class="dot" style="background:#89b4fa"></span><div><b>Infrastructure</b><br><span>Dockerfile, compose, Terraform, Kubernetes and GitHub Actions misconfigurations.</span></div></div>
      <div class="row"><span class="dot" style="background:#94e2d5"></span><div><b>Repo health</b><br><span>OpenSSF Scorecard signals, plus a CycloneDX SBOM you can download.</span></div></div>
    </div></div>
  </div>
</div>

<div class="modal" id="m-faq" onclick="if(event.target===this)closeModal()">
  <div class="modal-card" role="dialog" aria-modal="true" aria-label="Common questions">
    <div class="modal-head">Common questions<button type="button" class="modal-x" onclick="closeModal()" aria-label="Close">✕</button></div>
    <div class="modal-body">${FAQ.map((f) => `<div class="qa"><div class="q">${escapeHtml(f.q)}</div><div class="a">${escapeHtml(f.a)}</div></div>`).join("")}</div>
  </div>
</div>
<script>
function go(e){e.preventDefault();var v=document.getElementById('u').value.trim();
var m=v.match(/(?:github\\.com\\/)?([^\\/\\s]+)\\/([^\\/\\s#?]+)/);
if(m)location.href='/'+m[1]+'/'+m[2].replace(/\\.git$/,'');}
function openModal(id){var m=document.getElementById(id);if(m){m.classList.add('open');document.body.classList.add('modal-open');}}
function closeModal(){var o=document.querySelectorAll('.modal.open');for(var i=0;i<o.length;i++)o[i].classList.remove('open');document.body.classList.remove('modal-open');}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeModal();});
</script>`;
  return shell(inner, true);
}

export function scanningPage(owner: string, repo: string): string {
  const path = JSON.stringify(`/${owner}/${repo}`);
  const label = `scanning <b>${escapeHtml(owner)}/${escapeHtml(repo)}</b><span class="dots"></span>`;
  const inner = `
<div class="hero">
  <span class="loader"></span>
  <div class="scan-label" id="lbl">${label}</div>
</div>
<script>
(function(){
  var p=${path};
  try{sessionStorage.removeItem('frisk_busy_tries');}catch(e){}
  var seq=['','.','..','...','..','.'];var i=0;
  var title='scanning';
  setInterval(function(){document.title=title+seq[i];i=(i+1)%seq.length;},350);
  var delay=250;
  var t0=Date.now(), tries=0;
  var lbl=document.getElementById('lbl');
  function done(){location.replace(p+'?view=1');}
  function go(){setTimeout(done,Math.max(0,delay-(Date.now()-t0)));}
  function waiting(){
    title='waiting';
    lbl.innerHTML='lots of people are scanning right now<br><span class="dim">holding your place · this starts automatically</span>';
  }
  function attempt(){
    fetch('/api/scan'+p).then(function(r){
      if(r.status===503){
        if(++tries>30){lbl.innerHTML='still very busy<br><span class="dim">please try again in a few minutes</span><br><a href="/">scan another repo</a>';title='busy';return;}
        waiting();
        setTimeout(attempt, 4000+Math.random()*3000);
        return;
      }
      if(!r.ok){done();return;}
      r.json().then(function(j){ (j&&j.cached) ? done() : go(); }, go);
    }, function(){ if(++tries>30){done();return;} setTimeout(attempt, 3000); });
  }
  attempt();
})();
</script>`;
  return shell(inner, true, "scanning");
}

export function busyPage(owner: string, repo: string): string {
  const inner = `
<div class="hero">
  <span class="loader"></span>
  <div class="scan-label" id="lbl">frisk is busy right now<br><span class="dim">lots of people are scanning ${escapeHtml(owner)}/${escapeHtml(repo)} and others. this page retries automatically.</span></div>
</div>
<script>
(function(){
  var n=1;
  try{n=(+sessionStorage.getItem('frisk_busy_tries')||0)+1;sessionStorage.setItem('frisk_busy_tries',n);}catch(e){}
  if(n>15){try{sessionStorage.removeItem('frisk_busy_tries');}catch(e){}document.getElementById('lbl').innerHTML='still very busy<br><span class="dim">please try again in a few minutes</span><br><a href="/">scan another repo</a>';return;}
  setTimeout(function(){location.reload();}, 6000+Math.floor(Math.random()*5000));
})();
</script>`;
  return shell(inner, true, "busy");
}

export function errorPage(owner: string, repo: string, message: string): string {
  const inner = `
<a class="back" href="/">← back</a>
<div class="logobar"><a class="logo" href="https://github.com/fletcherholt/frisk">frisk</a><span class="logo-hint">check out the repo ↗</span></div>
<h1>${escapeHtml(owner)}/${escapeHtml(repo)}</h1>
<div class="f"><div class="ftitle" style="color:#fab387">Could not scan</div>
<div class="fdetail">${escapeHtml(message)}</div>
<div class="fdetail" style="margin-top:10px"><a href="/">Scan another repository</a></div></div>`;
  return shell(inner);
}
