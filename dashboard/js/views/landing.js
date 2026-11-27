import * as api from '../api.js';
import { $, esc, icon, reveal, statusPill, ago, stamp, toast } from '../ui.js';
import { STAGES, STAGE_INFO } from '../model.js';
import { agentHtml } from './parts.js';

const SAMPLES_DEMO = ['fake-stealer@1.0.0', 'chrono-helpers@2.4.1', 'release-notes-gen@0.3.1', 'left-pad@1.3.0'];
const SAMPLES_LIVE = ['left-pad@1.3.0', 'is-number@7.0.0'];
const MARK = 'VLT9F21C04B7E';
const mk = (pre, post = '…') => `${esc(pre)}<b>${MARK}</b>${esc(post)}`;

// The sample report in the hero: what the demo package fake-stealer does in the sandbox.
const SHEET_ROWS = [
  ['~/.aws/credentials', 'AWS access keys', true],
  ['~/.npmrc', 'npm publish token', true],
  ['~/.ssh/id_rsa', 'SSH private key', true],
  ['.env', 'Stripe and OpenAI keys', true],
  ['~/.git-credentials', 'GitHub token', false],
  ['~/.kube/config', 'Cluster token', false, 'xtra'],
];
const BAIT = [
  ['~/.aws/credentials', 'AWS access keys', mk('AKIA')],
  ['~/.npmrc', 'npm publish token', mk('npm_')],
  ['~/.ssh/id_rsa', 'SSH private key', mk('', 'b3Blbn…')],
  ['~/.git-credentials', 'GitHub token', mk('ghp_')],
  ['.env', 'Stripe and OpenAI keys', mk('sk_live_')],
  ['~/.kube/config', 'Kubernetes token', mk('', 'kube')],
  ['~/.docker/config.json', 'Registry login', mk('')],
  ['~/.config/solana/id.json', 'Solana wallet', ''],
  ['~/.ethereum/keystore', 'Ethereum wallet', mk('')],
  ['GITHUB_TOKEN, NPM_TOKEN', 'CI environment', mk('ghs_', 'CI…')],
];
const TRANSCRIPT = [
  { tool: 'grep', args: '"Date.now|new Date"', thought: 'Today’s runs were clean but the +90 day runs read secrets, so there should be a date check', result: 'lib/tz.js:41  if (Date.now() > 1767225600000) require("./sync")' },
  { tool: 'read_file', args: 'lib/sync.js', thought: 'What does the code behind that check do', result: 'Reads ~/.npmrc and ~/.git-credentials and encodes them into DNS lookups' },
  { tool: 'rerun', args: 'persona=developer, clock=+365d', thought: 'Confirm it stays armed after the trigger date', result: 'Two secrets read and three DNS lookups again: armed from 1 January 2026 onward' },
];

export default function landing(el) {
  const demo = api.state.mode === 'mock';
  const samples = demo ? SAMPLES_DEMO : SAMPLES_LIVE;
  el.innerHTML = `
  <section class="hero">
    <div class="wrap hero-in">
      <div class="hero-copy">
        <h1 class="display">See what a package steals before you install it</h1>
        <p class="sub">Vulture installs any npm package or GitHub repo on a throwaway Vultr machine stocked with fake secrets, then shows you every file it read and every server it called</p>
        <form class="scanbox" id="scan-f" novalidate>
          ${icon('package', 'lead-ico')}
          <label class="sr-only" for="src">npm package, GitHub URL or file</label>
          <input id="src" type="text" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="package@version or a GitHub URL">
          <span id="file-slot" hidden></span>
          <input id="file" type="file" accept=".tgz,.tar.gz,.tar,.zip" hidden>
          <button type="button" class="icon-btn" id="pick" aria-label="Upload a .tgz, .tar or .zip file" title="Upload a file">${icon('upload')}</button>
          <button class="btn lg" id="go">Scan</button>
        </form>
        <p class="scan-error" id="err" role="alert"></p>
        <p class="samples"><span>Try a sample</span>${samples.map(v => `<button type="button" data-v="${esc(v)}">${esc(v.split('@')[0])}</button>`).join('')}</p>
      </div>
      <img class="hero-art" src="img/hero.webp" width="1672" height="941" fetchpriority="high" alt="Engraving of a vulture perched on a dead post, studying a taped parcel on cracked ground">
    </div>
  </section>

  <section class="specimen">
    <div class="wrap">
      <div class="sheet-demo" id="sheet">
        <div class="sheet-head">
          <span class="pkg">fake-stealer@1.0.0</span><span class="tag" title="Marker planted in every fake secret for this scan">${MARK}</span>
          <span class="right">Sample report</span>
        </div>
        <div class="sheet-body">
          <div class="sheet-col">
            <p class="label">Planted secrets</p>
            <table class="ledger" id="sheet-rows"><tbody>${SHEET_ROWS.map(([p, k, hit, cls]) => `<tr class="${cls || ''}" data-hit="${hit ? 1 : 0}"><td><span class="path">${esc(p)}</span></td><td class="kind">${esc(k)}</td><td>untouched</td></tr>`).join('')}</tbody></table>
            <div class="wire" id="sheet-wire">
              <p class="label">Network</p>
              <div class="wire-line"><span class="verb">DNS</span><span class="what">collect.exfil-sample.invalid</span><span class="found" style="color:var(--ink-3)">fake internet</span></div>
              <div class="wire-line"><span class="verb">POST</span><span class="what">collect.exfil-sample.invalid/c</span><span class="found">marker in body</span></div>
            </div>
          </div>
          <div class="sheet-col">
            <p class="label">Secrets read in each run</p>
            <div class="plate" id="sheet-plate" style="--cols:2">
              <span class="ph corner top"></span><span class="ph top">Today</span><span class="ph top">+90 days</span>
              <span class="ph side">Developer laptop</span><div class="cell"><span class="n">–</span></div><div class="cell"><span class="n">–</span></div>
              <span class="ph side">CI runner</span><div class="cell"><span class="n">–</span></div><div class="cell"><span class="n">–</span></div>
            </div>
            <div style="height:88px"></div>
            <div class="sheet-stamp" id="sheet-stamp">${stamp('malware', { xl: true })}</div>
          </div>
        </div>
        <div class="sheet-foot">
          <span>fake-stealer is a harmless test package. It only talks to hosts that exist inside the sandbox</span>
          <button class="text-btn" id="replay" type="button">Replay</button>
        </div>
      </div>
    </div>
  </section>

  <section class="section tight" id="recent-sec" hidden>
    <div class="wrap">
      <div class="page-head" style="margin-bottom:16px"><h2 class="h3">Recent scans</h2><a class="link-arrow" href="#/history">All scans ${icon('chevron')}</a></div>
      <div class="list" id="recent"></div>
    </div>
  </section>

  <section class="section">
    <div class="wrap split">
      <div class="aside reveal">
        <h2 class="h2">Eight steps from a package name to a verdict</h2>
        <p class="sub">Nothing from the package runs on the machine that serves this page. Each scan gets its own Vultr instance, and that instance is deleted when the scan ends</p>
      </div>
      <ol class="steps" data-reveal>
        ${STAGES.map((s, i) => `<li class="${s === 'detonate' ? 'hot' : ''}"><span class="n">${i + 1}</span><div><h3>${STAGE_INFO[s].label}</h3><p>${STAGE_INFO[s].text}</p></div></li>`).join('')}
      </ol>
    </div>
  </section>

  <hr class="rule">
  <section class="section">
    <div class="wrap">
      <div class="reveal">
        <h2 class="h2">Everything on the machine is bait</h2>
        <p class="sub" style="margin-top:16px">Each run plants ten kinds of credentials that carry a marker unique to the scan. When that marker shows up in outgoing traffic, the theft is proven, not guessed</p>
      </div>
      <div class="plant">
        <div class="tbl-wrap reveal">
          <table class="ledger"><tbody>${BAIT.map(([p, k, v]) => `<tr><td><span class="path">${esc(p)}</span></td><td class="kind">${esc(k)}</td><td class="bait">${v}</td></tr>`).join('')}</tbody></table>
        </div>
        <div class="facts reveal">
          <div><h3>A fake internet answers every request</h3><p>DNS, HTTP, TLS and raw TCP all land on a sinkhole inside the sandbox. The package believes it got through, and nothing reaches a real server</p>
            <pre>DNS   collect.exfil-sample.invalid → 172.30.0.2\nPOST  /c  200  body contains <b>${MARK}</b></pre></div>
          <div><h3>The clock is moved 90 days ahead</h3><p>Every package runs twice, today and three months from now, so code that waits for a date goes off inside the sandbox</p></div>
          <div><h3>It runs as a laptop and as a CI runner</h3><p>Malware that only acts when it sees <span class="mono">GITHUB_ACTIONS</span> gets a runner with tokens that look worth taking</p></div>
        </div>
      </div>
    </div>
  </section>

  <hr class="rule">
  <section class="section">
    <div class="wrap split">
      <div class="aside reveal">
        <h2 class="h2">An investigator, not a summary</h2>
        <p class="sub">A model on Vultr Inference gets the traces and a set of tools. It decides what to read, what to search for and what to run again, and stops when every suspicious code path is explained</p>
      </div>
      <div>
        <div class="transcript reveal"><div class="agent">${agentHtml(TRANSCRIPT)}</div></div>
        <div class="reveal" style="margin-top:64px">
          <h3 class="h3">One machine per scan</h3>
          <div class="vm-line" data-reveal>
            <div><b>Create</b>The Vultr API starts a fresh instance</div>
            <div><b>Boot</b>From a snapshot with the images already pulled</div>
            <div><b>Detonate</b>No route out, only the fake internet</div>
            <div><b>Destroy</b>The instance is deleted with everything on it</div>
          </div>
        </div>
        <div class="reveal" style="margin-top:64px">
          <h3 class="h3">Risky steps wait for a person</h3>
          <p class="sub" style="margin-top:8px;font-size:16px;line-height:26px">Running with the real internet, filing a public abuse report and renting a bigger machine all pause the scan until someone approves them. <a href="#/approvals">Open approvals</a></p>
        </div>
      </div>
    </div>
  </section>

  <hr class="rule">
  <section class="closing">
    <div class="wrap reveal">
      <h2 class="h2">Paste the package name before you paste the install command</h2>
      <p><a class="btn lg" href="#/" id="cta-top">Scan a package</a></p>
    </div>
  </section>
  <div class="dropzone" id="drop" aria-hidden="true"><div class="inner">${icon('upload')}Drop a .tgz, .tar or .zip file to scan it</div></div>`;

  // bait values: the marker is the red part
  el.querySelectorAll('.bait b').forEach(b => { b.style.cssText = 'font-weight:500;color:var(--red)'; });

  const form = $('#scan-f', el), input = $('#src', el), fileIn = $('#file', el), err = $('#err', el), go = $('#go', el), slot = $('#file-slot', el);
  let file = null;
  const showFile = () => {
    slot.hidden = !file; input.hidden = !!file;
    slot.className = file ? 'file-chip' : '';
    slot.innerHTML = file ? `${icon('file')}<span>${esc(file.name)}</span><button type="button" aria-label="Remove file" id="unfile">${icon('x')}</button>` : '';
    if (file) $('#unfile', el).onclick = () => { file = null; fileIn.value = ''; showFile(); input.focus(); };
  };
  $('#pick', el).onclick = () => fileIn.click();
  fileIn.onchange = () => { file = fileIn.files[0] || null; showFile(); };
  el.querySelectorAll('[data-v]').forEach(c => c.onclick = () => { file = null; showFile(); input.value = c.dataset.v; err.textContent = ''; form.requestSubmit(); });
  $('#cta-top', el).onclick = e => { e.preventDefault(); window.scrollTo({ top: 0, behavior: 'smooth' }); setTimeout(() => input.focus({ preventScroll: true }), 450); };

  form.onsubmit = async e => {
    e.preventDefault();
    err.textContent = '';
    const source = input.value.trim();
    if (!source && !file) { err.textContent = 'Type a package name or a GitHub URL, or drop a file'; input.focus(); return; }
    go.disabled = true; go.innerHTML = '<span class="spinner"></span>Starting';
    try {
      const { id, deduped } = await api.createScan({ source, file });
      // an exact version that was already scanned has the same answer, so the API hands back the stored scan
      if (deduped) toast('Already scanned, here is the stored report');
      location.hash = deduped ? `#/report/${id}` : `#/scan/${id}`;
    } catch (ex) {
      err.textContent = ex.message;
      go.disabled = false; go.textContent = 'Scan';
    }
  };

  // drag and drop anywhere on the page
  const drop = $('#drop', el);
  let depth = 0;
  const hasFiles = e => [...(e.dataTransfer?.types || [])].includes('Files');
  const onEnter = e => { if (!hasFiles(e)) return; e.preventDefault(); depth++; drop.classList.add('on'); };
  const onLeave = () => { depth = Math.max(0, depth - 1); if (!depth) drop.classList.remove('on'); };
  const onOver = e => { if (hasFiles(e)) e.preventDefault(); };
  const onDrop = e => {
    if (!e.dataTransfer?.files?.length) return;
    e.preventDefault(); depth = 0; drop.classList.remove('on');
    file = e.dataTransfer.files[0]; showFile(); window.scrollTo({ top: 0, behavior: 'smooth' }); go.focus();
  };
  document.addEventListener('dragenter', onEnter); document.addEventListener('dragleave', onLeave);
  document.addEventListener('dragover', onOver); document.addEventListener('drop', onDrop);

  const stopSheet = playSheet(el);

  api.listScans({ limit: 4 }).then(list => {
    if (!list.length) return;
    $('#recent-sec', el).hidden = false;
    $('#recent', el).innerHTML = list.slice(0, 4).map(rowHtml).join('');
  }).catch(() => {});

  reveal(el);
  return () => {
    stopSheet();
    document.removeEventListener('dragenter', onEnter); document.removeEventListener('dragleave', onLeave);
    document.removeEventListener('dragover', onOver); document.removeEventListener('drop', onDrop);
  };
}

/** The sample report plays the scan once when it scrolls into view: secrets get marked, traffic appears, the stamp lands. */
function playSheet(el) {
  const sheet = $('#sheet', el), rows = [...el.querySelectorAll('#sheet-rows tr')], wires = [...el.querySelectorAll('#sheet-wire .wire-line')];
  const cells = [...el.querySelectorAll('#sheet-plate .cell')], st = $('#sheet-stamp', el), mark = st.firstElementChild;
  const still = matchMedia('(prefers-reduced-motion: reduce)').matches;
  let timers = [];
  const at = (ms, fn) => timers.push(setTimeout(fn, still ? 0 : ms));
  const reset = () => {
    timers.forEach(clearTimeout); timers = [];
    rows.forEach(r => { r.classList.remove('read'); r.lastElementChild.textContent = 'untouched'; });
    wires.forEach(w => w.classList.remove('in'));
    cells.forEach(c => { c.className = 'cell'; c.innerHTML = '<span class="n">–</span>'; });
    st.classList.remove('land'); mark.classList.remove('land'); sheet.classList.remove('thud');
  };
  const play = () => {
    reset();
    let t = 500;
    rows.filter(r => r.dataset.hit === '1').forEach(r => { at(t, () => { r.classList.add('read'); r.lastElementChild.textContent = 'read'; }); t += 380; });
    wires.forEach(w => { t += 180; at(t, () => w.classList.add('in')); t += 320; });
    t += 200;
    cells.forEach(c => { at(t, () => { c.className = 'cell l3'; c.innerHTML = '<span class="n">4</span><span class="x">secrets read</span>'; }); t += 150; });
    at(t + 450, () => { void st.offsetWidth; st.classList.add('land'); mark.classList.add('land'); sheet.classList.add('thud'); });
  };
  $('#replay', el).onclick = play;
  if (!('IntersectionObserver' in window)) { play(); return () => timers.forEach(clearTimeout); }
  const io = new IntersectionObserver(es => { if (es.some(e => e.isIntersecting)) { io.disconnect(); play(); } }, { threshold: 0.35 });
  io.observe(sheet);
  return () => { io.disconnect(); timers.forEach(clearTimeout); };
}

export function rowHtml(s) {
  const key = s.status === 'done' ? (s.verdict || 'incomplete') : s.status;
  const ic = { safe: 'shieldCheck', suspicious: 'shieldAlert', malware: 'shieldX', incomplete: 'shieldQ', failed: 'alert', cancelled: 'ban', running: 'flask', queued: 'clock' }[key] || 'package';
  const href = s.status === 'done' ? `#/report/${s.id}` : `#/scan/${s.id}`;
  const kind = s.source.startsWith('upload:') ? 'Uploaded file' : s.source.startsWith('https://github.com') ? 'GitHub repository' : 'npm package';
  return `<a class="row" href="${href}">
    <span class="vi ${key}">${icon(ic)}</span>
    <span style="min-width:0"><div class="nm">${esc(s.source.replace(/^upload:/, '').replace(/^https:\/\/github\.com\//, ''))}</div><div class="sb">${kind}</div></span>
    ${statusPill(s)}
    <span class="tm">${ago(s.created)}</span>
    ${icon('chevron', 'ico chev')}
  </a>`;
}
