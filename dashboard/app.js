// Vulture dashboard v2: landing, live scan view, shareable report, history, approvals.
// Plain JS, hash routes. `?mock=1` runs the whole UI on sample data (mock.js), no backend needed.
const $ = (s, r = document) => r.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const MOCK = new URLSearchParams(location.search).has('mock') && window.VultureMock;
let timer = null, askToken = null;

// ---- API (access token asked once, kept in this browser; a 401 asks again) ----
function tokenPrompt() {
  askToken ??= new Promise(done => {
    const o = document.createElement('div'); o.className = 'overlay';
    o.innerHTML = `<form class="card" style="max-width:360px"><h3>Access token</h3>
      <p class="muted">This Vulture instance is private. Paste the access token you were given.</p>
      <input id="tok" type="password" autocomplete="off" style="width:100%;margin-bottom:10px" required><button>Continue</button></form>`;
    document.body.append(o); $('#tok', o).focus();
    $('form', o).onsubmit = e => { e.preventDefault(); const v = $('#tok', o).value.trim(); o.remove(); askToken = null; done(v); };
  });
  return askToken;
}
async function api(url, opts = {}, retried = false) {
  if (MOCK) return VultureMock.api(url, opts);
  const tok = localStorage.getItem('vultureToken');
  const r = await fetch(url, { ...opts, headers: { ...(opts.headers || {}), ...(tok ? { Authorization: 'Bearer ' + tok } : {}) } });
  if (r.status !== 401 || retried) return r;
  localStorage.setItem('vultureToken', await tokenPrompt());
  return api(url, opts, true);
}
const json = async r => { const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.detail || r.statusText); return j; };

// ---- helpers ----
const table = (rows, cols) => !rows || !rows.length ? '<div class="empty">Nothing.</div>' :
  `<table><tr>${cols.map(c => `<th>${c[0]}</th>`).join('')}</tr>${rows.map(r => `<tr>${cols.map(c => `<td>${c[1](r)}</td>`).join('')}</tr>`).join('')}</table>`;
const ago = t => { const s = Math.max(0, Date.now() / 1000 - t); return s < 90 ? 'just now' : s < 5400 ? Math.round(s / 60) + ' min ago' : s < 129600 ? Math.round(s / 3600) + ' h ago' : Math.round(s / 86400) + ' d ago'; };
const vclass = v => ['safe', 'suspicious', 'malware'].includes(v) ? v : 'incomplete';
const vpill = (v, status) => v ? `<span class="pill ${v === 'malware' ? 'bad' : v === 'suspicious' ? 'warn' : v === 'safe' ? 'ok' : ''}">${esc(v.toUpperCase())}</span>` : `<span class="pill">${esc(status)}</span>`;
function nav(on) {
  document.querySelectorAll('[data-nav]').forEach(a => a.classList.toggle('on', a.dataset.nav === on));
  $('#mock-flag').hidden = !MOCK;
}

// ---- router ----
function route() {
  clearInterval(timer);
  const h = location.hash.replace(/^#\/?/, '');
  if (h.startsWith('scan/')) return scanView(h.slice(5));
  if (h === 'history') return historyView();
  if (h === 'approvals') return approvalsView();
  return homeView();
}
addEventListener('hashchange', route);

// ---- landing ----
async function homeView() {
  nav('home');
  $('#view').innerHTML = `
  <div class="hero"><h1>Is this package safe to install?</h1>
    <p>Paste a package or repo. Vulture runs it on a throwaway machine full of fake secrets and a fake internet, an AI agent investigates, and you get a shareable Safe / Malware report.</p></div>
  <div class="drop" id="drop"><form class="row" id="f">
    <input type="text" id="source" placeholder="npm package (left-pad@1.3.0) or GitHub URL (https://github.com/owner/repo)" aria-label="Package to scan">
    <button id="go">Scan</button></form>
    <div class="muted" style="margin-top:8px;font-size:12px">or drag a <b>.tgz / .zip</b> here <span id="fname"></span> <input type="file" id="file" accept=".tgz,.tar.gz,.tar,.zip" hidden> <a href="#" id="pick">choose a file</a></div>
    <div class="examples">${['left-pad@1.3.0', 'is-number@7.0.0', 'https://github.com/Ans1337/vulture'].map(x => `<span class="chip" data-v="${esc(x)}">${esc(x)}</span>`).join('')}
      <span class="chip" data-sample="1">harmless fake malware (sample)</span></div></div>
  <div id="formerr"></div>
  <div class="how">${[['1 Fetch', 'pin the exact version and hash'], ['2 Static pass', 'install scripts, obfuscation, risky calls'], ['3 Sandbox', 'throwaway VM, fake secrets, fake internet'],
    ['4 Detonate', 'persona × clock matrix, time pushed forward'], ['5 Observe', 'network, files, processes, honeytoken hits'], ['6 Investigate', 'AI reads code and re-runs what looks gated']]
    .map(([a, b]) => `<div><b>${a}</b>${b}</div>`).join('')}</div>
  <div class="card list"><h3>Recent scans</h3><div id="recent" class="empty">Loading…</div></div>`;
  let file = null;
  const setFile = f => { file = f; $('#fname').textContent = f ? '· ' + f.name : ''; };
  document.querySelectorAll('.chip[data-v]').forEach(c => c.onclick = () => { $('#source').value = c.dataset.v; });
  $('.chip[data-sample]').onclick = () => { $('#source').value = 'npm:fake-stealer@2.1.0'; };
  $('#pick').onclick = e => { e.preventDefault(); $('#file').click(); };
  $('#file').onchange = e => setFile(e.target.files[0]);
  const drop = $('#drop');
  ['dragover', 'dragenter'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', e => setFile(e.dataTransfer.files[0]));
  $('#f').onsubmit = async e => {
    e.preventDefault(); $('#go').disabled = true; $('#formerr').innerHTML = '';
    try {
      const fd = new FormData(); fd.append('source', $('#source').value); if (file) fd.append('file', file);
      const j = await json(await api('/api/scans', { method: 'POST', body: fd }));
      location.hash = '#/scan/' + j.id;
    } catch (err) { $('#formerr').innerHTML = `<div class="card err">${esc(err.message)}</div>`; $('#go').disabled = false; }
  };
  try { const list = await json(await api('/api/scans?limit=8')); $('#recent').outerHTML = `<div id="recent">${scanList(list)}</div>`; } catch { $('#recent').textContent = 'Could not load history.'; }
}
const scanList = list => list.length ? list.map(s => `<a class="item" href="#/scan/${esc(s.id)}"><span>${esc(s.source)}</span><span class="muted">${ago(s.created)}</span>${vpill(s.verdict, s.status)}</a>`).join('') : '<div class="empty">None yet.</div>';

// ---- history ----
async function historyView() {
  nav('history');
  $('#view').innerHTML = `<h2>Scan history</h2><div class="card"><div class="row"><input type="text" id="q" placeholder="Filter by package…">
    <select id="fv"><option value="">any verdict</option><option>safe</option><option>suspicious</option><option>malware</option><option>incomplete</option></select>
    <select id="fs"><option value="">any status</option><option>done</option><option>running</option><option>queued</option><option>failed</option><option>cancelled</option></select></div></div>
    <div class="card list" id="hist"></div>`;
  const load = async () => {
    const p = new URLSearchParams({ q: $('#q').value, verdict: $('#fv').value, status: $('#fs').value, limit: 200 });
    try { $('#hist').innerHTML = scanList(await json(await api('/api/scans?' + p))); } catch (e) { $('#hist').innerHTML = `<div class="err">${esc(e.message)}</div>`; }
  };
  let t; $('#q').oninput = () => { clearTimeout(t); t = setTimeout(load, 250); }; $('#fv').onchange = $('#fs').onchange = load;
  load();
}

// ---- approvals inbox (events carry data.approval = {id,title,detail,state}; approve/reject call the API) ----
async function approvalsView() {
  nav('approvals');
  $('#view').innerHTML = '<h2>Approvals</h2><div id="appr" class="empty">Loading…</div>';
  const items = await pendingApprovals();
  $('#appr').outerHTML = `<div id="appr">${items.length ? items.map(a => approvalCard(a.approval, a.scan)).join('') : '<div class="card empty">Nothing is waiting for approval.</div>'}</div>`;
  wireApprovals();
}
async function pendingApprovals() {
  try {
    const list = await json(await api('/api/scans?status=running&limit=50')), out = [];
    for (const s of list) { const full = await json(await api('/api/scans/' + s.id)); for (const a of approvalsOf(full.events)) if (a.state === 'pending') out.push({ approval: a, scan: s }); }
    return out;
  } catch { return []; }
}
const approvalsOf = events => { const m = {}; for (const e of events || []) if (e.data?.approval) m[e.data.approval.id] = e.data.approval; return Object.values(m); };
const approvalCard = (a, scan) => `<div class="card gate"><b>⚠ Approval needed: ${esc(a.title)}</b>${scan ? ` <span class="muted">· ${esc(scan.source)}</span>` : ''}
  <div class="muted">${esc(a.detail)}</div><div class="row"><button class="ok" data-appr="${esc(a.id)}" data-do="approve">Approve</button><button class="bad" data-appr="${esc(a.id)}" data-do="reject">Reject</button></div></div>`;
function wireApprovals() {
  document.querySelectorAll('[data-appr]').forEach(b => b.onclick = async () => {
    b.disabled = true;
    try { await json(await api(`/api/approvals/${encodeURIComponent(b.dataset.appr)}/${b.dataset.do}`, { method: 'POST' })); route(); }
    catch (e) { b.parentElement.insertAdjacentHTML('beforeend', `<span class="err">${esc(e.message)}</span>`); b.disabled = false; }
  });
}

// ---- scan view: live progress, then the report ----
async function scanView(id) {
  nav('home');
  const st = { id, events: [], last: 0, scan: null };
  const tick = async () => {
    try {
      const s = await json(await api(`/api/scans/${encodeURIComponent(id)}?after=${st.last}`));
      st.events.push(...s.events); st.last = st.events.at(-1)?.id ?? st.last; st.scan = s;
      drawScan(st);
      if (!['queued', 'running'].includes(s.status)) clearInterval(timer);
    } catch (e) { $('#view').innerHTML = `<div class="card err">${esc(e.message)}</div>`; clearInterval(timer); }
  };
  $('#view').innerHTML = '<div class="empty">Loading…</div>';
  await tick(); timer = setInterval(tick, 1200);
}

function runCards(events) {
  const runs = {};
  for (const e of events) { const d = e.data || {}; if (d.run) runs[d.run] = { ...runs[d.run], ...d, msg: e.msg }; }
  const list = Object.entries(runs);
  return list.length ? `<div class="cards">${list.map(([name, r]) => {
    const cls = r.state === 'running' ? 'running' : r.honeytoken_hits ? 'hit' : r.state === 'done' ? 'clean' : '';
    return `<div class="run ${cls}"><b>${esc(name)}</b>${r.state === 'running' ? 'running…' : r.state === 'done' ? `${r.honeytoken_hits ?? 0} honeytoken hits · ${r.network ?? 0} net · ${r.processes ?? 0} procs` : esc(r.state || '')}
      ${r.retry ? `<div class="retry">↻ retry ${r.retry}${r.retry_reason ? ': ' + esc(r.retry_reason) : ''}</div>` : ''}</div>`;
  }).join('')}</div>` : '<div class="empty">Waiting for the first run…</div>';
}
function vmStrip(events) {
  const seen = new Set(events.map(e => e.data?.vm).filter(Boolean));
  if (!seen.size) return '';
  const steps = [['creating', 'VM created'], ['ready', 'booted'], ['destroyed', 'destroyed']];
  const failed = seen.has('destroy_failed');
  return `<div class="vm">${steps.map(([k, label], i) => `${i ? '<i></i>' : ''}<span class="${seen.has(k) || (k === 'creating' && seen.has('created')) ? 'done' : ''}">${label}</span>`).join('')}${failed ? '<i></i><span class="bad">destroy failed (janitor will retry)</span>' : ''}</div>`;
}
function investigatorSteps(events) {
  const steps = events.filter(e => e.stage === 'investigate');
  if (!steps.length) return '';
  return `<div class="card"><h3>AI investigator</h3><div class="steps">${steps.map(e => e.data?.tool
    ? `<div class="step"><div class="tool">${esc(e.msg)}</div>${e.data.thought ? `<div class="thought">${esc(e.data.thought)}</div>` : ''}</div>`
    : `<div class="step"><div class="thought">${esc(e.msg)}${e.data?.retry ? ` <span class="pill warn">retry ${e.data.retry}</span>` : ''}</div></div>`).join('')}</div></div>`;
}
function filmstrip(events) {
  const shots = events.filter(e => e.data?.screenshot);
  return shots.length ? `<div class="card"><h3>Screenshot trail</h3><div class="film">${shots.map(e => `<figure><img src="${esc(e.data.screenshot)}" alt="${esc(e.data.url || 'screenshot')}"><figcaption>${esc(e.data.url || '')}${e.data.vision ? '<br>' + esc(e.data.vision) : ''}</figcaption></figure>`).join('')}</div></div>` : '';
}

function drawScan(st) {
  const s = st.scan, ev = st.events, rep = s.report, active = ['queued', 'running'].includes(s.status);
  const idx = s.stages.indexOf(s.stage);
  const pills = s.stages.map((x, i) => `<span class="stage ${s.status === 'done' || (!active && i <= idx) || i < idx ? 'done' : i === idx ? 'on' : ''}">${i + 1}. ${esc(x)}</span>`).join('');
  const approvals = approvalsOf(ev).filter(a => a.state === 'pending');
  const log = ev.map(e => `<div>[${e.t}s] <b>${esc(e.stage)}</b> ${esc(e.msg)}</div>`).join('');
  const keep = $('#log'), atEnd = !keep || keep.scrollTop + keep.clientHeight >= keep.scrollHeight - 8;
  let h = `<div class="row" style="justify-content:space-between;margin-bottom:8px"><div><h2 style="margin:0">${esc(s.source)}</h2>
      <span class="muted">${esc(s.status)}${s.stage && active ? ' · ' + esc(s.stage) : ''} · started ${ago(s.created)}</span></div>
      <div class="row">${active ? '<button class="ghost" id="cancel">Cancel scan</button>' : ''}<button class="ghost" id="share">Copy link</button>${!active ? '<button id="rescan">Re-scan</button>' : ''}</div></div>
    ${approvals.map(a => approvalCard(a)).join('')}
    <div class="card"><div class="stages">${pills}</div>${vmStrip(ev)}<div class="log" id="log" style="margin-top:8px">${log}</div>
      ${s.error ? `<div class="err" style="margin-top:8px">${esc(s.error)}</div>` : ''}</div>
    <div class="card"><h3>Persona × clock runs</h3>${runCards(ev)}</div>${investigatorSteps(ev)}${filmstrip(ev)}`;
  if (rep) h += reportHtml(s, rep);
  $('#view').innerHTML = h;
  const l = $('#log'); if (l && atEnd) l.scrollTop = l.scrollHeight;
  wireApprovals(); if (rep) wireTabs(rep);
  $('#share').onclick = async () => { await navigator.clipboard?.writeText(location.href); $('#share').textContent = 'Copied ✓'; };
  const c = $('#cancel'); if (c) c.onclick = async () => { c.disabled = true; try { await json(await api(`/api/scans/${s.id}/cancel`, { method: 'POST' })); } catch (e) { c.textContent = e.message; } };
  const r = $('#rescan'); if (r) r.onclick = async () => {
    r.disabled = true; const fd = new FormData(); fd.append('source', s.source.replace(/^upload:.*/, '')); fd.append('force', 'true');
    try { location.hash = '#/scan/' + (await json(await api('/api/scans', { method: 'POST', body: fd }))).id; } catch (e) { r.textContent = e.message; }
  };
}

// ---- report ----
function plainEnglish(rep) {
  const ai = rep.ai && !rep.ai.error ? rep.ai : null;
  if (ai?.summary) return ai.summary;
  const r = rep.rules.reasons;
  return r.length ? 'What we saw: ' + r.join('; ') + '.' : 'No risky behaviour was observed.';
}
function heatmap(matrix) {
  const rows = {}, cols = new Set();
  for (const [name, v] of Object.entries(matrix || {})) {
    const m = name.match(/^(.+?)\s*[@/|:·]\s*(\+?\d+d?)$/) || [null, name, '0'];
    (rows[m[1]] ??= {})[m[2]] = v; cols.add(m[2]);
  }
  const cs = [...cols], ps = Object.keys(rows);
  if (!ps.length) return '<div class="empty">No runs recorded.</div>';
  const cell = v => !v ? '<div>-</div>' : `<div class="c${v.honeytoken_hits ? 2 : v.network || v.processes > 3 ? 1 : 0}" title="${v.honeytoken_hits} honeytoken hits, ${v.network} network calls, ${v.processes} processes">${v.honeytoken_hits ? v.honeytoken_hits + ' hits' : v.network ? v.network + ' net' : 'clean'}</div>`;
  return `<div class="heat" style="grid-template-columns:110px repeat(${cs.length},1fr)"><div class="h"></div>${cs.map(c => `<div class="h">clock ${esc(c)}</div>`).join('')}${ps.map(p => `<div class="h" style="text-align:left">${esc(p)}</div>${cs.map(c => cell(rows[p][c])).join('')}`).join('')}</div>`;
}
function reportHtml(s, rep) {
  const ev = rep.evidence, ai = rep.ai && !rep.ai.error ? rep.ai : null, t = ev.target || {}, cov = rep.rules.coverage;
  const conf = ai?.confidence != null ? Math.round(ai.confidence * 100) : null, v = rep.verdict;
  const sub = ai ? `AI says ${esc(ai.verdict)} · verdict set by ${rep.verdict_source === 'ai' ? 'AI (raised above rules)' : 'rules'}${ai.note ? ` · <span style="color:var(--warn)">${esc(ai.note)}</span>` : ''}`
    : rep.ai?.error ? 'rule-based (AI review failed)' : 'rule-based (set VULTR_INFERENCE_API_KEY + AGENT_MODEL for the AI verdict)';
  const tabs = {
    Honeytokens: [ev.honeytoken_access, () => table(ev.honeytoken_access, [['File', h => `<span class="mono">${esc((h.file || '').replace(/^\/tmp\/runs\/[^/]+/, ''))}</span>`], ['Op', h => esc(h.op)], ['Run', h => esc(h.run)]])],
    Network: [[...(ev.exfiltration || []), ...(ev.requests || [])], () => `${(ev.dns_lookups || []).map(d => `<span class="pill">${esc(d)}</span>`).join('')}<h3 style="margin-top:10px">Secrets sent out</h3>${table(ev.exfiltration, [['Where', x => esc((x.host || x.sni || '') + (x.path || '') + (x.port ? ':' + x.port : ''))], ['Kind', x => esc(x.kind + (x.method ? ' ' + x.method : ''))]])}<h3 style="margin-top:10px">Requests</h3>${table(ev.requests, [['Kind', x => esc(x.kind)], ['Target', x => esc((x.host || x.sni || '') + (x.path || '') + ' :' + x.port)], ['Body', x => `<span class="mono">${esc((x.body || x.data || '').slice(0, 120))}</span>`]])}`],
    Processes: [ev.processes, () => table(ev.processes, [['Command', p => `<span class="mono">${esc((p.argv || []).join(' ').slice(0, 160))}</span>`], ['Run', p => esc(p.run)]])],
    Files: [ev.files_written_outside_project, () => (ev.files_written_outside_project || []).length ? `<ul>${ev.files_written_outside_project.map(f => `<li class="mono">${esc(f)}</li>`).join('')}</ul>` : '<div class="empty">Nothing written outside the project.</div>'],
    Static: [ev.static_findings, () => `${(ev.install_scripts || []).length ? `<p>Install scripts: ${ev.install_scripts.map(i => `<span class="pill">${esc(i.package)} ${esc(i.hook)}: ${esc(i.command)}</span>`).join('')}</p>` : ''}${table((ev.static_findings || []).filter(f => f.severity !== 'low').slice(0, 30), [['Sev', f => `<span class="sev-${esc(f.severity)}">${esc(f.severity)}</span>`], ['Rule', f => esc(f.rule)], ['Where', f => `<span class="mono">${esc(f.file)}:${f.line}</span>`], ['Code', f => `<span class="mono">${esc(f.snippet)}</span>`]])}`],
    'Dormant code': [ai?.dormant_triggers, () => table(ai?.dormant_triggers, [['File', d => `<span class="mono">${esc(d.file)}</span>`], ['Condition', d => esc(d.condition)], ['Would do', d => esc(d.would_do)]])],
  };
  const names = Object.keys(tabs);
  window.__tabs = tabs;
  return `<div class="card"><div class="verdict"><div class="big ${vclass(v)}">${esc(v.toUpperCase())}</div><div>
      <div><b>${esc(t.name || s.source)}</b> ${esc(t.version || '')}</div>
      <div class="mono muted">${esc(t.pinned || '')}${t.sha256 ? ' · sha256 ' + esc(t.sha256.slice(0, 16)) + '…' : ''}</div>
      <div class="muted">risk score ${rep.rules.risk_score}/100 · ${sub}</div>
      ${conf != null ? `<div class="row" style="margin-top:4px"><div class="meter"><i style="width:${conf}%;background:var(--accent)"></i></div><span class="muted">${conf}% confidence</span></div>` : ''}
      ${rep.isolation ? `<div class="muted" style="font-size:12px">sandbox: ${esc(rep.isolation.technology)} · ${esc(rep.isolation.network)}</div>` : ''}</div></div>
    <h3 style="margin-top:14px">What it tried to do</h3><p>${esc(plainEnglish(rep))}</p>
    ${ai?.recommendation ? `<p><b>Recommendation:</b> ${esc(ai.recommendation)}</p>` : ''}
    ${rep.ai?.error ? `<p class="err">AI review unavailable (${esc(rep.ai.error)}). The verdict above is rule-based only.</p>` : ''}
    ${cov && !cov.executed ? `<p class="incomplete" style="padding:8px 12px;border-radius:8px"><b>Marked safe, but no package code ran:</b> ${esc(cov.reason)}. Nothing bad was seen because nothing was executed.</p>` : ''}
    <ul>${rep.rules.reasons.map(r => `<li>${esc(r)}</li>`).join('') || '<li>No risky behaviour observed.</li>'}</ul></div>
    ${ai?.indicators?.length ? `<div class="card"><h3>Indicators</h3>${table(ai.indicators, [['Severity', i => `<span class="sev-${esc(i.severity)}">${esc(i.severity)}</span>`], ['Indicator', i => esc(i.title)], ['Evidence', i => esc(i.evidence)]])}</div>` : ''}
    <div class="card"><h3>Persona × clock matrix</h3>${heatmap(ev.matrix)}</div>
    <div class="card"><div class="tabs" id="tabs">${names.map((n, i) => `<button class="${i ? '' : 'on'}" data-tab="${esc(n)}">${esc(n)}<span class="n">${Array.isArray(tabs[n][0]) ? tabs[n][0].length : ''}</span></button>`).join('')}</div><div id="tabbody">${tabs[names[0]][1]()}</div></div>`
  ;
}
function wireTabs() {
  const tabs = window.__tabs;
  document.querySelectorAll('#tabs button').forEach(b => b.onclick = () => {
    document.querySelectorAll('#tabs button').forEach(x => x.classList.toggle('on', x === b));
    $('#tabbody').innerHTML = tabs[b.dataset.tab][1]();
  });
}

async function refreshApprovalBadge() {
  const n = (await pendingApprovals()).length, b = $('#appr-count');
  b.hidden = !n; b.textContent = n;
}
route();
refreshApprovalBadge();
