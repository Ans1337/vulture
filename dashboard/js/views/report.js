import * as api from '../api.js';
import { $, esc, icon, copyText, toast, VERDICT, parseRun, personaLabel, clockLabel, shortHash, stamp, countUp } from '../ui.js';
import { derive, describe, secretKind, prettyPath } from '../model.js';
import { agentHtml, filmHtml, bindFilm, logHtml } from './parts.js';
import { notFound } from './scan.js';

export default function reportView(el, id) {
  el.innerHTML = `<div class="wrap"><div class="verdict-hero"><div class="skel" style="width:160px;height:20px"></div>
    <div class="skel" style="width:min(520px,80%);height:64px;margin-top:16px"></div></div></div>`;
  let alive = true;
  api.getScan(id).then(scan => {
    if (!alive) return;
    if (scan.status !== 'done' || !scan.report) { location.replace(`#/scan/${id}`); return; }
    render(el, scan);
  }).catch(e => { if (alive) el.innerHTML = e.status === 404 ? notFound(id) : `<div class="wrap"><div class="empty-big">${icon('alert')}<h3>This report did not load</h3><p>${esc(e.message)}</p></div></div>`; });
  return () => { alive = false; };
}

const sevRank = { high: 0, medium: 1, low: 2, ok: 3 };
const tbl = (rows, cols, empty = 'Nothing recorded') => !rows?.length ? `<div class="empty">${empty}</div>` :
  `<div class="tbl-wrap"><table class="tbl"><thead><tr>${cols.map(c => `<th scope="col">${c[0]}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${cols.map(c => `<td>${c[1](r)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
const runTag = r => { if (!r) return ''; const { persona, clock } = parseRun(r); return `<span class="badge">${esc(personaLabel(persona))}, ${esc(clockLabel(clock).toLowerCase())}</span>`; };
const sev = s => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const mono = s => `<span class="mono">${esc(s)}</span>`;

function render(el, scan) {
  const rep = scan.report, ev = rep.evidence || {}, t = ev.target || {}, v = rep.verdict;
  const ai = rep.ai && !rep.ai.error ? rep.ai : null;
  const d = derive(scan);
  const runs = Object.keys(ev.matrix || {});
  const hitRuns = runs.filter(r => ev.matrix[r].honeytoken_hits > 0).length;
  const secrets = new Set((ev.honeytoken_access || []).map(h => secretKind(h.file).label));
  const exHosts = new Set((ev.exfiltration || []).map(x => x.host || x.sni));
  const conf = ai ? Math.round((ai.confidence || 0) * 100) : null;
  const items = describe(rep).sort((a, b) => sevRank[a.sev] - sevRank[b.sev]);
  const name = t.name || scan.source.replace(/^upload:/, '').replace(/^https:\/\/github\.com\//, '');
  const kind = scan.source.startsWith('upload:') ? 'Uploaded file' : scan.source.startsWith('https://github.com') ? 'GitHub repository' : 'npm package';
  const when = new Date(scan.created * 1000).toLocaleString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' });

  const tabs = [
    ['indicators', 'Indicators', ai?.indicators?.length || 0, () => tbl(ai?.indicators, [
      ['Severity', i => sev(i.severity)], ['Indicator', i => esc(i.title)], ['Evidence', i => mono(i.evidence)]],
      rep.ai?.error ? `The AI review did not run (${esc(rep.ai.error)}), so the verdict is rule-based` : 'The investigator flagged nothing')],
    ['secrets', 'Secrets', (ev.honeytoken_access || []).length, () => tbl(ev.honeytoken_access, [
      ['Secret', h => { const k = secretKind(h.file); return `<span class="cellico">${icon(k.icon)}${esc(k.label)}</span>`; }],
      ['File', h => mono(prettyPath(h.file))], ['Access', h => esc(h.op)], ['Run', h => runTag(h.run)]], 'No planted secret was touched')],
    ['network', 'Network', (ev.requests || []).length + (ev.exfiltration || []).length + (ev.dns_lookups || []).length, () => `
      ${ev.dns_lookups?.length ? `<p class="label">DNS lookups</p><div class="tokens">${ev.dns_lookups.map(x => `<span>${esc(x)}</span>`).join('')}</div>` : ''}
      ${ev.exfiltration?.length ? `<p class="label" style="color:var(--red)">Sent out with the marker in it</p>${tbl(ev.exfiltration, [
        ['Kind', x => mono(((x.kind || '') + (x.method ? ' ' + x.method : '')).toUpperCase())], ['Where', x => mono((x.host || x.sni || '') + (x.path || '') + (x.port ? ':' + x.port : ''))], ['Run', x => runTag(x.run)]])}<div style="height:24px"></div>` : ''}
      <p class="label">Requests answered by the fake internet</p>
      ${tbl(ev.requests, [['Kind', x => mono((x.kind || '').toUpperCase())], ['Target', x => mono((x.host || x.sni || '') + (x.path || '') + (x.port ? ':' + x.port : ''))], ['Body', x => mono((x.body || x.data || '').slice(0, 140))], ['Run', x => runTag(x.run)]], 'No requests')}`],
    ['processes', 'Processes', (ev.processes || []).length, () => tbl(ev.processes, [['Command', p => mono((p.argv || []).join(' ').slice(0, 200))], ['Run', p => runTag(p.run)]], 'It spawned no processes')],
    ['files', 'Files', (ev.files_written_outside_project || []).length, () => tbl((ev.files_written_outside_project || []).map(f => ({ f })), [['Written outside the package folder', x => mono(prettyPath(x.f))]], 'It wrote nothing outside its own folder')],
    ['static', 'Static', (ev.static_findings || []).length, () => `
      ${ev.install_scripts?.length ? `<p class="label">Install scripts</p><div class="tokens">${ev.install_scripts.map(i => `<span>${esc(i.hook)}: ${esc(i.command)}</span>`).join('')}</div>` : ''}
      ${tbl([...(ev.static_findings || [])].sort((a, b) => sevRank[a.severity] - sevRank[b.severity]), [['Severity', f => sev(f.severity)], ['Rule', f => esc(f.rule)], ['Where', f => mono(`${f.file}:${f.line}`)], ['Code', f => mono(f.snippet)]], 'No static findings')}`],
    ['dormant', 'Dormant code', (ai?.dormant_triggers?.length || 0) + (ev.dormant_code?.length || 0), () => `
      ${tbl(ai?.dormant_triggers, [['File', x => mono(x.file)], ['Trigger', x => esc(x.condition)], ['Would do', x => esc(x.would_do)]], 'No hidden triggers found')}
      ${ev.dormant_code?.length ? `<p class="label" style="margin-top:24px">Suspicious code that never ran</p>${tbl(ev.dormant_code, [['Severity', f => sev(f.severity)], ['Where', f => mono(`${f.file}:${f.line}`)], ['Code', f => mono(f.snippet)]])}` : ''}`],
    ['shots', 'Screenshots', d.shots.length, () => d.shots.length ? `<div class="film">${filmHtml(d.shots)}</div>` : '<div class="empty">No pages were opened during this scan</div>'],
    ['timeline', 'Timeline', scan.events.length, () => `<div class="two"><div><p class="label">AI investigator</p><div class="agent">${agentHtml(d.ai)}</div></div>
      <div><p class="label">Every event</p><div class="log" style="max-height:520px">${logHtml(scan.events)}</div></div></div>`],
  ];

  const personas = [...new Set(runs.map(r => parseRun(r).persona))];
  const clocks = [...new Set(runs.map(r => parseRun(r).clock))];
  const plate = runs.length ? `<div class="plate" style="--cols:${clocks.length}">
      <span class="ph corner top"></span>${clocks.map(c => `<span class="ph top">${esc(clockLabel(c))}</span>`).join('')}
      ${personas.map(p => `<span class="ph side">${esc(personaLabel(p))}</span>${clocks.map(c => {
        const m = ev.matrix[`${p}${c === '0' ? '' : c}`];
        if (!m) return '<div class="cell"><span class="n">–</span><span class="x">not run</span></div>';
        const lvl = m.honeytoken_hits >= 3 ? 'l3' : m.honeytoken_hits ? 'l2' : m.network ? 'l1' : 'l0';
        return `<div class="cell ${lvl}"><span class="n">${m.honeytoken_hits}</span><span class="x">${m.network} network, ${m.processes} processes</span></div>`;
      }).join('')}`).join('')}
    </div>
    <div class="legend"><span><i style="background:var(--card)"></i>Clean</span><span><i style="background:var(--ochre-wash)"></i>Network only</span><span><i style="background:rgba(163,36,27,.14)"></i>Read secrets</span></div>`
    : '<div class="empty">No runs recorded</div>';

  const cov = rep.rules?.coverage;
  const risk = rep.rules.risk_score;
  el.innerHTML = `
  <section class="verdict-hero">
    <div class="wrap">
      <div class="top">
        <div>
          <div class="pkg"><span>${kind}</span><span>Scanned ${esc(when)}</span><span class="tag">${esc(scan.id)}</span></div>
          <h1 class="pkg-title">${esc(name)}${t.version ? `<span class="ver">@${esc(t.version)}</span>` : ''}</h1>
          <p class="tagline">${esc(ai?.summary || VERDICT[v]?.line || '')}</p>
          <div class="actions">
            <button class="btn" id="share">${icon('link')}Copy link</button>
            <button class="btn quiet" id="rescan" ${scan.source.startsWith('upload:') ? 'disabled title="Upload the file again to re-scan it"' : ''}>${icon('refresh')}Re-scan</button>
            <a class="btn quiet" href="#/scan/${esc(scan.id)}">${icon('play')}Replay</a>
            <button class="btn quiet" id="dl">${icon('download')}JSON</button>
          </div>
        </div>
        <div class="stamp-slot">${stamp(v, { xl: true, land: true })}</div>
      </div>
    </div>
  </section>
  <div class="wrap" style="padding-bottom:96px">
    <div class="stats">
      <div class="stat ${risk >= 70 ? 'bad' : risk >= 30 ? 'warn' : ''}"><div class="k">Risk score</div><div class="v"><span data-count="${risk}">${risk}</span><small>of 100</small></div><div class="s">Set by ${rep.verdict_source === 'ai' ? 'the investigator, above the rules' : 'observed behaviour'}</div></div>
      <div class="stat"><div class="k">AI confidence</div>${conf != null ? `<div class="v"><span data-count="${conf}">${conf}</span>%</div><div class="s">The investigator says ${esc(ai.verdict)}</div>` : `<div class="v">–</div><div class="s">${rep.ai?.error ? 'The AI review failed' : 'Rules only, no AI configured'}</div>`}</div>
      <div class="stat ${secrets.size ? 'bad' : ''}"><div class="k">Secrets read</div><div class="v"><span data-count="${secrets.size}">${secrets.size}</span><small>kinds</small></div><div class="s">${runs.length ? `in ${hitRuns} of ${runs.length} runs` : 'No runs'}</div></div>
      <div class="stat ${exHosts.size ? 'bad' : ''}"><div class="k">Sent out</div><div class="v"><span data-count="${(ev.exfiltration || []).length}">${(ev.exfiltration || []).length}</span><small>times</small></div><div class="s">${exHosts.size ? `to ${esc([...exHosts].join(', '))}` : 'Nothing left the sandbox'}</div></div>
    </div>
    ${cov && !cov.executed ? `<div class="notice">${icon('info')}<div>Not enough coverage to call this safe: ${esc(cov.reason || '')}. The package’s own code never ran in the sandbox, so seeing nothing bad proves nothing.</div></div>` : ''}
    ${ai?.note ? `<div class="notice warn">${icon('alert')}<div>${esc(ai.note)}</div></div>` : ''}
    ${rep.ai?.error ? `<div class="notice warn">${icon('alert')}<div>The AI review did not run (${esc(rep.ai.error)}). The verdict is rule-based only.</div></div>` : ''}

    <div class="two" style="margin-top:16px">
      <section class="card" aria-labelledby="did-h">
        <div class="card-head"><h2 class="h4" id="did-h">What it tried to do</h2></div>
        ${ai?.recommendation ? `<p class="advice">${esc(ai.recommendation)}</p>` : ''}
        <div class="did">${items.map(i => `<div class="item ${i.sev}"><span class="ic">${icon(i.icon)}</span><div style="min-width:0"><div class="tt">${esc(i.title)}</div>${i.detail ? `<div class="dd">${esc(i.detail)}</div>` : ''}</div>${i.sev !== 'ok' ? `<span class="sev ${i.sev}">${i.sev === 'low' ? 'info' : i.sev}</span>` : ''}</div>`).join('')}</div>
        ${rep.rules.unresolved?.length ? `<p class="label" style="margin:24px 0 4px">Left unexplained</p><ul style="margin:0;padding-left:20px;color:var(--ink-2);font-size:14px">${rep.rules.unresolved.map(r => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
        ${rep.rules.reasons?.length ? `<p class="label" style="margin:24px 0 4px">Rule engine</p><ul style="margin:0;padding-left:20px;color:var(--ink-2);font-size:14px">${rep.rules.reasons.map(r => `<li>${esc(r)}</li>`).join('')}</ul>` : ''}
      </section>
      <section class="card" aria-labelledby="heat-h">
        <div class="card-head"><h2 class="h4" id="heat-h">Secrets read in each run</h2><span class="aside">${runs.length} runs</span></div>
        ${plate}
      </section>
    </div>

    <section class="card" style="margin-top:16px" aria-labelledby="ev-h">
      <div class="card-head" style="margin-bottom:8px"><h2 class="h4" id="ev-h">Evidence</h2></div>
      <div class="seg" role="tablist" aria-label="Evidence">${tabs.map(([k, label, n], i) => `<button role="tab" id="tab-${k}" aria-controls="panel" aria-selected="${i === 0}" data-tab="${k}">${label}${n ? `<span class="count">${n}</span>` : ''}</button>`).join('')}</div>
      <div class="tabpanel" id="panel" role="tabpanel"></div>
    </section>

    <section class="card" style="margin-top:16px" aria-labelledby="pin-h">
      <div class="card-head"><h2 class="h4" id="pin-h">What was scanned</h2></div>
      <dl class="kv">
        <dt>Source</dt><dd class="mono">${esc(scan.source)}</dd>
        ${t.pinned ? `<dt>Pinned version</dt><dd class="mono">${esc(t.pinned)}</dd>` : ''}
        ${t.commit ? `<dt>Commit</dt><dd class="mono">${esc(t.commit)}</dd>` : ''}
        ${t.sha256 ? `<dt>SHA-256</dt><dd class="mono"><span title="${esc(t.sha256)}">${esc(shortHash(t.sha256))}</span><button class="copy" id="cp-sha" aria-label="Copy SHA-256">${icon('copy')}</button></dd>` : ''}
        ${scan.lifecycle ? `<dt>Sandbox</dt><dd>${scan.lifecycle.destroyed ? 'Destroyed after the scan' : `Not fully removed: ${esc((scan.lifecycle.leftover || []).join(', '))}`}</dd>` : ''}
        ${Object.entries(rep.isolation || {}).map(([k, val]) => `<dt>${esc(k[0].toUpperCase() + k.slice(1))}</dt><dd>${esc(val)}</dd>`).join('')}
      </dl>
    </section>
  </div>`;

  const panel = $('#panel', el);
  const show = k => {
    el.querySelectorAll('[data-tab]').forEach(b => b.setAttribute('aria-selected', String(b.dataset.tab === k)));
    const tab = tabs.find(x => x[0] === k);
    panel.setAttribute('aria-labelledby', `tab-${k}`);
    panel.style.animation = 'none'; void panel.offsetWidth; panel.style.animation = '';
    panel.innerHTML = tab[3]();
    if (k === 'shots') bindFilm(panel, d.shots);
  };
  el.querySelectorAll('[data-tab]').forEach(b => b.onclick = () => show(b.dataset.tab));
  $('.seg', el).addEventListener('keydown', e => {
    if (!['ArrowLeft', 'ArrowRight'].includes(e.key)) return;
    const bs = [...el.querySelectorAll('[data-tab]')], i = bs.findIndex(b => b.getAttribute('aria-selected') === 'true');
    const n = bs[(i + (e.key === 'ArrowRight' ? 1 : bs.length - 1)) % bs.length]; n.focus(); show(n.dataset.tab);
  });
  // open the most telling tab first
  show(secrets.size ? 'secrets' : ai?.indicators?.length ? 'indicators' : (ev.requests?.length ? 'network' : 'indicators'));
  countUp(el);

  $('#share', el).onclick = () => copyText(location.href, 'Report link copied');
  $('#cp-sha', el)?.addEventListener('click', () => copyText(t.sha256, 'SHA-256 copied'));
  $('#dl', el).onclick = () => {
    const blob = new Blob([JSON.stringify({ id: scan.id, source: scan.source, created: scan.created, report: rep }, null, 2)], { type: 'application/json' });
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `vulture-${(t.pinned || scan.id).replace(/[^\w.@-]+/g, '_')}.json`; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  $('#rescan', el).onclick = async () => {
    try { const { id } = await api.createScan({ source: scan.source, force: true }); location.hash = `#/scan/${id}`; }
    catch (e) { toast(e.message); }
  };
}
