import * as api from '../api.js';
import { $, esc, icon, patch, dur, statusPill, copyText, toast, VERDICT, stamp } from '../ui.js';
import { derive } from '../model.js';
import { agentHtml, typeThought, runsHtml, filmHtml, bindFilm, logHtml } from './parts.js';

const VM_NODES = [['creating', 'Create', 'plus'], ['created', 'Boot', 'power'], ['ready', 'Ready', 'check'], ['destroyed', 'Destroyed', 'trash']];
const LIVE = ['queued', 'running'];

export default function scanView(el, id) {
  el.innerHTML = `
  <div class="page"><div class="wrap">
    <div class="scan-head">
      <div class="title">
        <p class="eyebrow" id="eyebrow">Scanning</p>
        <h1 class="pkg-title" id="name"><span class="skel" style="display:inline-block;width:320px;height:44px"></span></h1>
        <div class="meta" id="meta"></div>
      </div>
      <div class="actions">
        <button class="btn quiet sm" id="copy">${icon('link')} Copy link</button>
        <button class="btn quiet sm" id="cancel" hidden>${icon('x')} Cancel</button>
      </div>
    </div>
    <div id="finish"></div>
    <div id="gate"></div>
    <div class="stepper" id="stepper" role="list" aria-label="Pipeline"></div>
    <div class="live-grid">
      <div class="col">
        <section class="card" id="vm-card" hidden aria-labelledby="vm-h">
          <div class="card-head"><h2 class="h4" id="vm-h">${icon('server')} Throwaway Vultr VM</h2><span class="aside" id="vm-aside"></span></div>
          <div class="vm-strip" id="vm"></div><div class="vm-meta" id="vm-meta"></div>
        </section>
        <section class="card" aria-labelledby="runs-h">
          <div class="card-head"><h2 class="h4" id="runs-h">${icon('flask')} Detonation runs</h2><span class="aside" id="runs-aside"></span></div>
          <div class="runs" id="runs"></div>
        </section>
        <section class="card" aria-labelledby="ai-h">
          <div class="card-head"><h2 class="h4" id="ai-h">${icon('microscope')} AI investigator</h2><span class="aside">Vultr Inference</span></div>
          <div class="agent" id="ai" aria-live="polite"></div>
        </section>
        <section class="card" id="shots-card" hidden aria-labelledby="shots-h">
          <div class="card-head"><h2 class="h4" id="shots-h">${icon('camera')} Screenshot trail</h2><span class="aside" id="shots-aside"></span></div>
          <div class="film" id="shots"></div>
        </section>
      </div>
      <aside class="side">
        <section class="card" aria-labelledby="log-h">
          <div class="card-head"><h2 class="h4" id="log-h">${icon('terminal')} Activity</h2><span class="aside" id="log-aside"></span></div>
          <div class="log" id="log" tabindex="0" aria-label="Scan activity log"></div>
        </section>
      </aside>
    </div>
  </div></div>`;

  let scan = null, aiCount = -1, stopType = () => {}, gateFor = null, tick = null, wasLive = false;

  $('#copy', el).onclick = () => copyText(location.href, 'Link copied');
  $('#cancel', el).onclick = async () => {
    try { await api.cancelScan(id); toast('Cancelling the scan'); }
    catch (e) { toast(e.message); }
  };

  const render = () => {
    if (!scan) return;
    const d = derive(scan);
    const live = LIVE.includes(scan.status);
    const gate = live ? d.approvals.find(a => a.state === 'pending') : null;
    if (live) wasLive = true;
    const elapsed = live ? Date.now() / 1000 - scan.created : d.elapsed;
    const rep = scan.report, v = rep?.verdict;

    $('#eyebrow', el).textContent = live ? (gate ? 'Paused for approval' : scan.status === 'queued' ? 'Queued' : 'Scanning') : scan.status === 'done' ? 'Scan finished' : 'Scan stopped';
    patch($('#name', el), esc(scan.source.replace(/^upload:/, '').replace(/^https:\/\/github\.com\//, '')));
    patch($('#meta', el), `${statusPill(scan)}<span class="clock" id="clock">${dur(elapsed)}</span><span class="tag">${esc(scan.id)}</span>`);
    $('#cancel', el).hidden = !live;

    // verdict reveal
    if (scan.status === 'done' && rep) {
      const ai = rep.ai && !rep.ai.error ? rep.ai : null;
      patch($('#finish', el), `<div class="finish${wasLive ? ' thud' : ''}" role="status">
        ${stamp(v, { land: wasLive })}
        <div class="txt">${esc(ai?.summary || VERDICT[v]?.line || '')}</div>
        <a class="btn" href="#/report/${esc(scan.id)}">Open report ${icon('arrow')}</a></div>`);
    } else if (scan.status === 'failed' || scan.status === 'cancelled') {
      patch($('#finish', el), `<div class="finish" role="alert">
        <div class="fail-title">${scan.status === 'failed' ? 'Scan failed' : 'Scan cancelled'}</div>
        <div class="txt mono">${esc(scan.error || '')}</div>
        <a class="btn quiet" href="#/">Scan something else</a></div>`);
    } else patch($('#finish', el), '');

    drawGate(gate);

    $('#stepper', el).style.gridTemplateColumns = `repeat(${d.stages.length}, 1fr)`;
    patch($('#stepper', el), d.stages.map(s => `<div class="s ${s.state}" role="listitem" aria-current="${s.state === 'on' ? 'step' : 'false'}">
      <span class="knob">${icon(s.state === 'fail' ? 'x' : 'check')}</span><span class="lbl">${s.label.replace(' scan', '')}${s.retries ? `<span class="retry" title="Retried ${s.retries} time${s.retries > 1 ? 's' : ''}">retried ${s.retries}×</span>` : ''}</span></div>`).join(''));

    // VM lifecycle (only when the scan runs on a throwaway Vultr VM)
    if (d.vm) {
      $('#vm-card', el).hidden = false;
      const cur = d.vm.current, failed = cur === 'destroy_failed';
      const idx = failed ? 3 : VM_NODES.findIndex(n => n[0] === cur);
      patch($('#vm', el), VM_NODES.map(([st, label, ic], i) => {
        const last = st === 'destroyed';
        const cls = last && failed ? 'fail' : last && cur === 'destroyed' ? 'gone' : i < idx ? 'done' : i === idx ? 'now' : '';
        return `${i ? `<div class="bar ${i <= idx ? 'on' : ''}"></div>` : ''}<div class="n ${cls}"><div class="d">${icon(last && failed ? 'x' : ic)}</div><span>${last && failed ? 'Destroy failed' : label}</span></div>`;
      }).join(''));
      patch($('#vm-meta', el), d.vm.id ? `<span>Instance <b class="mono">${esc(d.vm.id)}</b></span>` : '');
      $('#vm-meta', el).hidden = !d.vm.id;
      patch($('#vm-aside', el), cur === 'destroyed' ? 'destroyed, nothing left behind' : failed ? 'the janitor will retry' : '');
    }

    // runs
    const clocks = new Set([...d.runs.values()].map(r => r.clock));
    $('#runs', el).style.gridTemplateColumns = `repeat(${Math.max(1, Math.min(clocks.size || 2, 3))}, minmax(0, 1fr))`;
    patch($('#runs', el), runsHtml(d.runs));
    const doneRuns = [...d.runs.values()].filter(r => r.state === 'done').length;
    patch($('#runs-aside', el), d.runs.size ? `${doneRuns}/${d.runs.size} done` : '');

    // AI investigator
    if (d.ai.length !== aiCount) {
      stopType();
      const fresh = live && d.ai.length > Math.max(aiCount, 0) ? d.ai.length - 1 : -1;
      patch($('#ai', el), d.ai.length ? agentHtml(d.ai, { fresh }) : `<div class="empty">${esc(d.aiNote ? d.aiNote[0].toUpperCase() + d.aiNote.slice(1) : 'The investigator starts once the traces are in')}</div>`);
      stopType = fresh >= 0 ? typeThought($('#ai', el), d.ai, fresh) : () => {};
      aiCount = d.ai.length;
    } else if (!d.ai.length && d.aiNote) {
      patch($('#ai', el), `<div class="empty">${esc(d.aiNote[0].toUpperCase() + d.aiNote.slice(1))}</div>`);
    }

    // screenshots
    if (d.shots.length) {
      $('#shots-card', el).hidden = false;
      if (patch($('#shots', el), filmHtml(d.shots))) bindFilm($('#shots', el), d.shots);
      patch($('#shots-aside', el), `${d.shots.length} page${d.shots.length > 1 ? 's' : ''}, read by a vision model`);
    }

    // log, keeping the reader's scroll position unless they are at the bottom
    const log = $('#log', el), atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
    if (patch(log, logHtml(scan.events)) && atBottom) log.scrollTop = log.scrollHeight;
    patch($('#log-aside', el), live ? '<span class="pill running"><span class="dot"></span>Live</span>' : `${scan.events.length} events`);
  };

  // Approval gate: the scan waits until a person approves or rejects a risky step (data.approval on an event).
  function drawGate(ap) {
    const key = ap ? ap.id : '';
    if (gateFor === key) return;
    gateFor = key;
    if (!ap) { patch($('#gate', el), ''); return; }
    patch($('#gate', el), `<div class="gate" role="alert">
      <div class="gi">${icon(ap.kind === 'spend' ? 'coins' : ap.kind === 'publish_verdict' ? 'megaphone' : 'zap')}</div>
      <div class="gt"><b>${esc(ap.title || 'Approval needed')}</b><span>${esc(ap.detail || '')}</span></div>
      <div class="ga"><button class="btn quiet" data-dec="reject">Reject</button><button class="btn" data-dec="approve">Approve</button></div></div>`);
    $('#gate', el).querySelectorAll('[data-dec]').forEach(b => b.onclick = async () => {
      $('#gate', el).querySelectorAll('[data-dec]').forEach(x => { x.disabled = true; });
      try {
        await api.decide(ap.id, b.dataset.dec);
        toast(b.dataset.dec === 'approve' ? 'Approved, the scan continues' : 'Rejected, the scan continues without it');
        window.dispatchEvent(new Event('vulture:approvals-changed'));
      } catch (e) { toast(e.message); $('#gate', el).querySelectorAll('[data-dec]').forEach(x => { x.disabled = false; }); }
    });
  }

  const stop = api.watch(id, s => { scan = s; render(); }, e => {
    if (e.status === 404) el.innerHTML = notFound(id);
  });
  tick = setInterval(() => {
    if (scan && LIVE.includes(scan.status)) {
      const c = $('#clock', el); if (c) c.textContent = dur(Date.now() / 1000 - scan.created);
    }
  }, 1000);
  return () => { stop(); stopType(); clearInterval(tick); };
}

export const notFound = id => `<div class="wrap"><div class="empty-big">${icon('search')}<h3>No scan with the ID ${esc(id)}</h3>
  <p>It may have been made before scans were stored permanently, or the link is mistyped</p>
  <p style="margin-top:24px"><a class="btn" href="#/">Start a new scan</a></p></div></div>`;
