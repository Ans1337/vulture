// Pieces shared by the live scan view and the report.

import { esc, icon, dur, personaLabel, clockLabel, lightbox } from '../ui.js';

const TOOL_ICON = { rerun: 'refresh', read_file: 'file', grep: 'search', list_files: 'fileSearch' };

export function agentHtml(steps, { fresh = -1 } = {}) {
  if (!steps.length) return `<div class="empty">The investigator starts once the traces are in</div>`;
  return steps.map((s, i) => `
    <div class="stp ${s.final ? 'verdict' : ''} ${i === fresh ? 'new' : ''}">
      <div class="ic">${icon(s.final ? 'check' : TOOL_ICON[s.tool] || 'microscope')}</div>
      <div style="min-width:0">
        <span class="call">${s.final ? 'conclusion' : `${esc(s.tool)}(${esc(s.args)})`}</span>
        <p class="thought" data-i="${i}">${i === fresh ? '' : esc(s.thought)}</p>
        ${s.result ? `<p class="res" ${i === fresh ? 'hidden' : ''}>${esc(s.result)}</p>` : ''}
      </div>
    </div>`).join('');
}

/** Typewriter for the newest agent thought. Returns a cancel function. */
export function typeThought(root, steps, i) {
  const p = root.querySelector(`.thought[data-i="${i}"]`);
  if (!p) return () => {};
  const full = steps[i].thought || '';
  const res = p.parentElement.querySelector('.res');
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) { p.textContent = full; if (res) res.hidden = false; return () => {}; }
  let n = 0; p.classList.add('caret');
  const t = setInterval(() => {
    n = Math.min(full.length, n + 2);
    p.textContent = full.slice(0, n);
    if (n >= full.length) { clearInterval(t); p.classList.remove('caret'); if (res) res.hidden = false; }
  }, 16);
  return () => { clearInterval(t); p.textContent = full; p.classList.remove('caret'); if (res) res.hidden = false; };
}

export function runsHtml(runs) {
  const list = [...runs.values()];
  if (!list.length) return `<div class="empty">Runs appear once the sandbox is up</div>`;
  return list.map(r => {
    const done = r.state === 'done';
    const cls = [r.state === 'wait' ? 'wait' : r.state, r.hits ? 'hit' : done && r.net ? 'netonly' : done ? 'clean' : ''].join(' ');
    const badge = !done ? '' : r.hits ? '<span class="badge bad">read secrets</span>'
      : r.net ? '<span class="badge warn">network only</span>' : '<span class="badge ok">clean</span>';
    return `<div class="run ${cls}">
      <div class="top">
        <div class="who">${esc(personaLabel(r.persona))}</div>
        ${r.retries ? `<span class="badge warn" title="Retried ${r.retries} time${r.retries > 1 ? 's' : ''}">retried ${r.retries}×</span>` : ''}
        ${r.state === 'running' ? '<span class="spinner" aria-label="running"></span>' : badge}
      </div>
      <div class="when">${esc(clockLabel(r.clock))}</div>
      <div class="now">${esc(r.now)}</div>
      <div class="nums">
        <div><b class="h">${r.state === 'wait' ? '–' : r.hits}</b>secrets</div>
        <div><b>${r.state === 'wait' ? '–' : r.net}</b>network</div>
        <div><b>${r.state === 'wait' ? '–' : r.procs}</b>processes</div>
      </div>
    </div>`;
  }).join('');
}

export function filmHtml(shots) {
  return shots.map((s, i) => `<button type="button" data-shot="${i}" aria-label="Open screenshot of ${esc(s.url)}">
    <img src="${esc(s.image)}" alt="Screenshot of ${esc(s.url)}" loading="lazy">
    <div class="cap"><b>${esc(s.url)}</b>${esc(s.caption || '')}</div></button>`).join('');
}

export function bindFilm(root, shots) {
  root.querySelectorAll('[data-shot]').forEach(b => b.onclick = () => {
    const s = shots[+b.dataset.shot]; lightbox(s.image, s.url, s.caption);
  });
}

// Short names so the stage column stays narrow: "investigate" does not fit next to the message.
const LOG_STAGE = { investigate: 'agent', analyze: 'verdict' };

/** Red only for what went wrong or what the package did: never for words that merely appear in a path or a tool call. */
function isBad(e) {
  const d = e.data || {}, msg = e.msg || '';
  if (d.vm === 'destroy_failed' || d.limit_hit || (d.lifecycle && d.lifecycle.destroyed === false)) return true;
  if (d.honeytoken_hits > 0) return true;
  if (d.tool || d.retry) return false; // investigator steps quote code and paths; a retry is not a failure
  return /^verdict: (MALWARE|SUSPICIOUS)\b/.test(msg) || /\bFAILED\b/.test(msg) || /[1-9]\d* honeytoken hits/.test(msg);
}

export function logHtml(events) {
  if (!events.length) return '<div class="empty">Waiting for the first event</div>';
  return events.map(e => {
    const vm = typeof e.data?.vm === 'string';
    const cls = isBad(e) ? 'bad' : e.stage === 'investigate' || vm ? 'ai' : '';
    const stage = vm ? 'vm' : LOG_STAGE[e.stage] || e.stage;
    return `<div class="l ${cls}"><span class="t">${dur(e.t)}</span><span class="st" title="${esc(e.stage)}">${esc(stage)}</span><span class="m">${esc(e.msg)}</span></div>`;
  }).join('');
}
