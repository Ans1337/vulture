import * as api from '../api.js';
import { $, esc, icon, patch } from '../ui.js';
import { rowHtml } from './landing.js';

const FILTERS = [
  ['all', 'All', () => true],
  ['malware', 'Malware', s => s.verdict === 'malware'],
  ['suspicious', 'Suspicious', s => s.verdict === 'suspicious'],
  ['safe', 'Safe', s => s.verdict === 'safe'],
  ['incomplete', 'Inconclusive', s => s.verdict === 'incomplete'],
  ['active', 'In progress', s => ['queued', 'running'].includes(s.status)],
  ['failed', 'Failed', s => s.status === 'failed'],
  ['cancelled', 'Cancelled', s => s.status === 'cancelled'],
];

export default function historyView(el) {
  const q = new URLSearchParams(location.hash.split('?')[1] || '');
  let filter = q.get('f') || 'all', text = '', list = null, timer = null;
  el.innerHTML = `<div class="page"><div class="wrap">
    <div class="page-head"><div><h1 class="h2">History</h1><p class="lead" id="sub">Every scan keeps a permanent report link</p></div>
      <a class="btn" href="#/">${icon('plus')}New scan</a></div>
    <div class="toolbar">
      <div class="search">${icon('search')}<label class="sr-only" for="q">Search scans</label><input id="q" type="search" placeholder="Search"></div>
      <div class="seg" role="tablist" aria-label="Filter by verdict" id="filters"></div>
    </div>
    <div id="list"><div class="list">${'<div class="skel-row"><div class="skel" style="height:28px;width:40%"></div></div>'.repeat(4)}</div></div>
  </div></div>`;

  const draw = () => {
    if (!list) return;
    const counts = Object.fromEntries(FILTERS.map(([k, , f]) => [k, list.filter(f).length]));
    patch($('#filters', el), FILTERS.filter(([k]) => k === 'all' || counts[k]).map(([k, label]) =>
      `<button role="tab" aria-selected="${k === filter}" data-f="${k}">${label}<span class="count">${counts[k]}</span></button>`).join(''));
    el.querySelectorAll('[data-f]').forEach(b => b.onclick = () => { filter = b.dataset.f; draw(); });
    const f = FILTERS.find(x => x[0] === filter)?.[2] || (() => true);
    const rows = list.filter(f).filter(s => !text || s.source.toLowerCase().includes(text));
    $('#sub', el).textContent = `${list.length} scan${list.length === 1 ? '' : 's'}, each with a permanent report link`;
    patch($('#list', el), rows.length ? `<div class="list">${rows.map(rowHtml).join('')}</div>`
      : list.length ? `<div class="empty-big">${icon('search')}<h3>No scans match</h3><p>Try another search or filter</p></div>`
      : `<div class="empty-big">${icon('history')}<h3>No scans yet</h3><p>Scan a package and it shows up here</p><p style="margin-top:24px"><a class="btn" href="#/">Scan a package</a></p></div>`);
  };

  const load = async () => {
    try { list = await api.listScans(); draw(); }
    catch (e) { patch($('#list', el), `<div class="empty-big">${icon('alert')}<h3>The scan list did not load</h3><p>${esc(e.message)}</p></div>`); }
    const busy = list?.some(s => ['queued', 'running'].includes(s.status));
    timer = setTimeout(load, busy ? 3000 : 15000);
  };
  $('#q', el).oninput = e => { text = e.target.value.trim().toLowerCase(); draw(); };
  load();
  return () => clearTimeout(timer);
}
