import * as api from '../api.js';
import { $, esc, icon, patch, toast, ago } from '../ui.js';

const KIND = {
  live_internet: { icon: 'zap', label: 'Live internet' },
  publish_verdict: { icon: 'megaphone', label: 'Publish verdict' },
  spend: { icon: 'coins', label: 'Spending' },
};
const left = s => { s = Math.max(0, Math.round(s)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; };

export default function approvalsView(el) {
  let data = null, timer = null, tick = null;
  el.innerHTML = `<div class="page"><div class="wrap">
    <div class="page-head"><div><h1 class="h2">Approvals</h1>
      <p class="lead">Some steps cannot be undone, so the scan pauses until a person approves them</p></div></div>
    <div id="pending"></div>
    <h2 class="h3" style="margin:64px 0 16px">Audit log</h2>
    <div id="log"></div>
  </div></div>`;

  const draw = () => {
    if (!data) return;
    const now = Date.now() / 1000;
    patch($('#pending', el), data.pending.length ? `<div class="approvals">${data.pending.map(a => `
        <article class="appr" aria-labelledby="ap-${esc(a.id)}">
          <div class="ai ${esc(a.kind)}">${icon(KIND[a.kind]?.icon || 'alert')}</div>
          <div style="min-width:0">
            <h3 id="ap-${esc(a.id)}">${esc(a.title)}</h3>
            <p class="d">${esc(a.detail)}</p>
            <div class="m"><a href="#/scan/${esc(a.scan_id)}">${esc(a.source || a.scan_id)}</a>
              ${KIND[a.kind] ? `<span>${KIND[a.kind].label}</span>` : ''}
              ${a.requested_at ? `<span>Asked by the ${esc(a.requested_by || 'investigator')}, ${ago(a.requested_at)}</span>` : ''}
              ${a.expires_at ? `<span class="timer" data-exp="${a.expires_at}">Rejects itself in ${left(a.expires_at - now)}</span>` : ''}</div>
          </div>
          <div class="btns">
            <button class="btn quiet" data-id="${esc(a.id)}" data-dec="reject">Reject</button>
            <button class="btn" data-id="${esc(a.id)}" data-dec="approve">Approve</button>
          </div>
        </article>`).join('')}</div>`
      : `<div class="card"><div class="empty-big" style="padding:32px 0">${icon('inbox')}<h3>Nothing is waiting</h3><p>When the investigator wants to do something risky, it asks here first</p></div></div>`);
    el.querySelectorAll('[data-dec]').forEach(b => b.onclick = async () => {
      el.querySelectorAll(`[data-id="${CSS.escape(b.dataset.id)}"]`).forEach(x => x.disabled = true);
      try {
        await api.decide(b.dataset.id, b.dataset.dec);
        toast(b.dataset.dec === 'approve' ? 'Approved, the scan continues' : 'Rejected');
        window.dispatchEvent(new Event('vulture:approvals-changed'));
        load();
      } catch (e) { toast(e.message); load(); }
    });
    patch($('#log', el), !data.log ? '<div class="empty">The API does not keep a log of approvals yet, so past decisions are not listed here</div>' : data.log.length ? `<div class="card"><div class="tbl-wrap"><table class="tbl">
      <thead><tr><th scope="col">When</th><th scope="col">Action</th><th scope="col">Package</th><th scope="col">Decision</th><th scope="col">By</th></tr></thead>
      <tbody>${data.log.map(a => `<tr>
        <td class="nowrap muted">${ago(a.decided_at || a.requested_at)}</td>
        <td>${esc(a.title)}</td>
        <td><a class="mono" href="#/scan/${esc(a.scan_id)}">${esc(a.source || a.scan_id)}</a></td>
        <td><span class="pill ${a.state === 'approved' ? 'safe' : a.state === 'expired' ? '' : 'malware'}"><span class="dot"></span>${esc(a.state[0].toUpperCase() + a.state.slice(1))}</span></td>
        <td>${esc(a.decided_by || (a.state === 'expired' ? 'timeout' : '–'))}</td></tr>`).join('')}</tbody></table></div></div>`
      : '<div class="empty">No decisions yet</div>');
  };

  const load = async () => {
    clearTimeout(timer);
    try { data = await api.listApprovals(); draw(); }
    catch (e) { patch($('#pending', el), `<div class="notice bad">${icon('alert')}<div>${esc(e.message)}</div></div>`); }
    timer = setTimeout(load, api.state.mode === 'mock' ? 4000 : 20000);
  };
  tick = setInterval(() => el.querySelectorAll('[data-exp]').forEach(t => { t.textContent = `Rejects itself in ${left(+t.dataset.exp - Date.now() / 1000)}`; }), 1000);
  load();
  return () => { clearTimeout(timer); clearInterval(tick); };
}
