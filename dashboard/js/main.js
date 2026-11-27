// Hash router + app chrome (nav state, demo-mode pill, approvals badge, access-token sheet).

import * as api from './api.js';
import { $, $$, sheet, swap, copyText } from './ui.js';
import landing from './views/landing.js';
import scanView from './views/scan.js';
import reportView from './views/report.js';
import historyView from './views/history.js';
import approvalsView from './views/approvals.js';

const routes = [
  [/^\/?$/, landing, 'home', 'Vulture · See what a package steals before you install it'],
  [/^\/scan\/([\w-]+)$/, scanView, 'home', 'Scanning · Vulture'],
  [/^\/report\/([\w-]+)$/, reportView, 'history', 'Report · Vulture'],
  [/^\/history$/, historyView, 'history', 'History · Vulture'],
  [/^\/approvals$/, approvalsView, 'approvals', 'Approvals · Vulture'],
];

let cleanup = null;

function route() {
  let path = location.hash.replace(/^#/, '').split('?')[0];
  if (/^[0-9a-f]{10}$/.test(path)) { location.replace(`#/scan/${path}`); return; } // links from the classic UI
  const app = $('#app');
  cleanup?.(); cleanup = null;
  let hit = routes.find(([re]) => re.test(path));
  if (!hit) hit = routes[0], path = '/';
  const [re, view, nav, title] = hit;
  const params = path.match(re).slice(1);
  document.title = title;
  $$('[data-nav]').forEach(a => a.dataset.nav === nav ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current'));
  swap(() => {
    app.innerHTML = '';
    window.scrollTo(0, 0);
    cleanup = view(app, ...params) || null;
  });
}

async function refreshBadge() {
  try {
    const { pending } = await api.listApprovals();
    const b = $('#appr-badge');
    b.innerHTML = pending.length ? `<span class="nav-badge" aria-label="${pending.length} waiting">${pending.length}</span>` : '';
  } catch { /* the badge is best-effort */ }
}

/** "Your key": the personal key that owns your scans. Show it, copy it, or paste one from another device. */
async function keySheet() {
  const { close, el } = sheet(`
    <h2>Your key</h2>
    <p>Scans belong to the key that started them, and nobody can list or open them without it. It lives only in this browser and cannot be recovered, so save it somewhere. Paste a key from another device to see the scans made there.</p>
    <form id="key-f"><label class="sr-only" for="key-in">Personal key</label>
      <input id="key-in" autocomplete="off" spellcheck="false" placeholder="Loading">
      <p class="scan-error" id="key-err" role="alert"></p>
      <div class="row"><button type="button" class="btn quiet sm" id="key-copy" style="margin-right:auto">Copy</button><button type="button" class="btn quiet sm" id="key-x">Close</button><button class="btn sm">Use this key</button></div>
    </form>`);
  const input = el.querySelector('#key-in'), err = el.querySelector('#key-err');
  api.key.get().then(k => { input.value = k; }).catch(e => { input.placeholder = ''; err.textContent = e.message; });
  el.querySelector('#key-x').onclick = close;
  el.querySelector('#key-copy').onclick = () => copyText(input.value, 'Key copied');
  el.querySelector('#key-f').onsubmit = e => {
    e.preventDefault();
    const v = input.value.trim();
    if (!api.key.valid(v)) { err.textContent = 'A key is 32 to 128 letters, digits, - or _'; return; }
    api.key.set(v); close(); route(); refreshBadge();
  };
}

function tokenSheet() {
  return new Promise(resolve => {
    let done = false;
    const { close, el } = sheet(`
      <h2>Access token</h2>
      <p>This Vulture is private. Paste the token your team shared with you. It stays in this browser.</p>
      <form id="tok-f"><label class="sr-only" for="tok">Access token</label>
        <input id="tok" type="password" autocomplete="off" spellcheck="false" placeholder="Access token" required>
        <div class="row"><button type="button" class="btn quiet sm" id="tok-x">Cancel</button><button class="btn sm">Continue</button></div>
      </form>`, { onClose: () => { if (!done) resolve(null); } });
    el.querySelector('#tok-x').onclick = close;
    el.querySelector('#tok-f').onsubmit = e => { e.preventDefault(); done = true; const v = el.querySelector('#tok').value.trim(); close(); resolve(v || null); };
  });
}

let tokenPromise = null;
api.onTokenNeeded(() => (tokenPromise ||= tokenSheet().finally(() => { tokenPromise = null; })));

async function start() {
  await api.init();
  if (api.state.mode === 'mock') {
    $('#mode-pill').innerHTML = `<button class="nav-pill" id="mode-btn" title="${api.state.reason === 'offline' ? 'No API answered, showing demo scans' : 'Showing demo scans'}">Demo data</button>`;
    $('#mode-btn').onclick = () => {
      const { close, el } = sheet(`<h2>Demo data</h2><p>${api.state.reason === 'offline' ? 'No Vulture API answered, so' : 'You turned on demo mode, so'} these scans are scripted replays that run in your browser. They include features the backend is still building.</p>
        <div class="row"><button class="btn quiet sm" id="m-reset" style="margin-right:auto">Reset demo</button><button class="btn quiet sm" id="m-live">Use live API</button><button class="btn sm" id="m-ok">Keep demo</button></div>`);
      el.querySelector('#m-ok').onclick = close;
      el.querySelector('#m-live').onclick = () => api.setMode('live');
      el.querySelector('#m-reset').onclick = () => { api.resetDemo(); close(); location.hash = '#/'; location.reload(); };
    };
  }
  const keyBtn = $('#key-btn');
  keyBtn.hidden = api.state.mode === 'mock';
  keyBtn.onclick = e => { e.preventDefault(); keySheet(); };
  window.addEventListener('hashchange', () => { route(); refreshBadge(); });
  route();
  refreshBadge();
  // Demo data is free to poll. On the live API approvals are found by reading running scans, so only look on navigation.
  if (api.state.mode === 'mock') setInterval(() => { if (!document.hidden) refreshBadge(); }, 4000);
}

window.addEventListener('vulture:approvals-changed', refreshBadge);
start();
