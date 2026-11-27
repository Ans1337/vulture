// The only module that talks to the backend. Views call these functions and never fetch() directly.
// Live mode uses the real API (api/app.py); demo mode replays scripted scans in the browser (mock.js).

import * as mock from './mock.js';
import { approvalsOf } from './model.js';

// Same storage keys as the classic dashboard, so both views see the same scans.
const TOKEN_KEY = 'vultureToken';
const NONCE_KEY = 'vultureNonce';
const FINAL = new Set(['done', 'failed', 'cancelled']);

export const state = { mode: 'live', reason: '', limits: null };
let askToken = async () => null;
export function onTokenNeeded(fn) { askToken = fn; }

class ApiError extends Error { constructor(msg, status) { super(msg); this.status = status; } }
const isMock = () => state.mode === 'mock';
const sentence = s => s ? s[0].toUpperCase() + s.slice(1) : s;

/** fetch with the instance access token (APP_TOKEN). A 401 that is not about the nonce asks for the token once. */
async function raw(path, opts = {}, retried = false) {
  const headers = { ...(opts.headers || {}) };
  const t = localStorage.getItem(TOKEN_KEY);
  if (t) headers.Authorization = `Bearer ${t}`;
  let r;
  try { r = await fetch(path, { ...opts, headers }); }
  catch { throw new ApiError('The Vulture API is not reachable. Check your connection', 0); }
  if (r.status === 401 && !retried) {
    const detail = (await r.clone().json().catch(() => ({}))).detail || '';
    if (!String(detail).includes('nonce')) {
      const v = await askToken();
      if (v) { localStorage.setItem(TOKEN_KEY, v); return raw(path, opts, true); }
    }
  }
  return r;
}

async function parse(r) {
  const text = await r.text();
  let body = null;
  try { body = text ? JSON.parse(text) : null; } catch { /* not JSON: a proxy error page or a static server */ }
  if (!r.ok) {
    const detail = body && (typeof body.detail === 'string' ? body.detail : body.detail?.[0]?.msg);
    throw new ApiError(sentence(detail) || `The request failed (${r.status})`, r.status);
  }
  if (body === null && text) throw new ApiError('Unexpected response from the API', r.status);
  return body;
}

/**
 * The personal key (nonce): every scan belongs to the key that created it. The server mints one, nothing
 * else stores it, and it lives only in this browser.
 */
let minting = null;
export const key = {
  valid: v => /^[A-Za-z0-9_-]{32,128}$/.test(v || ''),
  peek: () => localStorage.getItem(NONCE_KEY) || '',
  set: v => localStorage.setItem(NONCE_KEY, v),
  async get() {
    const have = key.peek();
    if (key.valid(have)) return have;
    minting ||= raw('/api/nonce', { method: 'POST' }).then(parse).then(j => { key.set(j.nonce); return j.nonce; }).finally(() => { minting = null; });
    return minting;
  },
};

async function req(path, opts = {}) {
  const headers = { ...(opts.headers || {}), 'X-Vulture-Nonce': await key.get() };
  return parse(await raw(path, { ...opts, headers }));
}

/** Decide between the live API and demo data. `?mock=1` forces demo data, `?mock=0` forces the live API. */
export async function init() {
  const q = new URLSearchParams(location.search);
  if (q.has('mock') && q.get('mock') !== '0') { state.mode = 'mock'; state.reason = 'demo'; return; }
  const forcedLive = q.get('mock') === '0';
  try {
    const t = localStorage.getItem(TOKEN_KEY);
    const r = await fetch('/api/limits', t ? { headers: { Authorization: `Bearer ${t}` } } : {});
    if (r.status === 401 || r.status === 429) { state.mode = 'live'; return; }
    const j = await r.json();
    if (!r.ok || typeof j !== 'object' || !('sandbox_mode' in j)) throw new Error('not the Vulture API');
    state.mode = 'live'; state.limits = j;
  } catch {
    if (forcedLive) { state.mode = 'live'; return; }
    state.mode = 'mock'; state.reason = 'offline';
  }
}

export function setMode(m) {
  location.href = location.pathname + (m === 'mock' ? '?mock=1' : '?mock=0') + location.hash;
}

export async function listScans({ limit = 200 } = {}) {
  if (isMock()) return mock.list();
  return req(`/api/scans?limit=${limit}`);
}

/** `after` is the id of the last event the caller already has, so polling only transfers new ones. */
export async function getScan(id, after = 0) {
  if (isMock()) return mock.get(id, after);
  return req(`/api/scans/${encodeURIComponent(id)}?after=${after}`);
}

/** Returns {id} or, for an exact version that was already scanned, {id, deduped: true}. `force` scans it again. */
export async function createScan({ source, file, force = false }) {
  if (isMock()) return mock.create({ source, file });
  const fd = new FormData();
  fd.append('source', source || '');
  if (force) fd.append('force', 'true');
  if (file) fd.append('file', file);
  return req('/api/scans', { method: 'POST', body: fd });
}

export async function cancelScan(id) {
  if (isMock()) return mock.cancel(id);
  return req(`/api/scans/${encodeURIComponent(id)}/cancel`, { method: 'POST' });
}

/**
 * Approvals ride on scan events (data.approval). The API has no approvals list or log yet, so live mode looks
 * at the running scans; demo data also carries an audit log.
 */
export async function listApprovals() {
  if (isMock()) return mock.approvals();
  const running = await req('/api/scans?status=running&limit=20');
  const pending = [];
  for (const s of running) {
    const full = await getScan(s.id);
    for (const a of approvalsOf(full.events)) if (a.state === 'pending') pending.push({ ...a, scan_id: s.id, source: s.source });
  }
  return { pending, log: null };
}

export async function decide(id, decision) {
  if (isMock()) return mock.decide(id, decision);
  return req(`/api/approvals/${encodeURIComponent(id)}/${decision}`, { method: 'POST' });
}

export function resetDemo() { mock.reset(); }

/** Follow one scan. Calls cb(scan) with every event so far, and stops by itself once the scan is final. */
export function watch(id, cb, onError) {
  let stopped = false, timer = null, events = [], last = 0;
  const poll = async () => {
    if (stopped) return;
    try {
      const s = await getScan(id, last);
      if (stopped) return;
      events = events.concat(s.events || []);
      last = events.length ? (events[events.length - 1].id ?? last) : last;
      cb({ ...s, events });
      if (FINAL.has(s.status)) return;
    } catch (e) {
      onError?.(e);
      if (e.status === 404 || e.status === 401) return;
    }
    timer = setTimeout(poll, isMock() ? 350 : 1200);
  };
  poll();
  return () => { stopped = true; clearTimeout(timer); };
}
