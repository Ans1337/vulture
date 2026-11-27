// Turns a raw scan (events + report) into what the views draw. Event shapes are the ones api/ emits:
//   data.vm          "creating" | "created" | "ready" | "destroyed" | "destroy_failed"   (api/vultr.py)
//   data.run         run name such as "developer" or "ci+90d", with honeytoken_hits when it finishes (worker)
//   stage investigate, data.tool / data.args / data.thought, then data.stop_reason + data.conclusion (api/investigator.py)
//   data.retry       attempt counter on whatever was retried
//   data.lifecycle   what the teardown removed (api/lifecycle.py)
//   data.limits      the resource caps, announced before the fetch (api/orchestrator.py)
// and three the backend does not send yet, drawn as soon as they appear:
//   data.screenshot (+ url, vision), data.approval {id, title, detail, state}, data.run with state "running" | "done"

import { parseRun } from './ui.js';

export const STAGES = ['fetch', 'static', 'sandbox', 'detonate', 'observe', 'investigate', 'destroy', 'analyze'];
export const STAGE_INFO = {
  fetch: { label: 'Fetch', text: 'Download the package and pin its exact version and hash, without running anything' },
  static: { label: 'Static scan', text: 'Read the source for install hooks, obfuscation and code that reaches for secrets' },
  sandbox: { label: 'Sandbox', text: 'Boot a throwaway Vultr machine and stock it with fake secrets and a fake internet' },
  detonate: { label: 'Detonate', text: 'Install and run it as a developer laptop and as a CI runner, today and 90 days from now' },
  observe: { label: 'Observe', text: 'Trace every process, file and socket it touched, and every request the fake internet caught' },
  investigate: { label: 'Investigate', text: 'An AI investigator reads the code, searches it and re-runs whatever looks gated' },
  destroy: { label: 'Destroy', text: 'Delete the machine with everything on it, and check that it is gone' },
  analyze: { label: 'Verdict', text: 'Rules set the floor from observed behaviour, and the AI can only raise it to suspicious' },
};

const runSummary = r => r.hits ? `Touched ${r.hits} planted secret${r.hits > 1 ? 's' : ''}` : r.net ? `${r.net} network call${r.net > 1 ? 's' : ''}, no secrets touched` : 'Clean run';
const fmtArgs = a => !a ? '' : typeof a === 'string' ? a : Object.entries(a).map(([k, v]) => `${k}=${String(v).slice(0, 80)}`).join(', ');

/** Latest state of every approval mentioned in the events. */
export function approvalsOf(events) {
  const m = {};
  for (const e of events || []) if (e.data?.approval?.id) m[e.data.approval.id] = { ...m[e.data.approval.id], ...e.data.approval };
  return Object.values(m);
}

export function derive(scan) {
  const events = scan.events || [];
  const rep = scan.report;
  const stageIds = scan.stages?.length ? scan.stages : STAGES;
  const out = {
    stages: [], runs: new Map(), vm: null, ai: [], aiNote: '', shots: [], approvals: approvalsOf(events), lifecycle: scan.lifecycle || null,
    elapsed: events.length ? events[events.length - 1].t : 0,
  };

  // persona × clock grid: announced by the sandbox event, otherwise built as runs appear
  const sandboxEv = events.find(e => Array.isArray(e.data?.personas));
  const blank = (name, persona, clock) => ({ name, persona, clock, state: 'wait', now: 'Waiting', hits: 0, net: 0, procs: 0, retries: 0 });
  if (sandboxEv) {
    for (const p of sandboxEv.data.personas) for (const c of (sandboxEv.data.clocks || ['0'])) {
      const name = `${p}${c === '0' ? '' : c}`;
      out.runs.set(name, blank(name, p, c));
    }
  }
  const run = name => {
    if (!out.runs.has(name)) { const { persona, clock } = parseRun(name); out.runs.set(name, blank(name, persona, clock)); }
    return out.runs.get(name);
  };

  const retryByStage = {};
  for (const e of events) {
    const d = e.data || {};
    if (typeof d.vm === 'string') {
      out.vm ||= { seen: new Set(), id: '' };
      out.vm.seen.add(d.vm); out.vm.current = d.vm;
      out.vm.id = d.vm_report?.vm_id || (/\(([0-9a-f-]{6,})\)/.exec(e.msg || '') || [])[1] || out.vm.id;
    }
    if (d.lifecycle) out.lifecycle = d.lifecycle;
    if (d.screenshot) out.shots.push({ image: d.screenshot, url: d.url || '', caption: d.vision || '' });
    if (e.stage === 'investigate') {
      if (d.tool) out.ai.push({ tool: d.tool, args: fmtArgs(d.args), thought: d.thought || '', result: d.result || '' });
      else if (d.stop_reason) {
        const c = d.conclusion;
        out.ai.push({ final: true, thought: e.msg, result: c ? `Leaning ${c.leaning}${c.unexplained?.length ? `, ${c.unexplained.length} question${c.unexplained.length > 1 ? 's' : ''} left open` : ', nothing left unexplained'}` : '' });
      } else if (!d.retry && !d.approval) out.aiNote = e.msg;
    }
    if (d.retry && !d.run) retryByStage[e.stage] = Math.max(retryByStage[e.stage] || 0, +d.retry || 1);
    if (d.run) {
      const r = run(d.run);
      if (d.retry) r.retries = +d.retry || r.retries + 1;
      if ('honeytoken_hits' in d || d.state === 'done') {
        r.state = 'done'; r.hits = d.honeytoken_hits ?? r.hits;
        const m = /(\d+) network calls/.exec(e.msg || '');
        r.net = d.network ?? (m ? +m[1] : r.net);
        r.procs = d.processes ?? r.procs;
        r.now = runSummary(r);
      } else if (!d.retry) {
        r.state = 'running';
        r.now = (e.msg || '').replace(/^run [^:]+:\s*/, '').replace(/^./, c => c.toUpperCase());
      }
    }
  }
  // final numbers come from the report when there is one
  if (rep?.evidence?.matrix) {
    for (const [name, m] of Object.entries(rep.evidence.matrix)) {
      const r = run(name);
      Object.assign(r, { state: 'done', hits: m.honeytoken_hits, net: m.network, procs: m.processes });
      r.now = runSummary(r);
    }
  }

  // The furthest pipeline stage reached. Setting the sandbox up (booting a VM, announcing the resource limits)
  // is tagged "sandbox" but happens before the fetch, so those events don't move the pipeline forward. A scan
  // that fails or is cancelled still tears its sandbox down, so for those the stage it stopped in is the
  // furthest one before "destroy".
  const stopped = scan.status === 'failed' || scan.status === 'cancelled';
  const setup = e => typeof e.data?.vm === 'string' || !!e.data?.limits;
  let cur = -1;
  for (const e of events) {
    if (e.stage === 'destroy' ? stopped : setup(e)) continue;
    cur = Math.max(cur, stageIds.indexOf(e.stage));
  }
  // Only setup has happened so far: nothing before "sandbox" may be shown as done.
  const settingUp = scan.status !== 'done' && cur < 0 && events.some(setup);
  if (cur < 0) cur = stopped ? 0 : stageIds.indexOf(scan.stage);
  if (scan.status === 'done') cur = stageIds.length;
  // "destroy" is only done when a teardown reports it: a restart also logs under this stage, without removing anything
  const destroyed = events.some(e => e.data?.lifecycle?.destroyed || e.data?.vm === 'destroyed');
  stageIds.forEach((id, i) => {
    let state = i < cur ? 'done' : i === cur ? (stopped ? 'fail' : 'on') : 'todo';
    if (settingUp) state = id === 'sandbox' ? (stopped ? 'fail' : 'on') : 'todo';
    if (stopped && id === 'destroy') state = destroyed ? 'done' : 'todo';
    out.stages.push({ id, label: STAGE_INFO[id]?.label || id, state, retries: retryByStage[id] || 0 });
  });
  return out;
}

const SECRET_KINDS = [
  [/\.aws\/credentials/, 'AWS access keys', 'key'],
  [/\.npmrc/, 'npm publish token', 'key'],
  [/\.ssh\/id_/, 'SSH private key', 'lock'],
  [/\.git-credentials/, 'Git credentials', 'github'],
  [/solana|ethereum|wallet/i, 'Crypto wallet', 'wallet'],
  [/\.docker\/config/, 'Docker registry login', 'package'],
  [/\.kube\/config/, 'Kubernetes cluster token', 'server'],
  [/\.env$/, 'Project .env secrets', 'file'],
  [/\.bash_history/, 'Shell history', 'terminal'],
];

export function secretKind(file) {
  for (const [re, label, ic] of SECRET_KINDS) if (re.test(file)) return { label, icon: ic };
  return { label: file.split('/').pop(), icon: 'file' };
}

export const prettyPath = f => String(f || '').replace(/^\/tmp\/runs\/[^/]+/, '').replace(/^\/home\/(alice|runner|deploy)/, '~');

/** Plain-English list of what the package tried to do, most serious first. */
export function describe(rep) {
  const ev = rep.evidence || {}, items = [];
  const runs = Object.keys(ev.matrix || {});
  const kinds = new Map();
  for (const h of ev.honeytoken_access || []) {
    const k = secretKind(h.file);
    const e = kinds.get(k.label) || { ...k, files: new Set(), runs: new Set() };
    e.files.add(prettyPath(h.file)); e.runs.add(h.run); kinds.set(k.label, e);
  }
  if (kinds.size) {
    items.push({ sev: 'high', icon: 'key', title: `Read ${kinds.size} kind${kinds.size > 1 ? 's' : ''} of secrets: ${[...kinds.keys()].join(', ')}`,
      detail: [...new Set([...kinds.values()].flatMap(k => [...k.files]))].join(' · ') });
  }
  const ex = ev.exfiltration || [];
  if (ex.length) {
    const hosts = [...new Set(ex.map(x => x.host || x.sni))];
    const kind = [...new Set(ex.map(x => x.kind === 'dns' ? 'DNS lookups' : (x.method || x.kind || '').toUpperCase()))].join(', ');
    items.push({ sev: 'high', icon: 'send', title: `Sent them out to ${hosts.length > 1 ? `${hosts.length} hosts` : hosts[0]}`, detail: `${kind} · seen in ${new Set(ex.map(x => x.run)).size} of ${runs.length || '?'} runs · our marker was in the payload` });
  }
  const trig = (rep.ai && !rep.ai.error && rep.ai.dormant_triggers) || [];
  for (const d of trig) items.push({ sev: 'medium', icon: 'bomb', title: `Hidden trigger: ${d.condition}`, detail: `${d.file} — would ${d.would_do}` });

  const byRun = ev.matrix || {};
  const hitRuns = Object.entries(byRun).filter(([, m]) => m.honeytoken_hits > 0).map(([n]) => n);
  if (hitRuns.length && hitRuns.length < runs.length) {
    const { clock } = parseRun(hitRuns[0]);
    const allClock = hitRuns.every(r => parseRun(r).clock === clock && clock !== '0');
    const allPersona = hitRuns.every(r => parseRun(r).persona === parseRun(hitRuns[0]).persona);
    if (allClock) items.push({ sev: 'medium', icon: 'clock', title: `Only misbehaves when the clock is moved ${clock.replace('d', ' days')}`, detail: 'A time bomb: it looks clean if you test it today' });
    else if (allPersona) items.push({ sev: 'medium', icon: 'user', title: `Only misbehaves as ${parseRun(hitRuns[0]).persona}`, detail: 'It checks where it is running before acting' });
  }
  const net = (ev.requests || []).filter(r => !(ex || []).some(x => (x.host || x.sni) === (r.host || r.sni)));
  if (net.length) {
    const hosts = [...new Set(net.map(x => x.host || x.sni))];
    items.push({ sev: 'medium', icon: 'globe', title: `Contacted ${hosts.slice(0, 2).join(', ')}${hosts.length > 2 ? ` and ${hosts.length - 2} more` : ''}`, detail: 'Answered by the fake internet, so nothing reached a real server' });
  }
  const scripts = ev.install_scripts || [];
  for (const s of scripts) items.push({ sev: kinds.size ? 'medium' : 'low', icon: 'terminal', title: `Runs a ${s.hook} script on install`, detail: s.command });
  const shells = (ev.processes || []).filter(p => /^(curl|wget|sh|bash|powershell|nc)$/.test((p.argv?.[0] || '').split('/').pop()));
  if (shells.length) items.push({ sev: 'low', icon: 'cpu', title: `Spawned ${new Set(shells.map(p => p.argv[0])).size} kind of shell command`, detail: [...new Set(shells.map(p => p.argv.join(' ').slice(0, 80)))].slice(0, 3).join(' · ') });
  const w = ev.files_written_outside_project || [];
  if (w.length) items.push({ sev: 'medium', icon: 'pen', title: `Wrote ${w.length} file${w.length > 1 ? 's' : ''} outside its folder`, detail: w.slice(0, 3).map(prettyPath).join(' · ') });

  if (!items.length || (!kinds.size && !ex.length && !net.length && !w.length)) {
    const cov = rep.rules?.coverage;
    if (cov && !cov.executed) items.unshift({ sev: 'low', icon: 'info', title: 'Its code never ran', detail: cov.reason || 'No install scripts and no entry point' });
    else items.unshift({ sev: 'ok', icon: 'shieldCheck', title: `Nothing risky in ${runs.length || 'any'} run${runs.length === 1 ? '' : 's'}`, detail: 'No planted secret was read, no data left the sandbox, nothing was written outside its folder' });
  }
  return items;
}
