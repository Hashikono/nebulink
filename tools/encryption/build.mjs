#!/usr/bin/env node
// NebuLink vault builder
//
//   node build.mjs [src.html] [gates.json] [out.html]
//
// Reads the plaintext game (ENTRIES + ASSETS), splits the filesystem into
// AES-256-GCM encrypted "vaults", and writes a single HTML file in which:
//   * the login IP / user / password are NOT in the source (they are the key
//     to the first vault, and each step is verified by a tiny sealed probe)
//   * each "name gate" (e.g. the hidden eridanus folder) is only decrypted
//     when the player types the right name as a path component
//   * gates nest: a vault can contain further sealed gates, so you cannot even
//     attempt a deeper gate without having opened the one above it.
//
// Keys:  PBKDF2-SHA256(secret, random salt, N iterations) -> AES-256-GCM.
// Payloads are deflated before encryption so the file does not balloon.
//
// gates.json holds the secrets. Keep it OUT of anything you ship.

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import zlib from 'node:zlib';
import { webcrypto as wc, randomBytes } from 'node:crypto';

const here = path.dirname(new URL(import.meta.url).pathname);
const argv = process.argv.slice(2);
const flag = (name) => (argv.find((a) => a.startsWith('--' + name + '=')) || '').split('=')[1];
const pos = argv.filter((a) => !a.startsWith('--'));
const srcPath = pos[0] || path.join(here, 'src/nebulink_v1.8.9.html');
const cfgPath = pos[1] || path.join(here, 'gates.json');
const outPath = pos[2] || path.join(here, 'dist/nebulink_v1.8.9_vaulted.html');

const die = (m) => { console.error('build error: ' + m); process.exit(1); };

// ---------------------------------------------------------------- load inputs
const src = fs.readFileSync(srcPath, 'utf8');
const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
const ITER = cfg.iterations || 250000;
const OBF = (flag('obfuscate') || cfg.obfuscate || 'medium').toLowerCase();
if (!['off', 'low', 'medium', 'high'].includes(OBF)) die(`--obfuscate must be off|low|medium|high (got ${OBF})`);
if (!cfg.login || !cfg.login.ip || !cfg.login.user || !cfg.login.pass) die('gates.json needs login.ip/user/pass');

// Locate the ASSETS and ENTRIES blocks in the source.
const assetsStart = src.indexOf('const ASSETS = {');
const assetsEnd = src.indexOf('\n};\n', assetsStart);
const buildMark = src.indexOf('// Build the FS\nconst FS = buildFS(ENTRIES);');
const entriesStart = src.indexOf('const ENTRIES = [');
const entriesEnd = src.lastIndexOf('];', buildMark);
if ([assetsStart, assetsEnd, buildMark, entriesStart, entriesEnd].some((i) => i < 0)) {
  die('could not find ASSETS / ENTRIES / buildFS anchors in the source (did its layout change?)');
}

// Evaluate the data blocks (pure data + two tiny helper functions) in a sandbox.
const evalCode =
  src.slice(assetsStart, assetsEnd + 4) +
  src.slice(src.indexOf('function entryDir'), src.indexOf('// Build FS')) + // entryDir + entryFile
  src.slice(entriesStart, entriesEnd + 2) +
  '\n;({ ASSETS, ENTRIES })';
let ASSETS, ENTRIES;
try { ({ ASSETS, ENTRIES } = vm.runInNewContext(evalCode, {}, { timeout: 10000 })); }
catch (e) { die('failed to evaluate ENTRIES: ' + e.message); }

// ------------------------------------------------------------------- helpers
const norm = (p) => (p.length > 1 && p.endsWith('/') ? p.slice(0, -1) : p);
const entryPath = (e) => (e.kind === 'dir' ? norm(e.dir) : norm(e.dir) + '/' + e.name);
const isPrefixOrEqual = (pre, p) => p === pre || p.startsWith(pre + '/');
const b64 = (buf) => Buffer.from(buf).toString('base64');

async function seal(id, secret, payload) {
  const salt = randomBytes(16), iv = randomBytes(12);
  const km = await wc.subtle.importKey('raw', Buffer.from(secret), 'PBKDF2', false, ['deriveKey']);
  const key = await wc.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, km,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const plain = zlib.deflateRawSync(Buffer.from(JSON.stringify(payload)), { level: 9 });
  const ct = await wc.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: Buffer.from(id) }, key, plain);
  return { id, s: b64(salt), n: b64(iv), c: b64(new Uint8Array(ct)) };
}
async function open(rec, secret) { // used only for the build-time self test
  try {
    const km = await wc.subtle.importKey('raw', Buffer.from(secret), 'PBKDF2', false, ['deriveKey']);
    const key = await wc.subtle.deriveKey(
      { name: 'PBKDF2', salt: Buffer.from(rec.s, 'base64'), iterations: ITER, hash: 'SHA-256' }, km,
      { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
    const pt = await wc.subtle.decrypt(
      { name: 'AES-GCM', iv: Buffer.from(rec.n, 'base64'), additionalData: Buffer.from(rec.id) },
      key, Buffer.from(rec.c, 'base64'));
    return JSON.parse(zlib.inflateRawSync(Buffer.from(pt)).toString());
  } catch { return null; }
}
const rid = () => randomBytes(4).toString('hex');

// --------------------------------------------------------- plan the vault tree
const gates = (cfg.gates || []).map((g) => ({
  ...g,
  parent: norm(g.parent),
  full: norm(g.parent) + '/' + g.name,
}));
for (const g of gates) {
  if (g.name.includes('/')) die(`gate name must be a single path component: ${g.name}`);
}
// the deepest gate whose directory contains `p` (or null => login vault)
const ownerOf = (p, exclude) => {
  let best = null;
  for (const g of gates) {
    if (g === exclude) continue;
    if (isPrefixOrEqual(g.full, p) && (!best || g.full.length > best.full.length)) best = g;
  }
  return best;
};
const loginEntries = [];
for (const g of gates) g.entries = [];
for (const e of ENTRIES) {
  const o = ownerOf(entryPath(e));
  (o ? o.entries : loginEntries).push(e);
}
for (const g of gates) {
  if (!g.entries.length) die(`gate "${g.full}" matches no entries`);
  g.owner = ownerOf(g.parent, g); // vault that must be open before this gate can be tried
  // the parent directory must exist (explicitly or implicitly) in the owning vault
  const pool = g.owner ? g.owner.entries : loginEntries;
  const ok = pool.some((e) => isPrefixOrEqual(g.parent, entryPath(e)) || isPrefixOrEqual(entryPath(e), g.parent));
  if (!ok) die(`parent "${g.parent}" of gate "${g.full}" is not present in its owning vault`);
}

// ---------------------------------------------------------------------- seal
const recGate = new Map(); // sealed record -> its gate (build-time only, never serialized)
async function sealGate(g) {
  const children = [];
  for (const c of gates.filter((x) => x.owner === g)) children.push(await sealGate(c));
  const rec = { ...(await seal(rid(), g.name, { e: g.entries, g: children })), p: g.parent };
  recGate.set(rec, g);
  return rec;
}
const topGates = [];
for (const g of gates.filter((x) => !x.owner)) topGates.push(await sealGate(g));

const { ip, user, pass } = cfg.login;
const stepA = await seal('a' + rid(), ip, {});
const stepB = await seal('b' + rid(), ip + '\n' + user, {});
// The easter-egg image: sealed under the canonical wipe command, and carried INSIDE the login vault ("x"),
// so without the guest credentials the sealed record is not even reachable. The panic code supplies the key.
const EASTER_KEY = cfg.easter && cfg.easter.key;
let extras = null;
if (EASTER_KEY) {
  if (!ASSETS.EASTER) die('gates.json has "easter" but the source has no ASSETS.EASTER');
  extras = { easter: await seal('e' + rid(), EASTER_KEY, { img: ASSETS.EASTER }) };
}
const vault = await seal('c' + rid(), ip + '\n' + user + '\n' + pass, { e: loginEntries, g: topGates, ...(extras ? { x: extras } : {}) });

const NL = { it: ITER, a: stepA, b: stepB, v: vault };

// ------------------------------------------------------------- runtime (ships)
const RUNTIME = String.raw`
/* ===== NebuLink vault runtime (generated by build.mjs; do not edit by hand) ===== */
const NL = __NL_JSON__;
const FS_GATES = [];                       // sealed name-gates waiting for a key
const EXTRAS = {};                         // other sealed things that arrive with the login vault (the easter egg)
const _enc = new TextEncoder();
const _b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function _open(rec, secret){
  try{
    const km  = await crypto.subtle.importKey('raw', _enc.encode(secret), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name:'PBKDF2', salt:_b64(rec.s), iterations:NL.it, hash:'SHA-256' }, km,
      { name:'AES-GCM', length:256 }, false, ['decrypt']);
    const pt  = await crypto.subtle.decrypt(
      { name:'AES-GCM', iv:_b64(rec.n), additionalData:_enc.encode(rec.id) }, key, _b64(rec.c));
    const txt = await new Response(new Blob([pt]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).text();
    return JSON.parse(txt);
  }catch(_){ return null; }                // wrong key => GCM auth failure => null
}

// Merge freshly decrypted entries into the live FS without resurrecting anything the player rm'd.
function mergeEntries(entries){
  const tmp = buildFS(entries);
  for(const p of Object.keys(tmp)){
    const cur = FS[p], add = tmp[p];
    if(!cur){ FS[p] = add; continue; }
    if(cur.kind === 'dir' && add.kind === 'dir'){
      for(const c of (add.children || [])) if(!cur.children.includes(c)) cur.children.push(c);
    }
  }
}
function _mount(pl){
  if(pl.e && pl.e.length) mergeEntries(pl.e);
  for(const g of (pl.g || [])) FS_GATES.push(g);
  if(pl.x) Object.assign(EXTRAS, pl.x);
}

// ---- login: IP -> user -> password, each step verified by a sealed probe; the last opens the guest vault
async function _stageOk(n, secret){ return !!(await _open(n === 1 ? NL.a : NL.b, secret)); }
async function _login(ip, user, pwd){
  const pl = await _open(NL.v, ip + '\n' + user + '\n' + pwd);
  if(!pl) return false;
  if(!NL.v.done){ NL.v.done = true; _mount(pl); }
  return true;
}

// ---- name gates: typing the right path component IS the key
async function unlockPath(abs){
  let cur = '';
  for(const name of abs.split('/').filter(Boolean)){
    const parent = cur || '/';
    const next = cur + '/' + name;
    if(!FS[next]){
      let hit = false;
      for(const g of FS_GATES){
        if(g.done || g.p !== parent) continue;
        const pl = await _open(g, name);
        if(pl){ g.done = true; _mount(pl); hit = true; break; }
      }
      if(!hit) return;
    }
    cur = next;
  }
}
const _PATH_CMDS = new Set(['ls','cd','cat','less','more','open','spectrogram','play','hexdump','head','tail','rm','chmod']);
async function preUnlock(cmdline){
  if(!LOGGED_IN) return;
  const PL = parseLine(cmdline);                         // same tokenizer the shell uses (quotes, ~, $VAR)
  if(!_PATH_CMDS.has(((PL.toks[0] && PL.toks[0].val) || '').toLowerCase())) return;
  for(const a of PL.args){
    if(a.startsWith('-') || a.includes('*') || a.includes('?')) continue;   // flags / unexpanded globs can't be gate names
    await unlockPath(resolve(a));
  }
}

// ---- easter egg: decrypt the image while the kernel panic plays (called from systemCrash)
async function onPanicDecrypt(){
  try{
    if(EXTRAS.easter && !ASSETS.EASTER){
      const pl = await _open(EXTRAS.easter, __EASTER_KEY__);
      if(pl && pl.img) ASSETS.EASTER = pl.img;
    }
  }catch(_){}
}

// run() is now: (maybe unlock) then the original synchronous dispatcher, strictly in order
let _runQ = Promise.resolve();
function run(cmdline){
  _runQ = _runQ
    .then(async () => { try{ await preUnlock(cmdline); }catch(e){ console.error(e); } runSync(cmdline); })
    .catch((e) => console.error(e));
}
/* ===== end vault runtime ===== */
`;

// ------------------------------------------------------------ patch the source
function patchOnce(text, from, to, label) {
  const first = text.indexOf(from);
  if (first < 0) die(`patch "${label}" target not found:\n${from}`);
  if (text.indexOf(from, first + 1) >= 0) die(`patch "${label}" target is not unique`);
  return text.slice(0, first) + to + text.slice(first + from.length);
}

let out = src;
// 1. assets: keep only what the engine itself uses in plaintext (EASTER); the rest live inside vaults
if (!ASSETS.EASTER) die('expected ASSETS.EASTER');
out = out.slice(0, out.indexOf('const ASSETS = {')) +
  (extras ? 'const ASSETS = {\n};\n' : 'const ASSETS = {\n  EASTER: ' + JSON.stringify(ASSETS.EASTER) + '\n};\n') +
  out.slice(out.indexOf('\n};\n', out.indexOf('const ASSETS = {')) + 4);
// 2. entries: empty at load time; the real ones arrive from vaults
{
  const s = out.indexOf('const ENTRIES = ['), e = out.lastIndexOf('];', out.indexOf('// Build the FS\nconst FS = buildFS(ENTRIES);'));
  out = out.slice(0, s) + 'const ENTRIES = [];' + out.slice(e + 2);
}
// 3a. the original dispatcher becomes runSync; the queued wrapper in the runtime is the new `run`
out = patchOnce(out, 'function run(cmdline){', 'function runSync(cmdline){', 'run');
// 3. runtime goes right after the FS is created
out = patchOnce(out, 'const FS = buildFS(ENTRIES);',
  'const FS = buildFS(ENTRIES);\n' + RUNTIME.replace('__NL_JSON__', () => JSON.stringify(NL)).replace('__EASTER_KEY__', () => JSON.stringify(EASTER_KEY || '')), 'runtime');
// 4. drop the plaintext credentials
out = patchOnce(out.replace(/\/\/ Login credentials\nconst LOGIN_IP[^\n]*\nconst LOGIN_USER[^\n]*\nconst LOGIN_PASS[^\n]*\n/, '// (login credentials are sealed in the vault)\n'),
  '// (login credentials are sealed in the vault)', '// (login credentials are sealed in the vault)', 'creds');
if (/LOGIN_PASS\s*=|LOGIN_IP\s*=/.test(out)) die('credential constants still present');
// 5. connect flow: verify by decrypting
out = patchOnce(out, 'if(ip !== LOGIN_IP){', 'if(!(await _stageOk(1, ip))){', 'ip');
out = patchOnce(out, 'if(user !== LOGIN_USER){', 'if(!(await _stageOk(2, PENDING.ip + "\\n" + user))){', 'user');
out = patchOnce(out, 'print(LOGIN_USER + "@" + PENDING.ip + "\'s password:");', 'print(PENDING.user + "@" + PENDING.ip + "\'s password:");', 'pwdprompt');
out = patchOnce(out, 'if(pwd !== LOGIN_PASS){', 'if(!(await _login(PENDING.ip, PENDING.user, pwd))){', 'pwd');
out = patchOnce(out, 'async function connectFlow(input){',
  'async function connectFlow(input){\n  if(!(window.crypto && crypto.subtle)){ print("NebuLink needs a secure browser context (open the file directly, or serve over https)."); return; }',
  'cryptoguard');
// 7. the old "never autocomplete these names" list would leak the secret names in plaintext; gates make it unnecessary
out = patchOnce(out, "new Set(['.cache', 'eridanus', 'error00.log'])", 'new Set()', 'noautocomplete');

// ---------------------------------------------------------------- self tests
const names = gates.map((g) => g.name);
{ // round trip + negative tests
  const pl = await open(vault, ip + '\n' + user + '\n' + pass);
  if (!pl) die('self-test: login vault does not open with correct credentials');
  if (await open(vault, ip + '\n' + user + '\nWRONG')) die('self-test: login vault opened with a wrong password');
  if (!(await open(stepA, ip)) || (await open(stepA, '1.2.3.4'))) die('self-test: ip probe');
  if (!(await open(stepB, ip + '\n' + user)) || (await open(stepB, ip + '\nroot'))) die('self-test: user probe');
  // walk the sealed tree exactly as the runtime would: each gate opens with its name, not with a near miss
  const queue = [...pl.g];
  let opened = 0;
  const expectedNames = new Map([...recGate].map(([rec, g]) => [rec.id, g.name]));
  while (queue.length) {
    const r = queue.shift();
    const name = expectedNames.get(r.id);
    const p2 = await open(r, name);
    if (!p2) die(`self-test: gate at ${r.p} did not open with "${name}"`);
    if (await open(r, name + 'x') || await open(r, name.toUpperCase() === name ? name.toLowerCase() + 'x' : name.toUpperCase())) {
      die('self-test: a wrong name opened a gate');
    }
    opened++;
    queue.push(...(p2.g || []));
  }
  if (opened !== gates.length) die(`self-test: opened ${opened} gates, expected ${gates.length}`);
  if (extras) {
    if (!pl.x || !pl.x.easter) die('self-test: easter record missing from the login vault');
    const img = await open(pl.x.easter, EASTER_KEY);
    if (!img || img.img !== ASSETS.EASTER) die('self-test: easter image did not round-trip');
    if (await open(pl.x.easter, 'rm -rf /')) die('self-test: wrong key opened the easter image');
    if (await open(stepA, EASTER_KEY)) die('self-test: easter key opened something else');
  }
}

// plaintext leak scan (pre-obfuscation: the strongest form of the check)
// The easter key is public in-game (man rm shows it) and the runtime must hold it, so it is only required to be
// absent AFTER obfuscation (checkKey); everything else must never appear in plaintext at all.
const leakScan = (text, label, checkKey = false) => {
  const imgs = extras ? ['data:image/png', 'data:image/jpeg', 'iVBORw0KGgo', '/9j/4AAQ'] : [];   // base64 PNG / JPEG headers
  const leaks = [ip, pass, ...names, ...(EASTER_KEY && checkKey ? [EASTER_KEY] : []), ...imgs].filter((x) => text.includes(x));
  if (leaks.length) die(`secret(s) still present in plaintext ${label}: ` + leaks.join(', '));
};
leakScan(out, 'output');

// ------------------------------------------- obfuscate + put the whole script on ONE line
// The ciphertext (NL) and the one plaintext image (ASSETS) are lifted out of the engine, left untouched,
// and placed in front of the obfuscated engine on the same line, so the file ends in a single long line of JS.
function jsoOptions(level, reserved) {
  const o = {
    compact: true, simplify: true, target: 'browser', renameGlobals: true,
    identifierNamesGenerator: 'hexadecimal', reservedNames: reserved,
    stringArray: true, stringArrayRotate: true, stringArrayShuffle: true, stringArrayThreshold: 1,
    stringArrayIndexShift: true, stringArrayEncoding: ['base64'], stringArrayWrappersCount: 1,
    numbersToExpressions: true, splitStrings: false, controlFlowFlattening: false, deadCodeInjection: false,
  };
  if (cfg.seed !== undefined) o.seed = cfg.seed;
  if (level === 'medium' || level === 'high') {
    Object.assign(o, {
      stringArrayEncoding: ['rc4'], stringArrayWrappersCount: 2, stringArrayWrappersType: 'function',
      stringArrayCallsTransform: true, splitStrings: true, splitStringsChunkLength: 10,
      controlFlowFlattening: true, controlFlowFlatteningThreshold: level === 'high' ? 0.6 : 0.25,
      deadCodeInjection: true, deadCodeInjectionThreshold: level === 'high' ? 0.3 : 0.1,
    });
  }
  return o;
}
async function toSingleLine(html, level, reserved) {
  const open = html.indexOf('<script>'), close = html.lastIndexOf('</script>');
  if (open < 0 || html.indexOf('<script', open + 8) >= 0) die('expected exactly one <script> in the page');
  let main = html.slice(open + 8, close);
  const nl = (main.match(/^const NL = .*;$/m) || [])[0];
  if (!nl) die('could not find the NL data line');
  main = main.replace(nl, '');
  const aS = main.indexOf('const ASSETS = {'), aE = main.indexOf('\n};\n', aS) + 4;
  if (aS < 0 || aE < 4) die('could not find the ASSETS block');
  const assets = main.slice(aS, aE).replace(/\s*\n\s*/g, ' ').trim();
  main = main.slice(0, aS) + main.slice(aE);
  const { default: JSO } = await import('javascript-obfuscator');
  const code = JSO.obfuscate(main, jsoOptions(level, reserved)).getObfuscatedCode();
  const line = nl + assets + code;
  if (/[\r\n]/.test(line)) die('script is not a single line');
  if (/<\/script|<!--/i.test(line)) die('script contains </script or <!-- and would break the page');
  return html.slice(0, open + 8) + '\n' + line + '\n' + html.slice(close);
}

const jobs = [{ file: outPath, reserved: [], label: 'ship' }];
// test-only twin: identical, except the global `FS` keeps its name so the browser tests can compare filesystems
if (OBF !== 'off') jobs.push({ file: outPath.replace(/\.html$/, '.testable.html').replace(/dist[\\/]/, 'dist/test/'), reserved: ['^FS$'], label: 'testable (do not ship)' });

fs.mkdirSync(path.dirname(outPath), { recursive: true });
const kb = (n) => (n / 1024).toFixed(0) + ' KB';
let shipped = out;
for (const j of jobs) {
  const html = OBF === 'off' ? out : await toSingleLine(out, OBF, j.reserved);
  leakScan(html, j.label, OBF !== 'off');
  fs.mkdirSync(path.dirname(j.file), { recursive: true });
  fs.writeFileSync(j.file, html);
  if (j.label === 'ship') shipped = html;
  console.log(`built ${path.relative(process.cwd(), j.file)}  [${j.label}]  (${kb(src.length)} -> ${kb(html.length)})`);
}
console.log(`  login vault : ${loginEntries.length} entries`);
const show = (g, d) => { console.log(`  ${'  '.repeat(d)}gate ${g.full}  (${g.entries.length} entries)`); gates.filter((x) => x.owner === g).forEach((c) => show(c, d + 1)); };
gates.filter((x) => !x.owner).forEach((g) => show(g, 0));
const scriptText = shipped.slice(shipped.indexOf('<script>') + 8, shipped.lastIndexOf('</script>')).replace(/^\n|\n$/g, '');
console.log(`  PBKDF2 iterations: ${ITER}   self-test: ok   plaintext leak scan: clean`);
console.log(`  obfuscation: ${OBF}   script lines: ${scriptText.split('\n').length}   script size: ${kb(scriptText.length)}`);
