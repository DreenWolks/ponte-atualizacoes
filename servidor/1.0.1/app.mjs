// Ponte Servidor — o servidor da equipe do Ponte, para rodar numa máquina sua (no lugar do Supabase).
// Fala a mesma língua do Supabase que o Ponte usa: login (/auth/v1) e funções do banco (/rest/v1/rpc).
// Banco: PostgreSQL embutido (PGlite), com o mesmo arquivo ponte-equipe.sql. HTTPS automático com a Let's Encrypt.
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { PGlite } from '@electric-sql/pglite';
import acme from 'acme-client';

const require = createRequire(import.meta.url);
// pediram para parar enquanto ainda está abrindo o banco: sai na hora (depois de pronto, fecha o banco com calma)
let ready = false;
const earlyExit = () => { if (!ready) process.exit(0); };
process.on('disconnect', earlyExit); process.on('SIGTERM', earlyExit); process.on('SIGINT', earlyExit);
const forge = require('node-forge');
const HERE = path.dirname(fileURLToPath(import.meta.url));
export const VERSION = '1.0.0';

/* ------------------------------------------------------------------ pastas e configuração */
const DATA = process.env.PONTE_DATA || (process.platform === 'win32' ? path.join(process.env.ProgramData || 'C:\\ProgramData', 'PonteServidor') : path.join(os.homedir(), '.ponte-servidor'));
for (const d of ['', 'db', 'certs', 'backups', 'logs']) fs.mkdirSync(path.join(DATA, d), { recursive: true });
const CFG_FILE = path.join(DATA, 'config.json');
const STATE_FILE = path.join(DATA, 'estado.json');
const readJSON = (f, def) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return def; } };
const writeJSON = (f, v) => { const tmp = f + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(v, null, 2)); fs.renameSync(tmp, f); };

const cfg = {
  key: 'ponte_pub_' + crypto.randomBytes(18).toString('base64url'),
  jwtSecret: crypto.randomBytes(48).toString('base64url'),
  publicIp: '',          // vazio = descobre sozinho
  domain: '',            // opcional: um domínio seu apontando para a VM
  email: '',             // opcional: e-mail para avisos da Let's Encrypt
  httpPort: 80,
  httpsPort: 443,
  statusPort: 8787,
  acmeDirectory: acme.directory.letsencrypt.production,
  allowNewTeams: 'first', // 'first' = só a primeira equipe (e quem já é dono cria outras); 'yes' = qualquer um
  ...readJSON(CFG_FILE, {}),
};
for (const k of ['httpPort', 'httpsPort', 'statusPort']) if (process.env['PONTE_' + k.toUpperCase()]) cfg[k] = Number(process.env['PONTE_' + k.toUpperCase()]);
if (process.env.PONTE_ACME_DIRECTORY) cfg.acmeDirectory = process.env.PONTE_ACME_DIRECTORY;
if (process.env.PONTE_PUBLIC_IP) cfg.publicIp = process.env.PONTE_PUBLIC_IP;
writeJSON(CFG_FILE, cfg);
const saveCfg = () => writeJSON(CFG_FILE, cfg);

const state = { startedAt: new Date().toISOString(), version: process.env.PONTE_SRV_VERSION || VERSION, cert: { status: 'starting', host: '', error: null, notAfter: null }, ip: null, listen: {}, lastBackup: null, errors: [], ...readJSON(STATE_FILE, {}) };
state.startedAt = new Date().toISOString(); state.version = process.env.PONTE_SRV_VERSION || VERSION; state.listen = {}; state.errors = [];
const saveState = () => { try { writeJSON(STATE_FILE, state); } catch { /* disco cheio */ } };

/* ------------------------------------------------------------------ registro */
const LOG = path.join(DATA, 'logs', 'servidor.log');
function log(...a) {
  const line = `[${new Date().toISOString()}] ${a.map((x) => (x instanceof Error ? x.message : typeof x === 'string' ? x : JSON.stringify(x))).join(' ')}`;
  try { console.log(line); } catch { /* sem terminal (tarefa do sistema) */ }
  try {
    if (fs.existsSync(LOG) && fs.statSync(LOG).size > 5e6) fs.renameSync(LOG, LOG + '.1');
    fs.appendFileSync(LOG, line + '\n');
  } catch { /* sem log */ }
}
function problem(where, e) {
  log('ERRO', where, e);
  state.errors.unshift({ at: new Date().toISOString(), where, error: String(e && e.message || e) });
  state.errors = state.errors.slice(0, 20);
  saveState();
}

/* ------------------------------------------------------------------ banco */
const SQL_FILE = process.env.PONTE_SQL || path.join(HERE, 'ponte-equipe.sql');
const db = new PGlite(path.join(DATA, 'db'));
await db.waitReady;
await db.exec(`
  do $$ begin create role anon nologin; exception when others then null; end $$;
  do $$ begin create role authenticated nologin; exception when others then null; end $$;
  create schema if not exists auth;
  create or replace function auth.jwt() returns jsonb language sql stable as $f$
    select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $f$;
  create or replace function auth.uid() returns uuid language sql stable as $f$
    select nullif(auth.jwt() ->> 'sub', '')::uuid $f$;
  create or replace function auth.email() returns text language sql stable as $f$ select auth.jwt() ->> 'email' $f$;
  create or replace function auth.role() returns text language sql stable as $f$ select auth.jwt() ->> 'role' $f$;
  grant usage on schema auth to anon, authenticated;
  grant execute on all functions in schema auth to anon, authenticated;
  grant usage on schema public to anon, authenticated;
  create schema if not exists srv;
  revoke all on schema srv from public, anon, authenticated;
  create table if not exists srv.users (
    id uuid primary key default gen_random_uuid(), email text unique not null, pass text not null,
    created_at timestamptz not null default now(), last_login timestamptz);
  create table if not exists srv.refresh (
    token_hash text primary key, user_id uuid not null references srv.users(id) on delete cascade,
    created_at timestamptz not null default now(), expires_at timestamptz not null);
  create index if not exists refresh_user on srv.refresh(user_id);
`);
await db.exec(fs.readFileSync(SQL_FILE, 'utf8'));
const schemaVer = (await db.query('select public.ponte_schema_version() v')).rows[0].v;
log(`banco pronto (esquema ${schemaVer}) em ${path.join(DATA, 'db')}`);

// chama uma função do Ponte como o usuário do token (igual ao PostgREST do Supabase)
async function callRpc(claims, fn, args) {
  return db.transaction(async (tx) => {
    await tx.query(`select set_config('request.jwt.claims', $1, true)`, [JSON.stringify(claims || { role: 'anon' })]);
    await tx.exec(`set local role ${claims && claims.sub ? 'authenticated' : 'anon'}`);
    const names = Object.keys(args || {}).filter((n) => /^p_[a-z_]+$/.test(n));
    const sql = `select public.${fn}(${names.map((n, i) => `${n} => $${i + 1}`).join(', ')}) as r`;
    const vals = names.map((n) => { const v = args[n]; return v !== null && typeof v === 'object' ? JSON.stringify(v) : v; });
    const res = await tx.query(sql, vals);
    return res.rows[0].r;
  });
}
const fnCache = new Map();
async function fnExists(fn) {
  if (fnCache.has(fn)) return fnCache.get(fn);
  const r = await db.query(`select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.proname = $1`, [fn]);
  fnCache.set(fn, r.rows.length > 0);
  return r.rows.length > 0;
}

/* ------------------------------------------------------------------ contas e tokens */
const ACCESS_TTL = 3600;
const b64u = (b) => Buffer.from(b).toString('base64url');
function signJwt(payload) {
  const head = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64u(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', cfg.jwtSecret).update(head + '.' + body).digest('base64url');
  return `${head}.${body}.${sig}`;
}
function verifyJwt(tok) {
  const p = String(tok || '').split('.');
  if (p.length !== 3) return null;
  const sig = crypto.createHmac('sha256', cfg.jwtSecret).update(p[0] + '.' + p[1]).digest('base64url');
  if (sig.length !== p[2].length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(p[2]))) return null;
  try { const j = JSON.parse(Buffer.from(p[1], 'base64url').toString('utf8')); return j.exp * 1000 > Date.now() ? j : 'expired'; } catch { return null; }
}
const scryptP = (pw, salt) => new Promise((ok, no) => crypto.scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1 }, (e, k) => (e ? no(e) : ok(k))));
async function hashPass(pw) { const salt = crypto.randomBytes(16); const k = await scryptP(pw, salt); return `scrypt$${salt.toString('base64')}$${k.toString('base64')}`; }
async function checkPass(pw, stored) {
  const [, salt, key] = String(stored).split('$');
  if (!salt || !key) return false;
  const k = await scryptP(pw, Buffer.from(salt, 'base64'));
  const want = Buffer.from(key, 'base64');
  return k.length === want.length && crypto.timingSafeEqual(k, want);
}
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
async function session(u) {
  const now = Math.floor(Date.now() / 1000);
  const access = signJwt({ sub: u.id, email: u.email, role: 'authenticated', aud: 'authenticated', iat: now, exp: now + ACCESS_TTL });
  const refresh = crypto.randomBytes(32).toString('base64url');
  await db.query(`insert into srv.refresh (token_hash, user_id, expires_at) values ($1, $2, now() + interval '60 days')`, [sha(refresh), u.id]);
  await db.query(`update srv.users set last_login = now() where id = $1`, [u.id]);
  return { access_token: access, token_type: 'bearer', expires_in: ACCESS_TTL, expires_at: now + ACCESS_TTL, refresh_token: refresh, user: { id: u.id, email: u.email, aud: 'authenticated', role: 'authenticated' } };
}

// muitas tentativas de senha errada: espera um pouco
const fails = new Map();
function tooMany(k) { const f = fails.get(k); return f && f.n >= 8 && Date.now() - f.at < 15 * 60e3; }
function failed(k) { const f = fails.get(k) || { n: 0, at: 0 }; if (Date.now() - f.at > 15 * 60e3) f.n = 0; f.n++; f.at = Date.now(); fails.set(k, f); }

/* ------------------------------------------------------------------ requisições */
const MAX_BODY = 25 * 1024 * 1024;
function send(res, code, obj, extra) {
  const body = obj === undefined ? '' : JSON.stringify(obj);
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', ...(extra || {}) });
  res.end(body);
}
function cors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'apikey, authorization, content-type, x-client-info, accept, prefer, accept-profile, content-profile');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Max-Age', '86400');
}
async function readBody(req) {
  let size = 0; const chunks = [];
  for await (const c of req) { size += c.length; if (size > MAX_BODY) throw Object.assign(new Error('Pedido grande demais.'), { status: 413 }); chunks.push(c); }
  const s = Buffer.concat(chunks).toString('utf8');
  if (!s) return {};
  try { return JSON.parse(s); } catch { throw Object.assign(new Error('JSON inválido.'), { status: 400 }); }
}
const authErr = (res, code, error_code, msg) => send(res, code, { code, error_code, msg, message: msg });
const validEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 200;

const HOME_HTML = (title, body) => `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title>
<style>:root{color-scheme:light dark;--bg:#f4f6fb;--fg:#172036;--mut:#5f6b86;--card:#fff;--line:#e3e8f1;--ok:#148a4b;--warn:#b7791f;--bad:#cf4535;--acc:#f2b33d}
@media (prefers-color-scheme:dark){:root{--bg:#0f1524;--fg:#e8ecf5;--mut:#9aa6c0;--card:#172036;--line:#26314a}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,Arial,sans-serif}main{max-width:760px;margin:0 auto;padding:28px 16px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:16px;margin:0 0 10px}.mut{color:var(--mut)}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin:14px 0}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}code,.code{font-family:ui-monospace,Consolas,monospace;font-size:13px;word-break:break-all;background:rgba(127,127,127,.12);padding:2px 6px;border-radius:6px}
.big{display:block;padding:12px;font-size:14px;margin:8px 0}button,input{font:inherit}button{background:var(--acc);border:0;border-radius:9px;padding:9px 14px;font-weight:600;cursor:pointer;color:#1b1406}
button.g{background:transparent;border:1px solid var(--line);color:var(--fg)}input{background:transparent;color:var(--fg);border:1px solid var(--line);border-radius:9px;padding:8px 10px;width:100%;box-sizing:border-box}
table{width:100%;border-collapse:collapse}td{padding:6px 0;border-bottom:1px solid var(--line);vertical-align:top}td:first-child{color:var(--mut);width:42%}ol{padding-left:20px}li{margin:4px 0}</style></head><body><main>${body}</main></body></html>`;

async function handleApi(req, res, url) {
  const p = url.pathname;
  if (p === '/' && req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(HOME_HTML('Ponte Servidor', `<h1>Ponte Servidor</h1><p class="ok">Funcionando.</p><p class="mut">Este é o servidor da equipe do Ponte. Para conectar, use o código de conexão que aparece na tela do Ponte Servidor, dentro da VM.</p>`));
  }
  if (p === '/health') return send(res, 200, { ok: true, version: state.version, schema: schemaVer });
  // só para testes automáticos, nesta máquina e com a variável ligada
  if (p === '/__sql' && process.env.PONTE_DEBUG_SQL === '1' && /^(::ffff:)?127\.0\.0\.1$|^::1$/.test(req.socket.remoteAddress || '')) {
    const b = await readBody(req); return send(res, 200, (await db.query(b.sql)).rows);
  }
  if (req.method !== 'POST') return send(res, 404, { message: 'not found' });
  if (req.headers.apikey !== cfg.key) return send(res, 401, { message: 'Invalid API key', hint: 'Double check your Supabase `anon` or `service_role` API key.' });
  const ip = req.socket.remoteAddress || '';
  const body = await readBody(req);

  if (p === '/auth/v1/signup') {
    const email = String(body.email || '').trim().toLowerCase();
    const pw = String(body.password || '');
    if (!validEmail(email)) return authErr(res, 400, 'validation_failed', 'Unable to validate email address: invalid format');
    if (pw.length < 6) return authErr(res, 422, 'weak_password', 'Password should be at least 6 characters.');
    if (tooMany('signup:' + ip)) return authErr(res, 429, 'over_request_rate_limit', 'Email rate limit exceeded');
    const ex = await db.query('select id from srv.users where email = $1', [email]);
    if (ex.rows.length) { failed('signup:' + ip); return authErr(res, 422, 'user_already_exists', 'User already registered'); }
    const r = await db.query('insert into srv.users (email, pass) values ($1, $2) returning id, email', [email, await hashPass(pw)]);
    log('nova conta', email);
    return send(res, 200, await session(r.rows[0]));
  }
  if (p === '/auth/v1/token') {
    const gt = url.searchParams.get('grant_type');
    if (gt === 'password') {
      const email = String(body.email || '').trim().toLowerCase();
      const k = 'login:' + email + ':' + ip;
      if (tooMany(k)) return authErr(res, 429, 'over_request_rate_limit', 'Request rate limit reached');
      const r = await db.query('select id, email, pass from srv.users where email = $1', [email]);
      const u = r.rows[0];
      if (!u || !(await checkPass(String(body.password || ''), u.pass))) { failed(k); return authErr(res, 400, 'invalid_credentials', 'Invalid login credentials'); }
      fails.delete(k);
      return send(res, 200, await session(u));
    }
    if (gt === 'refresh_token') {
      const h = sha(body.refresh_token || '');
      const r = await db.query(`delete from srv.refresh where token_hash = $1 returning user_id, expires_at`, [h]);
      const row = r.rows[0];
      if (!row || new Date(row.expires_at) < new Date()) return authErr(res, 400, 'refresh_token_not_found', 'Invalid Refresh Token: Refresh Token Not Found');
      const u = (await db.query('select id, email from srv.users where id = $1', [row.user_id])).rows[0];
      if (!u) return authErr(res, 400, 'refresh_token_not_found', 'Invalid Refresh Token: Refresh Token Not Found');
      return send(res, 200, await session(u));
    }
    return authErr(res, 400, 'validation_failed', 'unsupported grant_type');
  }
  if (p === '/auth/v1/logout') {
    const c = verifyJwt((req.headers.authorization || '').replace(/^Bearer /i, ''));
    if (c && c !== 'expired') await db.query('delete from srv.refresh where user_id = $1', [c.sub]);
    return send(res, 204);
  }
  const m = p.match(/^\/rest\/v1\/rpc\/([a-z_][a-z0-9_]*)$/);
  if (m) {
    const fn = m[1];
    const bearer = (req.headers.authorization || '').replace(/^Bearer /i, '');
    let claims = null;
    if (bearer && bearer !== cfg.key) {
      claims = verifyJwt(bearer);
      if (claims === 'expired') return send(res, 401, { code: 'PGRST301', message: 'JWT expired' });
      if (!claims) return send(res, 401, { code: 'PGRST301', message: 'JWT invalid' });
    }
    if (!fn.startsWith('ponte_') || !(await fnExists(fn))) return send(res, 404, { code: 'PGRST202', message: `Could not find the function public.${fn} in the schema cache` });
    // este servidor é de uma loja: só a primeira equipe (ou quem já é dono) pode criar equipes
    if ((fn === 'ponte_team_create' || fn === 'ponte_team_import') && claims && cfg.allowNewTeams !== 'yes') {
      const teams = Number((await db.query('select count(*)::int n from public.ponte_teams')).rows[0].n);
      const isOwner = (await db.query(`select 1 from public.ponte_members where user_id = $1 and role = 'owner' and active`, [claims.sub])).rows.length > 0;
      const sameTeam = fn === 'ponte_team_import' && body.p_team && (await db.query('select 1 from public.ponte_teams where id = $1', [body.p_team]).catch(() => ({ rows: [] }))).rows.length > 0;
      if (teams > 0 && !isOwner && !sameTeam) return send(res, 403, { code: 'P0001', message: 'Este servidor já tem uma equipe. Peça um convite ao dono para entrar nela.' });
    }
    try {
      const r = await callRpc(claims, fn, body);
      return send(res, 200, r);
    } catch (e) {
      const msg = String(e.message || '');
      if (/permission denied/i.test(msg)) return send(res, 401, { code: '42501', message: msg });
      return send(res, 400, { code: e.code || 'P0001', message: msg, details: e.detail || null, hint: null });
    }
  }
  return send(res, 404, { message: 'not found' });
}

function apiHandler(req, res) {
  cors(res);
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }
  let url;
  try { url = new URL(req.url, 'https://x'); } catch { return send(res, 400, { message: 'bad url' }); }
  handleApi(req, res, url).catch((e) => {
    if (e.status) return send(res, e.status, { message: e.message });
    problem('requisição ' + url.pathname, e);
    if (!res.headersSent) send(res, 500, { message: 'Erro no servidor da equipe.' });
  });
}

/* ------------------------------------------------------------------ HTTPS (Let's Encrypt) */
const CERT_DIR = path.join(DATA, 'certs');
const challenges = new Map();
function selfSigned(host) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const c = forge.pki.createCertificate();
  c.publicKey = keys.publicKey; c.serialNumber = '01' + crypto.randomBytes(8).toString('hex');
  c.validity.notBefore = new Date(Date.now() - 86400e3); c.validity.notAfter = new Date(Date.now() + 30 * 86400e3);
  const attrs = [{ name: 'commonName', value: 'Ponte Servidor (provisorio)' }];
  c.setSubject(attrs); c.setIssuer(attrs);
  c.setExtensions([{ name: 'subjectAltName', altNames: [/^\d+\.\d+\.\d+\.\d+$/.test(host) ? { type: 7, ip: host } : { type: 2, value: host || 'localhost' }] }]);
  c.sign(keys.privateKey, forge.md.sha256.create());
  return { key: forge.pki.privateKeyToPem(keys.privateKey), cert: forge.pki.certificateToPem(c) };
}
function loadCert() {
  try {
    const key = fs.readFileSync(path.join(CERT_DIR, 'key.pem'), 'utf8');
    const cert = fs.readFileSync(path.join(CERT_DIR, 'cert.pem'), 'utf8');
    const meta = readJSON(path.join(CERT_DIR, 'meta.json'), {});
    return { key, cert, meta };
  } catch { return null; }
}
async function detectIp() {
  if (cfg.publicIp) return cfg.publicIp;
  for (const u of ['https://api.ipify.org', 'https://ipv4.icanhazip.com', 'https://ifconfig.me/ip', 'https://checkip.amazonaws.com']) {
    try {
      const r = await fetch(u, { signal: AbortSignal.timeout(8000), headers: { 'user-agent': 'curl/8' } });
      const t = (await r.text()).trim();
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return t;
    } catch { /* tenta o próximo */ }
  }
  throw new Error('Não consegui descobrir o IP público desta máquina. Informe o IP na tela do Ponte Servidor.');
}
const sslipName = (ip) => ip.replace(/\./g, '-') + '.sslip.io';
if (acme.axios) acme.axios.defaults.timeout = 30000; // a Let's Encrypt fora do ar não pode travar o pedido
let accountKey = null;
async function acmeClient() {
  const f = path.join(CERT_DIR, 'conta-acme.pem');
  if (!accountKey) { try { accountKey = fs.readFileSync(f); } catch { accountKey = await acme.crypto.createPrivateEcdsaKey(); fs.writeFileSync(f, accountKey); } }
  const client = new acme.Client({ directoryUrl: cfg.acmeDirectory, accountKey });
  await client.createAccount({ termsOfServiceAgreed: true, ...(cfg.email ? { contact: ['mailto:' + cfg.email] } : {}) });
  return client;
}
async function issue(identifier, profile) {
  const client = await acmeClient();
  const order = await client.createOrder({ identifiers: [identifier], ...(profile ? { profile } : {}) });
  const authzs = await client.getAuthorizations(order);
  for (const a of authzs) {
    if (a.status === 'valid') continue;
    const ch = a.challenges.find((c) => c.type === 'http-01');
    if (!ch) throw new Error('A Let\'s Encrypt não ofereceu a verificação pela porta 80.');
    const ka = await client.getChallengeKeyAuthorization(ch);
    challenges.set(ch.token, ka);
    try {
      await client.completeChallenge(ch);
      await client.waitForValidStatus(ch);
    } finally { setTimeout(() => challenges.delete(ch.token), 60e3); }
  }
  const key = await acme.crypto.createPrivateEcdsaKey();
  const [, csr] = await acme.crypto.createCsr({ altNames: [identifier.value] }, key);
  const fin = await client.finalizeOrder(order, csr);
  const cert = await client.getCertificate(fin);
  return { key: key.toString(), cert };
}
let httpsServer = null, renewing = null;
function certInfo(pem) {
  try { const x = new crypto.X509Certificate(pem); return { notAfter: new Date(x.validTo).toISOString(), notBefore: new Date(x.validFrom).toISOString(), issuer: x.issuer }; } catch { return {}; }
}
async function ensureCert(force) {
  if (renewing) return renewing;
  renewing = (async () => {
    const cur = loadCert();
    const host = cfg.domain || null;
    let ip = null;
    try { ip = cfg.domain ? null : await detectIp(); state.ip = ip; } catch (e) { state.cert = { ...state.cert, status: 'error', error: e.message }; saveState(); throw e; }
    const want = cfg.domain ? cfg.domain : ip;
    if (cur && !force && cur.meta.for === want) {
      const inf = certInfo(cur.cert);
      const left = new Date(inf.notAfter).getTime() - Date.now();
      const total = new Date(inf.notAfter).getTime() - new Date(inf.notBefore).getTime();
      if (left > Math.max(total / 3, 36 * 3600e3)) {
        state.cert = { status: 'ok', host: cur.meta.host, error: null, notAfter: inf.notAfter, issuer: inf.issuer };
        saveState();
        return cur;
      }
    }
    state.cert = { ...state.cert, status: 'pending', error: null };
    saveState();
    let got = null, hostName = null, errs = [];
    const attempts = cfg.domain
      ? [{ id: { type: 'dns', value: cfg.domain }, host: cfg.domain, profile: null }]
      : [{ id: { type: 'ip', value: ip }, host: ip, profile: 'shortlived' }, { id: { type: 'dns', value: sslipName(ip) }, host: sslipName(ip), profile: null }];
    for (const a of attempts) {
      try {
        log('pedindo certificado HTTPS para', a.host);
        got = await Promise.race([issue(a.id, a.profile), new Promise((_, no) => setTimeout(() => no(new Error('a Let\'s Encrypt demorou demais para responder')), 4 * 60e3))]);
        hostName = a.host; break;
      }
      catch (e) { errs.push(`${a.host}: ${e.message}`); log('certificado falhou', a.host, e.message); }
    }
    if (!got) {
      const msg = errs.join(' | ');
      const hint = /connection|timeout|refused|unauthorized|Fetching|connect/i.test(msg) ? ' A Let\'s Encrypt não conseguiu acessar esta máquina pela porta 80: libere as portas 80 e 443 (TCP) no firewall da nuvem da VM.' : '';
      state.cert = { ...state.cert, status: 'error', error: msg + hint };
      saveState();
      throw new Error(msg);
    }
    fs.writeFileSync(path.join(CERT_DIR, 'key.pem'), got.key);
    fs.writeFileSync(path.join(CERT_DIR, 'cert.pem'), got.cert);
    writeJSON(path.join(CERT_DIR, 'meta.json'), { for: want, host: hostName, at: new Date().toISOString() });
    const inf = certInfo(got.cert);
    state.cert = { status: 'ok', host: hostName, error: null, notAfter: inf.notAfter, issuer: inf.issuer };
    saveState();
    if (httpsServer) httpsServer.setSecureContext({ key: got.key, cert: got.cert });
    log('certificado HTTPS pronto para', hostName, 'até', inf.notAfter);
    return { key: got.key, cert: got.cert, meta: { host: hostName } };
  })().finally(() => { renewing = null; });
  return renewing;
}

/* ------------------------------------------------------------------ código de conexão */
function publicUrl() {
  const h = state.cert && state.cert.status === 'ok' && state.cert.host ? state.cert.host : (cfg.domain || state.ip);
  if (!h) return null;
  return 'https://' + h + (cfg.httpsPort === 443 ? '' : ':' + cfg.httpsPort);
}
function connectionCode() {
  const u = publicUrl();
  return u ? 'PONTE-SRV-' + Buffer.from(JSON.stringify({ u, k: cfg.key })).toString('base64url') : null;
}

/* ------------------------------------------------------------------ backup */
const BK_DIR = path.join(DATA, 'backups');
async function backup(reason) {
  const name = `ponte-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.tar.gz`;
  const f = await db.dumpDataDir('gzip');
  fs.writeFileSync(path.join(BK_DIR, name), Buffer.from(await f.arrayBuffer()));
  const all = fs.readdirSync(BK_DIR).filter((x) => /^ponte-.*\.tar\.gz$/.test(x)).sort();
  for (const old of all.slice(0, Math.max(0, all.length - 14))) { try { fs.unlinkSync(path.join(BK_DIR, old)); } catch { /* ignorado */ } }
  state.lastBackup = { at: new Date().toISOString(), file: name, reason };
  saveState();
  log('backup feito', name);
  return name;
}

/* ------------------------------------------------------------------ painel local (só nesta máquina) */
async function statusData() {
  const teams = (await db.query('select t.name, (select count(*)::int from public.ponte_members m where m.team_id = t.id and m.active) as people from public.ponte_teams t order by t.created_at')).rows;
  const users = Number((await db.query('select count(*)::int n from srv.users')).rows[0].n);
  return { version: state.version, schema: schemaVer, startedAt: state.startedAt, ip: state.ip, ipOverride: cfg.publicIp, domain: cfg.domain, cert: state.cert, url: publicUrl(), code: state.cert.status === 'ok' ? connectionCode() : null, teams, users, lastBackup: state.lastBackup, errors: state.errors.slice(0, 5), listen: state.listen, data: DATA, ports: { http: cfg.httpPort, https: cfg.httpsPort } };
}
function statusPage(s) {
  const ok = s.cert.status === 'ok' && s.listen.https === 'ok';
  const row = (k, v) => `<tr><td>${k}</td><td>${v}</td></tr>`;
  const esc = (x) => String(x ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  return HOME_HTML('Ponte Servidor', `<h1>Ponte Servidor</h1><p class="mut">Versão ${esc(s.version)} · servidor da equipe do Ponte nesta máquina</p>
  <div class="card">${ok ? `<h2 class="ok">✓ Pronto</h2><p>Para conectar a equipe, copie o <b>código de conexão</b> e cole no Ponte (Equipe → Meu servidor, ou “Mudar para o meu servidor”).</p>
    <code class="big code" id="code">${esc(s.code)}</code><button onclick="navigator.clipboard.writeText(document.getElementById('code').textContent).then(()=>this.textContent='Copiado ✓')">Copiar código de conexão</button>
    <p class="mut" style="margin-bottom:0">O código tem o endereço e a chave pública do servidor. Pode mandar para a sua equipe: quem protege os dados é o login de cada pessoa.</p>`
    : s.cert.status === 'pending' || s.cert.status === 'starting' ? `<h2 class="warn">Preparando a conexão segura (HTTPS)…</h2><p>Isso leva até 1 minuto. A página atualiza sozinha.</p><script>setTimeout(()=>location.reload(),5000)</script>`
    : `<h2 class="bad">Falta liberar o acesso</h2><p>${esc(s.cert.error || (s.listen.https && s.listen.https !== 'ok' ? s.listen.https : 'Ainda não consegui o certificado HTTPS.'))}</p>
      <ol><li>No painel da nuvem onde a VM está (Azure, AWS, Google Cloud, Oracle, Hostinger…), abra as regras de rede/firewall da VM e libere as portas <b>80</b> e <b>443</b> (TCP) para qualquer origem.</li>
      <li>Confira se outro programa (IIS, Apache, Skype…) não está usando as portas 80 e 443.</li>
      <li>Clique em <b>Tentar de novo</b>.</li></ol>
      <form method="post" action="/tentar"><button>Tentar de novo</button></form>`}</div>
  <div class="card"><h2>Situação</h2><table>
    ${row('Endereço', s.url ? `<code>${esc(s.url)}</code>` : '—')}
    ${row('IP público', esc(s.ip || 'descobrindo…'))}
    ${row('Certificado HTTPS', s.cert.status === 'ok' ? `<span class="ok">válido até ${new Date(s.cert.notAfter).toLocaleString('pt-BR')}</span> <span class="mut">(renova sozinho)</span>` : s.cert.status === 'error' ? '<span class="bad">não conseguiu (veja acima)</span>' : '<span class="warn">pedindo à Let\'s Encrypt…</span>')}
    ${row('Portas', `80 (verificação) ${s.listen.http === 'ok' ? '<span class="ok">✓</span>' : `<span class="bad">${esc(s.listen.http || '…')}</span>`} · 443 (equipe) ${s.listen.https === 'ok' ? '<span class="ok">✓</span>' : `<span class="bad">${esc(s.listen.https || '…')}</span>`}`)}
    ${row('Equipes', s.teams.length ? s.teams.map((t) => `${esc(t.name)} <span class="mut">(${t.people} ${t.people === 1 ? 'pessoa' : 'pessoas'})</span>`).join('<br>') : '<span class="mut">nenhuma ainda</span>')}
    ${row('Contas cadastradas', s.users)}
    ${row('Último backup', s.lastBackup ? `${new Date(s.lastBackup.at).toLocaleString('pt-BR')} <span class="mut">(${esc(s.lastBackup.file)})</span>` : '<span class="mut">ainda não</span>')}
    ${row('Pasta dos dados', `<code>${esc(s.data)}</code>`)}
  </table><form method="post" action="/backup" style="margin-top:12px"><button class="g">Fazer backup agora</button></form></div>
  <div class="card"><h2>Endereço da máquina</h2><p class="mut">O Ponte Servidor descobre o IP público sozinho. Se a VM tiver um domínio seu (ex.: equipe.minhaloja.com.br) apontando para ela, informe aqui.</p>
    <form method="post" action="/endereco"><table>${row('IP público (vazio = automático)', `<input name="ip" value="${esc(s.ipOverride || '')}" placeholder="${esc(s.ip || '')}">`)}${row('Domínio (opcional)', `<input name="domain" value="${esc(s.domain || '')}" placeholder="equipe.minhaloja.com.br">`)}</table>
    <button style="margin-top:10px">Salvar e pedir certificado</button></form></div>
  ${s.errors.length ? `<div class="card"><h2>Últimos problemas</h2>${s.errors.map((e) => `<div class="mut" style="font-size:13px">${new Date(e.at).toLocaleString('pt-BR')} · ${esc(e.where)}: ${esc(e.error)}</div>`).join('')}</div>` : ''}`);
}
function formBody(req) {
  return new Promise((ok) => { let s = ''; req.on('data', (c) => { s += c; if (s.length > 1e4) req.destroy(); }); req.on('end', () => ok(Object.fromEntries(new URLSearchParams(s)))); });
}
const statusServer = http.createServer(async (req, res) => {
  try {
    if (req.method === 'POST' && req.url === '/tentar') { ensureCert(true).catch(() => null); res.writeHead(303, { location: '/' }); return res.end(); }
    if (req.method === 'POST' && req.url === '/backup') { await backup('manual'); res.writeHead(303, { location: '/' }); return res.end(); }
    if (req.method === 'POST' && req.url === '/endereco') {
      const f = await formBody(req);
      const ip = String(f.ip || '').trim(), dom = String(f.domain || '').trim().toLowerCase();
      if (ip && !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) { res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' }); return res.end('IP inválido.'); }
      if (dom && !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(dom)) { res.writeHead(400, { 'content-type': 'text/plain; charset=utf-8' }); return res.end('Domínio inválido.'); }
      cfg.publicIp = ip; cfg.domain = dom; saveCfg();
      ensureCert(true).catch(() => null);
      res.writeHead(303, { location: '/' }); return res.end();
    }
    if (req.url === '/status.json') return send(res, 200, await statusData());
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
    res.end(statusPage(await statusData()));
  } catch (e) { problem('painel', e); res.writeHead(500); res.end('erro'); }
});

/* ------------------------------------------------------------------ portas */
function listen(server, port, host, name) {
  return new Promise((ok) => {
    server.once('error', (e) => {
      const msg = e.code === 'EADDRINUSE' ? `a porta ${port} já está em uso por outro programa` : e.code === 'EACCES' ? `sem permissão para usar a porta ${port}` : e.message;
      state.listen[name] = msg; saveState(); problem('porta ' + port, msg); ok(false);
    });
    server.listen(port, host, () => { state.listen[name] = 'ok'; saveState(); log(`ouvindo ${name} em ${host || '*'}:${port}`); ok(true); });
  });
}
const httpServer = http.createServer((req, res) => {
  const m = (req.url || '').match(/^\/\.well-known\/acme-challenge\/([A-Za-z0-9_-]+)$/);
  if (m) {
    const ka = challenges.get(m[1]);
    if (ka) { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end(ka); }
    res.writeHead(404); return res.end();
  }
  const host = String(req.headers.host || '').replace(/:\d+$/, '');
  res.writeHead(301, { location: `https://${host}${cfg.httpsPort === 443 ? '' : ':' + cfg.httpsPort}${req.url}` });
  res.end();
});

const initial = loadCert() || selfSigned(cfg.publicIp || '127.0.0.1');
httpsServer = https.createServer({ key: initial.key, cert: initial.cert }, apiHandler);
httpsServer.requestTimeout = 120e3;
await listen(statusServer, cfg.statusPort, '127.0.0.1', 'painel');
await listen(httpServer, cfg.httpPort, undefined, 'http');
await listen(httpsServer, cfg.httpsPort, undefined, 'https');
if (process.env.PONTE_HTTP_API_PORT) await listen(http.createServer(apiHandler), Number(process.env.PONTE_HTTP_API_PORT), '127.0.0.1', 'api-local');

ensureCert(false).catch((e) => problem('certificado', e));
setInterval(() => { ensureCert(false).catch((e) => problem('certificado', e)); }, 6 * 3600e3);
setInterval(() => { if (state.cert.status !== 'ok' && !renewing) ensureCert(false).catch(() => null); }, 10 * 60e3); // sem certificado: tenta de novo
// backup todo dia; um checkpoint de tempos em tempos para o banco ficar gravado no disco
setInterval(() => { db.exec('checkpoint').catch(() => null); }, 5 * 60e3);
setInterval(() => {
  const last = state.lastBackup ? new Date(state.lastBackup.at).getTime() : 0;
  if (Date.now() - last > 23.5 * 3600e3) backup('diario').catch((e) => problem('backup', e));
}, 30 * 60e3);
setTimeout(() => { if (!state.lastBackup || Date.now() - new Date(state.lastBackup.at).getTime() > 23.5 * 3600e3) backup('diario').catch((e) => problem('backup', e)); }, 60e3);

async function shutdown() {
  log('desligando…');
  try { await db.exec('checkpoint'); await db.close(); } catch { /* ignorado */ }
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
process.on('disconnect', shutdown); // o supervisor fechou: fecha junto
process.on('uncaughtException', (e) => problem('erro inesperado', e));
process.on('unhandledRejection', (e) => problem('erro inesperado', e));
log(`Ponte Servidor ${state.version} no ar · dados em ${DATA}`);
ready = true;
