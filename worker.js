/* Nuru server on Cloudflare
   - Serves the website (index.html, privacy.html, terms.html) from the same Worker.
   - /api/... : sign-in with Google (or an emailed code when RESEND_API_KEY is set), each person's saved data,
     the shared community (posts, replies, likes, groups, group chat, shop listings, events, registrations, shop chats,
     profiles and follows) and photos.
   Storage: D1 database "DB" for accounts, shared items, photos and each person's saved app data. If an R2 bucket is bound
   as "MEDIA", photos and saved data go there instead (R2 needs a payment method on the Cloudflare account; D1 does not).
   Settings (wrangler.jsonc "vars"): GOOGLE_CLIENT_ID, ADMIN_EMAILS. Optional secrets: RESEND_API_KEY, MAIL_FROM. */

const MAX_ITEM = 300 * 1024, MAX_STATE = 1900 * 1024, MAX_PHOTO = 1900 * 1024, PAGE = 300;   // D1 keeps up to 2 MB in one row
const COLS = new Set(['post', 'listing', 'event', 'group', 'gmsg', 'reg', 'dm', 'profile', 'pay', 'report', 'site']);
const OWNER_FIELD = {post:'by', listing:'by', event:'by', group:'owner', gmsg:'by', reg:'user', dm:'from', profile:'handle', pay:'payer', report:'by', site:'by'};
const SESSION_DAYS = 60;

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    if (req.method === 'OPTIONS') return new Response(null, {status:204, headers:cors(req)});
    try {
      if (!env.DB) return json({error:'not_configured'}, 503, req);
      await schema(env);
      const res = await route(req, env, url, ctx);
      for (const [k, v] of Object.entries(cors(req))) res.headers.set(k, v);
      return res;
    } catch (e) {
      if (e instanceof Http) return json(e.body, e.status, req);
      console.error(e && e.stack || e);
      return json({error:'server_error'}, 500, req);
    }
  }
};

class Http { constructor(status, body) { this.status = status; this.body = typeof body === 'string' ? {error:body} : body; } }
const fail = (status, error) => { throw new Http(status, error); };
function cors(req) {
  const o = req.headers.get('origin');
  return o ? {'access-control-allow-origin':o, 'access-control-allow-headers':'authorization, content-type, x-nuru-admin', 'access-control-allow-methods':'GET, POST, PUT, DELETE, OPTIONS', 'vary':'origin'} : {};
}
const json = (o, status = 200) => new Response(JSON.stringify(o), {status, headers:{'content-type':'application/json; charset=utf-8', 'cache-control':'no-store'}});
const now = () => Date.now();
const rid = (n = 24) => { const b = crypto.getRandomValues(new Uint8Array(n)); return [...b].map(x => x.toString(36).padStart(2, '0')).join('').slice(0, n * 1.5 | 0); };
async function sha(s) { const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s)); return [...new Uint8Array(d)].map(x => x.toString(16).padStart(2, '0')).join(''); }
async function body(req, max = MAX_STATE) {
  const t = await req.text(); if (t.length > max) fail(413, 'too_large');
  try { return t ? JSON.parse(t) : {}; } catch (e) { fail(400, 'bad_json'); }
}
const clean = (s, n) => String(s ?? '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, n);
const admins = env => String(env.ADMIN_EMAILS || '').toLowerCase().split(/[\s,]+/).filter(Boolean);   // the owners (super admins), set in wrangler.jsonc
async function roleOf(env, email, verified) {                            // 'owner' | 'admin' | null. Admins must have proven their email (Google)
  if (verified !== 1) return null; email = String(email || '').toLowerCase();
  if (admins(env).includes(email)) return 'owner';
  return (await env.DB.prepare(`SELECT 1 FROM admins WHERE email = ?`).bind(email).first()) ? 'admin' : null;
}
let REQ_IP = '';
async function audit(env, actor, action, target = '', detail = '') {
  try { await env.DB.prepare(`INSERT INTO audit (ts, actor, action, target, detail, ip) VALUES (?, ?, ?, ?, ?, ?)`)
    .bind(now(), String(actor || '').slice(0, 200), action, String(target || '').slice(0, 300), typeof detail === 'string' ? detail.slice(0, 1000) : JSON.stringify(detail).slice(0, 1000), REQ_IP).run(); } catch (e) {}
}

/* ---------- database ---------- */
let ready = false;
async function schema(env) {
  if (ready) return;
  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT, handle TEXT UNIQUE, dob TEXT, under13 INTEGER DEFAULT 0, created INTEGER, state_version INTEGER DEFAULT 0, banned INTEGER DEFAULT 0)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires INTEGER)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS codes (email TEXT PRIMARY KEY, hash TEXT, expires INTEGER, tries INTEGER DEFAULT 0, name TEXT, dob TEXT, sent INTEGER)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS items (col TEXT NOT NULL, id TEXT NOT NULL, owner TEXT NOT NULL, data TEXT, seq INTEGER NOT NULL, deleted INTEGER DEFAULT 0, vis TEXT DEFAULT 'public', party TEXT, scope TEXT, created INTEGER, PRIMARY KEY (col, id))`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS items_seq ON items (seq)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS reactions (col TEXT, id TEXT, handle TEXT, kind TEXT, PRIMARY KEY (col, id, handle, kind))`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS members (gid TEXT, handle TEXT, PRIMARY KEY (gid, handle))`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v INTEGER)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS hits (k TEXT PRIMARY KEY, n INTEGER, until INTEGER)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS blobs (k TEXT PRIMARY KEY, type TEXT, data BLOB, created INTEGER)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS admins (email TEXT PRIMARY KEY, added_by TEXT, added_at INTEGER)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_pw (email TEXT PRIMARY KEY, hash TEXT, set_at INTEGER)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS admin_keys (key TEXT PRIMARY KEY, user_id TEXT, expires INTEGER)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, actor TEXT, action TEXT, target TEXT, detail TEXT, ip TEXT)`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts)`),
    env.DB.prepare(`INSERT OR IGNORE INTO meta (k, v) VALUES ('seq', 0)`)
  ]);
  for (const c of ['pw TEXT', 'verified INTEGER', 'handle_set INTEGER', 'handle_changed INTEGER']) { try { await env.DB.prepare(`ALTER TABLE users ADD COLUMN ${c}`).run(); } catch (e) {} }   // email + password accounts
  await env.DB.prepare(`UPDATE users SET verified = 1 WHERE verified IS NULL AND pw IS NULL`).run();   // accounts made with Google or an email code
  ready = true;
}
async function nextSeq(env) { const r = await env.DB.prepare(`UPDATE meta SET v = v + 1 WHERE k = 'seq' RETURNING v`).first(); return r.v; }
async function limit(env, key, n, windowMs) {
  const t = now(), r = await env.DB.prepare(`SELECT n, until FROM hits WHERE k = ?`).bind(key).first();
  if (!r || r.until < t) { await env.DB.prepare(`INSERT OR REPLACE INTO hits (k, n, until) VALUES (?, 1, ?)`).bind(key, t + windowMs).run(); return; }
  if (r.n >= n) fail(429, 'too_many');
  await env.DB.prepare(`UPDATE hits SET n = n + 1 WHERE k = ?`).bind(key).run();
}

/* ---------- accounts ---------- */
function ageOf(dob) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dob || ''); if (!m) return null;
  const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3])); if (isNaN(d) || d.getUTCDate() !== +m[3]) return null;
  const t = new Date(); let a = t.getUTCFullYear() - d.getUTCFullYear();
  if (t.getUTCMonth() < d.getUTCMonth() || (t.getUTCMonth() === d.getUTCMonth() && t.getUTCDate() < d.getUTCDate())) a--;
  return a;
}
const userOut = u => ({id:u.id, email:u.email, name:u.name, handle:u.handle, dob:u.under13 ? null : u.dob, under13:!!u.under13, handleSet:!!u.handle_set, handleChanged:u.handle_changed || 0});
async function freeHandle(env, base) {
  let h = (base || 'friend').toLowerCase().normalize('NFKD').replace(/[^a-z0-9_]/g, '').slice(0, 14) || 'friend';
  if (h.length < 3) h = (h + 'friend').slice(0, 8);
  for (let i = 0; i < 30; i++) {
    const c = i ? h + '_' + Math.floor(Math.random() * (i < 10 ? 1000 : 100000)) : h;
    if (!(await env.DB.prepare(`SELECT 1 FROM users WHERE handle = ?`).bind(c).first())) return c;
  }
  return h + '_' + rid(4);
}
/* ---------- usernames, like TikTok: unique, checked live, with Christian suggestions ---------- */
const HANDLE_RESERVED = new Set(['admin', 'admins', 'administrator', 'nuru', 'nuruapp', 'nuruofficial', 'support', 'help', 'helpdesk', 'moderator', 'mod', 'mods', 'official', 'team', 'staff', 'system', 'root', 'security',
  'jesus', 'christ', 'jesuschrist', 'god', 'yahweh', 'jehovah', 'holyspirit', 'thelord', 'lord', 'pope', 'bible', 'null', 'undefined', 'api', 'www', 'settings', 'login', 'signup', 'everyone']);
const HANDLE_BAD = /(fuck|shit|bitch|sexy|porn|xxx|nude|satan|devil|666|lucifer|witchcraft|nigg|whore|slut|pussy|bhang|cocaine|betting|casino|bastard|idiot|stupid)/i;
function handleRule(h) {
  if (h.length < 3) return 'Use at least 3 characters';
  if (h.length > 24) return 'Use 24 characters or fewer';
  if (!/^[a-z0-9._]+$/.test(h)) return 'Use only letters, numbers, underscores (_) and full stops (.)';
  if (!/^[a-z]/.test(h)) return 'Start your username with a letter';
  if ((h.match(/[a-z]/g) || []).length < 3) return 'Use at least 3 letters, not only numbers';
  if (/\.\./.test(h) || h.endsWith('.')) return 'A full stop cannot be doubled or come last';
  if (HANDLE_RESERVED.has(h.replace(/[._\d]/g, ''))) return 'This username is reserved. Try another one';
  if (HANDLE_BAD.test(h)) return 'This username is not allowed on Nuru. Try another one';
  return '';
}
const CH_ADJ = ['blessed', 'faithful', 'joyful', 'humble', 'grateful', 'chosen', 'redeemed', 'graceful', 'hopeful', 'beloved', 'prayerful', 'anointed'];
const CH_NOUN = ['servant', 'disciple', 'pilgrim', 'lamb', 'light', 'vessel', 'shepherd', 'psalmist', 'worshipper', 'saint', 'olive', 'dove'];
const CH_TAG = ['psalm23', 'john316', 'prov35', 'isaiah4031', 'jer2911', 'phil413', 'rom828', 'josh19', 'matt514', 'gal522'];
async function suggestHandles(env, base, n = 6) {
  const pick = a => a[Math.floor(Math.random() * a.length)];
  let b = String(base || '').trim().split(/\s+/)[0].toLowerCase().normalize('NFKD').replace(/[^a-z]/g, '').slice(0, 12);
  if (b.length < 3) b = '';
  const out = new Set();
  for (let i = 0; i < 40 && out.size < n * 3; i++) {
    const r = Math.random(), a = pick(CH_ADJ), o = pick(CH_NOUN), t = pick(CH_TAG);
    out.add(b ? (r < .2 ? `${b}.${a}` : r < .4 ? `${a}.${b}` : r < .55 ? `${b}_${t}` : r < .7 ? `${b}4christ` : r < .85 ? `${b}.${o}` : `${a}_${b}`)
              : (r < .5 ? `${a}.${o}` : r < .8 ? `${a}_${o}${Math.floor(Math.random() * 90 + 10)}` : `${o}.${t}`));
  }
  const L = [...out].filter(h => !handleRule(h)), free = [];
  for (const h of L) { if (free.length >= n) break; if (!(await env.DB.prepare(`SELECT 1 FROM users WHERE handle = ?`).bind(h).first())) free.push(h); }
  return free;
}
/* a new username: everything the person owns moves with it */
const HANDLE_KEYS = new Set(['by', 'from', 'to', 'owner', 'user', 'handle', 'payer', 'members', 'admins', 'requests', 'with', 'h']);
async function moveHandle(env, from, to) {
  const swap = (v, k) => {
    if (typeof v === 'string') return HANDLE_KEYS.has(k) && v === from ? [to, true] : [v, false];
    if (Array.isArray(v)) { let ch = false; const a = v.map(x => { const [y, c] = swap(x, HANDLE_KEYS.has(k) ? k : ''); ch ||= c; return y; }); return [a, ch]; }
    if (v && typeof v === 'object') { let ch = false; const o = {}; for (const [kk, vv] of Object.entries(v)) { const [y, c] = swap(vv, kk); o[kk] = y; ch ||= c; } return [o, ch]; }
    return [v, false];
  };
  const rows = (await env.DB.prepare(`SELECT col, id, owner, data, created FROM items WHERE deleted = 0 AND (owner = ?1 OR data LIKE ?2)`).bind(from, `%"${from}"%`).all()).results;
  for (const r of rows) {
    let d; try { d = JSON.parse(r.data); } catch (e) { continue; }
    const [nd, ch] = swap(d, ''); if (!ch && r.owner !== from) continue;
    await writeItem(env, r.col, r.id, r.owner === from ? to : r.owner, nd, r.created);
  }
  await env.DB.batch([
    env.DB.prepare(`UPDATE OR IGNORE reactions SET handle = ? WHERE handle = ?`).bind(to, from),
    env.DB.prepare(`UPDATE OR IGNORE reactions SET id = ? WHERE col = 'profile' AND id = ?`).bind(to, from),
    env.DB.prepare(`UPDATE OR IGNORE members SET handle = ? WHERE handle = ?`).bind(to, from),
    env.DB.prepare(`UPDATE items SET owner = ? WHERE owner = ? AND deleted = 1`).bind(to, from)]);
}
/* passwords: PBKDF2-SHA256, 100,000 rounds, a random salt per account */
const b64 = a => btoa(String.fromCharCode(...new Uint8Array(a))), unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function pwHash(pw, salt = crypto.getRandomValues(new Uint8Array(16)), n = 100000) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2', hash:'SHA-256', salt, iterations:n}, k, 256);
  return `pbkdf2$${n}$${b64(salt)}$${b64(bits)}`;
}
async function pwCheck(pw, stored) {
  const [, n, salt] = String(stored || '').split('$'); if (!n || !salt) return false;
  const a = await pwHash(pw, unb64(salt), +n); if (a.length !== stored.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ stored.charCodeAt(i); return d === 0;
}
const pwOk = pw => typeof pw === 'string' && pw.length >= 8 && pw.length <= 128 && /[A-Za-z]/.test(pw) && /\d/.test(pw);
const emailOk = e => /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(e) && e.length <= 200;
async function newSession(env, u) {
  const token = rid(32);
  await env.DB.prepare(`INSERT INTO sessions (token, user_id, expires) VALUES (?, ?, ?)`).bind(await sha(token), u.id, now() + SESSION_DAYS * 864e5).run();
  return {token, user:userOut(u), admin:!!(await roleOf(env, u.email, u.verified)), role:await roleOf(env, u.email, u.verified)};
}
async function createUser(env, email, name, dob, extra = {}) {
  const age = ageOf(dob);
  if (age === null || age > 120) fail(400, 'invalid_dob');
  if (age < 5) fail(400, 'dob_too_young');
  const u = {id:'u' + rid(12), email, name:clean(name || email.split('@')[0], 60), handle:await freeHandle(env, name || email.split('@')[0]), dob:age < 13 ? null : dob, under13:age < 13 ? 1 : 0, created:now(), pw:extra.pw || null, verified:extra.verified ? 1 : 0};
  await env.DB.prepare(`INSERT INTO users (id, email, name, handle, dob, under13, created, pw, verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(u.id, u.email, u.name, u.handle, u.dob, u.under13, u.created, u.pw, u.verified).run();
  await putProfile(env, u);
  return u;
}
/* Google or an emailed code: the email is proven. Find or create the account, then open a session.
   A password someone set on this email without proving it stops working here, so nobody keeps a way into it. */
async function signIn(env, email, name, dob) {
  email = String(email).toLowerCase().trim();
  let u = await env.DB.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();
  if (u && u.verified !== 1) {
    await env.DB.batch([env.DB.prepare(`UPDATE users SET verified = 1, pw = NULL WHERE id = ?`).bind(u.id), env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(u.id)]);
    u.verified = 1; u.pw = null;
  }
  if (!u) {
    if (!dob) throw new Http(428, {error:'need_birthday', name:clean(name, 60)});   // new account: the app asks "When's your birthday?" then tries again
    u = await createUser(env, email, name, dob, {verified:true});
    await audit(env, email, 'sign_up', email, 'Google or email code');
  } else await audit(env, email, 'sign_in', email, 'Google or email code');
  if (u.banned) { await audit(env, email, 'sign_in_blocked', email, 'banned'); fail(403, 'banned'); }
  return newSession(env, u);
}
async function auth(req, env) {
  const t = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!t) fail(401, 'signed_out');
  const r = await env.DB.prepare(`SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires > ?`).bind(await sha(t), now()).first();
  if (!r) fail(401, 'signed_out');
  if (r.banned) fail(403, 'banned');
  r.role = await roleOf(env, r.email, r.verified);
  r.admin = false;                                                       // admin powers need the role AND an unlocked admin password (30 minutes, renewed while used)
  const k = req.headers.get('x-nuru-admin');
  if (r.role && k) {
    const hk = await sha(k), a = await env.DB.prepare(`SELECT expires FROM admin_keys WHERE key = ? AND user_id = ?`).bind(hk, r.id).first();
    if (a && a.expires > now()) { r.admin = true; if (a.expires - now() < 25 * 6e4) await env.DB.prepare(`UPDATE admin_keys SET expires = ? WHERE key = ?`).bind(now() + 30 * 6e4, hk).run(); }
  }
  r.actor = r.email;
  return r;
}

/* Google: the app sends the access token Google gave it; we check it was issued to Nuru and read the verified email */
async function google(env, token) {
  const get = async (u, o) => { try { return await (await fetch(u, o)).json(); } catch (e) { fail(502, 'google_unreachable'); } };
  const ti = await get('https://oauth2.googleapis.com/tokeninfo?access_token=' + encodeURIComponent(token));
  const want = String(env.GOOGLE_CLIENT_ID || '');
  if (!ti || ti.error || !want || (ti.aud !== want && ti.azp !== want)) fail(401, 'google_failed');
  const ui = await get('https://openidconnect.googleapis.com/v1/userinfo', {headers:{authorization:'Bearer ' + token}});
  if (!ui || !ui.email) fail(401, 'google_failed');
  if (ui.email_verified === false || ui.email_verified === 'false') fail(401, 'email_unverified');
  return ui;
}

/* emailed 6-digit codes (only when an email service is set up) */
async function sendCode(env, email, code) {
  const r = await fetch('https://api.resend.com/emails', {method:'POST', headers:{authorization:'Bearer ' + env.RESEND_API_KEY, 'content-type':'application/json'},
    body:JSON.stringify({from:env.MAIL_FROM || 'Nuru <onboarding@resend.dev>', to:[email], subject:`${code} is your Nuru sign-in code`,
      text:`Your Nuru sign-in code is ${code}. It works for 10 minutes. If you did not ask for it, you can ignore this email.`,
      html:`<div style="font-family:system-ui,sans-serif;font-size:16px;color:#221C35"><p>Your Nuru sign-in code is</p><p style="font-size:32px;font-weight:800;letter-spacing:6px">${code}</p><p>It works for 10 minutes. If you did not ask for it, you can ignore this email.</p></div>`})});
  if (!r.ok) fail(502, 'email_failed');
}

/* ---------- photos and saved data: R2 when bound, otherwise D1 ---------- */
const store = {
  async put(env, k, data, type) {
    if (env.MEDIA) return env.MEDIA.put(k, data, {httpMetadata:{contentType:type, cacheControl:type.startsWith('image/') ? 'public, max-age=31536000, immutable' : 'no-store'}});
    const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data);
    await env.DB.prepare(`INSERT OR REPLACE INTO blobs (k, type, data, created) VALUES (?, ?, ?, ?)`).bind(k, type, bytes, now()).run();
  },
  async get(env, k) {                                       // -> {type, bytes} | null
    if (env.MEDIA) { const o = await env.MEDIA.get(k); return o ? {type:o.httpMetadata?.contentType || '', bytes:new Uint8Array(await o.arrayBuffer())} : null; }
    const r = await env.DB.prepare(`SELECT type, data FROM blobs WHERE k = ?`).bind(k).first();
    return r ? {type:r.type, bytes:new Uint8Array(r.data)} : null;
  },
  async text(env, k) { const o = await this.get(env, k); return o ? new TextDecoder().decode(o.bytes) : null; },
  async delPrefix(env, prefix) {
    if (env.MEDIA) { let c; do { const l = await env.MEDIA.list({prefix, cursor:c}); if (l.objects.length) await env.MEDIA.delete(l.objects.map(o => o.key)); c = l.truncated ? l.cursor : null; } while (c); return; }
    await env.DB.prepare(`DELETE FROM blobs WHERE k LIKE ?`).bind(prefix.replace(/[%_]/g, '') + '%').run();
  }
};
const IMG = {'image/jpeg':'jpg', 'image/png':'png', 'image/webp':'webp', 'image/gif':'gif'};
async function upload(req, env, u) {
  await limit(env, 'up:' + u.id, 120, 36e5);
  const type = (req.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
  if (!IMG[type]) fail(415, 'not_an_image');
  const buf = await req.arrayBuffer(); if (!buf.byteLength) fail(400, 'empty'); if (buf.byteLength > MAX_PHOTO) fail(413, 'too_large');
  const key = `p/${u.id}/${rid(16)}.${IMG[type]}`;
  await store.put(env, key, buf, type);
  return json({url:new URL(req.url).origin + '/api/media/' + key});
}
async function media(env, key) {
  if (!/^p\/[\w-]+\/[\w-]+\.(jpg|png|webp|gif)$/.test(key)) fail(404, 'not_found');
  const o = await store.get(env, key); if (!o) fail(404, 'not_found');
  return new Response(o.bytes, {headers:{'content-type':o.type || 'image/jpeg', 'cache-control':'public, max-age=31536000, immutable', 'x-content-type-options':'nosniff'}});
}

/* ---------- shared items ---------- */
function visOf(col, d, owner) {                     // who can see an item: [vis, party, scope]
  if (col === 'pay' || col === 'report') return ['review', null, null];   // M-Pesa payments and reports: the person and admins only
  if (col === 'site') return ['public', null, null];                 // Admin Studio settings everyone's app follows
  if (col === 'listing') return [['live', 'sold', 'active'].includes(d.status) ? 'public' : 'review', null, null];
  if (col === 'event') return [d.status === 'draft' || d.visibility === 'private' ? 'private' : 'public', null, null];
  if (col === 'gmsg') return ['group', null, String(d.gid || '')];
  if (col === 'post' && d.groupId) return ['group', null, String(d.groupId)];
  if (col === 'dm') return ['private', String(d.to || ''), null];
  if (col === 'reg') return ['private', String(d.host || ''), null];
  return ['public', null, null];
}
async function getItem(env, col, id) {
  const r = await env.DB.prepare(`SELECT * FROM items WHERE col = ? AND id = ?`).bind(col, id).first();
  if (r && r.data) r.d = JSON.parse(r.data); return r;
}
async function writeItem(env, col, id, owner, d, created) {
  const [vis, party, scope] = visOf(col, d, owner), seq = await nextSeq(env);
  if (col === 'post' && d.groupId) {               // posts in a public group stay public
    const g = await getItem(env, 'group', String(d.groupId)); if (!g || !g.d || g.d.privacy !== 'private') { await env.DB.prepare(`INSERT INTO items (col, id, owner, data, seq, deleted, vis, party, scope, created) VALUES (?, ?, ?, ?, ?, 0, 'public', NULL, NULL, ?) ON CONFLICT (col, id) DO UPDATE SET owner = excluded.owner, data = excluded.data, seq = excluded.seq, deleted = 0, vis = 'public', party = NULL, scope = NULL`).bind(col, id, owner, JSON.stringify(d), seq, created || now()).run(); return seq; }
  }
  await env.DB.prepare(`INSERT INTO items (col, id, owner, data, seq, deleted, vis, party, scope, created) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
    ON CONFLICT (col, id) DO UPDATE SET owner = excluded.owner, data = excluded.data, seq = excluded.seq, deleted = 0, vis = excluded.vis, party = excluded.party, scope = excluded.scope`)
    .bind(col, id, owner, JSON.stringify(d), seq, vis, party, scope, created || now()).run();
  return seq;
}
async function bump(env, col, id, d) { await env.DB.prepare(`UPDATE items SET data = ?, seq = ? WHERE col = ? AND id = ?`).bind(JSON.stringify(d), await nextSeq(env), col, id).run(); }
async function putProfile(env, u, extra) {
  const old = await getItem(env, 'profile', u.id), d = {...(old?.d || {}), ...(extra || {}), handle:u.handle, name:u.name};
  d.followers = (await env.DB.prepare(`SELECT COUNT(*) n FROM reactions WHERE col = 'profile' AND id = ? AND kind = 'follow'`).bind(u.handle).first()).n;
  d.following = (await env.DB.prepare(`SELECT COUNT(*) n FROM reactions WHERE col = 'profile' AND handle = ? AND kind = 'follow'`).bind(u.handle).first()).n;
  await writeItem(env, 'profile', u.id, u.handle, d);
}
async function isGroupAdmin(env, gid, h) { const g = await getItem(env, 'group', gid); return !!(g && g.d && (g.d.owner === h || (g.d.admins || []).includes(h))); }
async function syncMembers(env, gid, list) {
  await env.DB.prepare(`DELETE FROM members WHERE gid = ?`).bind(gid).run();
  const L = [...new Set((list || []).map(String))].slice(0, 5000);
  for (let i = 0; i < L.length; i += 50) await env.DB.batch(L.slice(i, i + 50).map(h => env.DB.prepare(`INSERT OR IGNORE INTO members (gid, handle) VALUES (?, ?)`).bind(gid, h)));
}
const hasBigImage = o => { let bad = false; const walk = v => { if (bad || !v) return; if (typeof v === 'string') { if (v.startsWith('data:') && v.length > 200000) bad = true; } else if (typeof v === 'object') for (const k in v) walk(v[k]); }; walk(o); return bad; };
const paidOrSupport = d => !!((d.tickets || []).some(t => +t.price > 0) || (d.support && d.support.on) || d.regType === 'paid');

async function putSite(env, u, data) {
  if (!u.admin) fail(403, 'not_admin');
  const old = await getItem(env, 'site', 'mod'), was = old?.d || {}, d = {...data, by:'site'};
  const before = new Set(was.banned || []), after = new Set(d.banned || []);
  for (const h of after) if (!before.has(h)) { const t = await env.DB.prepare(`SELECT id FROM users WHERE handle = ?`).bind(h).first();
    if (t) await env.DB.batch([env.DB.prepare(`UPDATE users SET banned = 1 WHERE id = ?`).bind(t.id), env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(t.id)]);
    await audit(env, u.actor, 'ban', '@' + h); }
  for (const h of before) if (!after.has(h)) { await env.DB.prepare(`UPDATE users SET banned = 0 WHERE handle = ?`).bind(h).run(); await audit(env, u.actor, 'unban', '@' + h); }
  const changed = Object.keys({...was, ...d}).filter(k => !['banned', 'by', 'id'].includes(k) && JSON.stringify(was[k]) !== JSON.stringify(d[k]));
  if (changed.length) await audit(env, u.actor, 'studio_settings', changed.join(', '));
  await writeItem(env, 'site', 'mod', 'site', d, old?.created);
}
/* ---------- automatic listing review ----------
   Every listing is checked the moment it is saved. Clean listings go live at once;
   anything that breaks the shop rules is rejected with a reason the seller can fix;
   only unclear cases wait for a person. */
const LISTING_BANNED = [
  [/\b(guns?|pistols?|rifles?|firearms?|ammunition|ammo|bullets?|grenades?|explosives?|machetes? for sale|tasers?|pepper spray)\b/i, 'Weapons are not allowed on Nuru'],
  [/\b(weed|bhang|marijuana|cannabis|cocaine|heroin|meth|mira+a|khat|muguka|kush|edibles|psychedelics?|shrooms|lsd|ecstasy|mdma|codeine syrup|tramadol)\b/i, 'Drugs are not allowed on Nuru'],
  [/\b(beers?|wines?|whisk(e)?y|vodka|gin|brandy|liquor|alcohol|chang'?aa|busaa|spirits? drink|cigarettes?|cigars?|tobacco|shisha|hookah|vapes?|e-?cig(arette)?s?)\b/i, 'Alcohol and tobacco are not allowed on Nuru'],
  [/\b(betting|bet slips?|sure ?bets?|jackpot tips|casino|gambling|lottery tickets?|fixed matches)\b/i, 'Betting and gambling are not allowed on Nuru'],
  [/\b(porn|xxx|nude|nudes|sex ?toys?|adult toys?|escort|hookup|onlyfans|lingerie models?)\b/i, 'Adult content is not allowed on Nuru'],
  [/\b(tarot|horoscopes?|astrology|ouija|witchcraft|charms? for luck|love portions?|love potions?|spell ?casters?|occult|black magic|juju|uganga|mganga)\b/i, 'Occult items are not allowed on Nuru'],
  [/\b(replica|fake (id|ids|passport|certificates?|money|notes)|counterfeit|first copy|clone (phone|watch|bag))\b/i, 'Counterfeit or fake items are not allowed on Nuru'],
  [/\b(get rich quick|double your money|investment scheme|forex signals|pyramid|ponzi|crypto doubling|loans? without)\b/i, 'Money schemes are not allowed on Nuru'],
];
const LISTING_HOLD = [
  [/https?:\/\/|www\.|\.(com|net|org|co\.ke|ly)\b/i, 'Links in a listing are checked by a person first'],
  [/\b(deposit first|send (money|cash) first|pay before (viewing|delivery)|advance payment)\b/i, 'Asking for money before delivery is checked by a person first'],
];
/* first listing free; each extra one needs its own M-Pesa listing fee (or an active seller plan) */
async function listingPaid(env, h, id) {
  const first = await env.DB.prepare(`SELECT id FROM items WHERE col = 'listing' AND owner = ? ORDER BY created ASC, rowid ASC LIMIT 1`).bind(h).first();
  if (!first || first.id === id) return true;
  const q = `SELECT 1 FROM items WHERE col = 'pay' AND owner = ? AND deleted = 0 AND COALESCE(json_extract(data, '$.status'), 'pending') <> 'rejected'`;
  if (await env.DB.prepare(q + ` AND json_extract(data, '$.plan.listingId') = ? AND COALESCE(json_extract(data, '$.amount'), 0) >= 100`).bind(h, id).first()) return true;
  if (await env.DB.prepare(q + ` AND json_extract(data, '$.plan.kind') = 'tier' AND created > ?`).bind(h, now() - 30 * 864e5).first()) return true;
  return false;
}
async function reviewListing(env, d, was) {
  const st = String(d.status || 'pending');
  delete d.autoNote;
  if (['sold', 'paused', 'draft'].includes(st)) return;
  if (st === 'unpaid') d.status = 'live';                         // the seller can always pause, finish or mark sold
  if (was && was.reviewedBy === 'admin' && ['rejected', 'removed'].includes(was.status)) {   // an admin's decision: the fix goes to a person
    const same = ['name', 'desc', 'cat', 'price', 'img', 'details'].every(k => JSON.stringify(was[k]) === JSON.stringify(d[k]));
    if (same) { d.status = was.status; d.reason = was.reason; d.reviewedBy = 'admin'; return; }
    d.status = 'pending'; d.reason = 'Sent back to the admin for a second look'; delete d.reviewedBy; d.autoNote = 1; return;
  }
  delete d.reviewedBy;
  const reject = r => { d.status = 'rejected'; d.reason = r; d.autoNote = 1; d.reviewed = Date.now(); };
  const name = String(d.name || '').trim(), price = Math.round(+d.price), was0 = Math.round(+d.was || 0);
  if (name.length < 3) return reject('Give the item a clear name (at least 3 letters)');
  if (!(price > 0) || price > 10000000) return reject('Enter a price between KSh 1 and KSh 10,000,000');
  if (was0 && was0 > price) {                                                   // a discount must be believable
    if (Math.round((1 - price / was0) * 100) > 90) return reject('A discount can be at most 90% off');
  } else delete d.was;
  if (d.stock != null && d.stock !== '' && !(+d.stock >= 0 && +d.stock <= 100000)) return reject('Enter how many you have in stock');
  const text = [name, d.desc, d.cat, d.loc, ...Object.values(d.details || d.specs || {})].filter(v => typeof v === 'string').join(' \n ');
  for (const [re, why] of LISTING_BANNED) if (re.test(text)) return reject(why);
  const site = await getItem(env, 'site', 'mod'), words = (site?.d?.words || []).map(w => String(w).toLowerCase()).filter(Boolean);
  const low = text.toLowerCase(), hit = words.find(w => low.includes(w));
  if (hit) return reject('This listing uses words the shop rules do not allow');
  for (const [re, why] of LISTING_HOLD) if (re.test(text)) { d.status = 'pending'; d.reason = why; d.autoNote = 1; return; }
  d.status = 'live'; delete d.reason; d.reviewed = Date.now();
  if (!was || was.status !== 'live') d.autoNote = 1;
}
async function put(env, u, {col, id, data}) {
  if (!COLS.has(col) || col === 'profile') fail(400, 'bad_col');
  if (col === 'site') { if (!data || typeof data !== 'object' || JSON.stringify(data).length > MAX_ITEM) fail(400, 'bad_data'); return putSite(env, u, data); }
  id = String(id || ''); if (!id || id.length > 80) fail(400, 'bad_id');
  if (!data || typeof data !== 'object') fail(400, 'bad_data');
  const raw = JSON.stringify(data); if (raw.length > MAX_ITEM || hasBigImage(data)) fail(413, 'too_large');
  const h = u.handle, old = await getItem(env, col, id), live = old && !old.deleted && old.d;
  let d = {...data, id};
  if (live) {
    const ok = old.owner === h || u.admin || (col === 'group' && ((old.d.admins || []).includes(h) || old.d.owner === h))
      || (col === 'reg' && old.d.host === h) || (col === 'gmsg' && await isGroupAdmin(env, String(old.d.gid), h));
    if (!ok) fail(403, 'not_yours');
    d[OWNER_FIELD[col]] = old.d[OWNER_FIELD[col]];                       // nobody can take over an item
    if (col === 'post') { d.replies = old.d.replies || []; d.likes = old.d.likes || 0; d.reposts = old.d.reposts || 0; }
    if (col === 'reg') d.host = old.d.host;
  } else {
    if (String(data[OWNER_FIELD[col]]) !== h) fail(403, 'not_yours');
    if (u.under13 && !['reg', 'pay', 'report'].includes(col)) fail(403, 'under13');
    if (col === 'post') { d.replies = []; d.likes = 0; d.reposts = 0; }
    if (col === 'reg') { const e = await getItem(env, 'event', String(data.eventId || '')); if (!e || !e.d) fail(404, 'no_event'); d.host = e.d.by; }
    if (col === 'gmsg') { const g = await getItem(env, 'group', String(data.gid || '')); if (!g || !g.d) fail(404, 'no_group');
      if (!(g.d.members || []).includes(h) && g.d.owner !== h) fail(403, 'not_member'); }
    if (col === 'dm' && !data.to) fail(400, 'no_recipient');
  }
  if (col === 'event' && paidOrSupport(d) && (old?.owner || h) === h && (u.under13 || (ageOf(u.dob) ?? 0) < 18)) fail(422, 'adults_only');
  if (col === 'listing' && !u.admin) {                                    // checked automatically, like TikTok
    await reviewListing(env, d, live ? old.d : null);
    if (['live', 'pending', 'unpaid'].includes(d.status) && !(await listingPaid(env, live ? old.owner : h, id))) { d.status = 'unpaid'; d.reason = 'Your first listing was free. Pay the listing fee to publish this one'; }
  }
  if (col === 'pay') {                                                  // only admins confirm or reject; each M-Pesa code counts once
    if (!u.admin) d.status = live ? old.d.status : 'pending';
    d.code = String(d.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
    if (!live && d.code && await env.DB.prepare(`SELECT 1 FROM items WHERE col = 'pay' AND id <> ? AND deleted = 0 AND json_extract(data, '$.code') = ?`).bind(id, d.code).first()) d.status = 'duplicate';
    d.payer = live ? old.d.payer : h; d.email = live ? old.d.email : u.email;
  }
  delete d.liked; delete d.reposted;
  if (live && old.owner !== h && u.admin) {                                   // record what admins change on other people's things
    if (col === 'pay' && old.d.status !== d.status) await audit(env, u.actor, d.status === 'confirmed' ? 'payment_confirmed' : d.status === 'rejected' ? 'payment_rejected' : 'payment_' + d.status, '@' + old.owner, `${d.code || ''} · KSh ${d.amount || ''} · ${d.what || ''}`);
    else if (col === 'listing' && old.d.status !== d.status) { d.reviewedBy = 'admin'; await audit(env, u.actor, 'listing_' + d.status, '@' + old.owner, d.name || id); }
    else await audit(env, u.actor, 'admin_edit', `${col} ${id} by @${old.owner}`, Object.keys(d).filter(k => JSON.stringify(d[k]) !== JSON.stringify(old.d[k])).join(', '));
  }
  await writeItem(env, col, id, live ? old.owner : h, d, old?.created);
  if (col === 'pay' && d.plan?.listingId) {
    const L = await getItem(env, 'listing', String(d.plan.listingId));
    if (L && !L.deleted && L.d && L.owner === (live ? old.owner : h)) {
      if (d.status === 'rejected' && ['live', 'pending', 'sold'].includes(L.d.status)) { L.d.status = 'unpaid'; L.d.reason = 'We could not find your M-Pesa payment for this listing'; await writeItem(env, 'listing', L.id || String(d.plan.listingId), L.owner, L.d, L.created); }
      else if (d.status !== 'rejected' && L.d.status === 'unpaid') { const ld = {...L.d, status:'live'}; await reviewListing(env, ld, L.d); if (ld.status === 'live' || ld.status === 'pending') await writeItem(env, 'listing', String(d.plan.listingId), L.owner, ld, L.created); }
    }
  }
  if (col === 'listing' && d.autoNote && (!live || old.d.status !== d.status)) await audit(env, 'auto-review', 'listing_auto_' + d.status, '@' + h, `${d.name || id}${d.reason ? ' · ' + d.reason : ''}`);
  if (col === 'group' && (!live || old.d.owner === h || (old.d.admins || []).includes(h) || u.admin)) await syncMembers(env, id, d.members);
}
async function del(env, u, {col, id}) {
  if (!COLS.has(col) || col === 'profile') fail(400, 'bad_col');
  const old = await getItem(env, col, String(id)); if (!old || old.deleted) return;
  if (col === 'pay' && !u.admin) fail(403, 'not_yours');                 // payment records stay
  if (col === 'site') fail(403, 'not_yours');
  const ok = old.owner === u.handle || u.admin || (col === 'gmsg' && await isGroupAdmin(env, String(old.d?.gid), u.handle)) || (col === 'post' && old.d?.groupId && await isGroupAdmin(env, String(old.d.groupId), u.handle));
  if (!ok) fail(403, 'not_yours');
  if (old.owner !== u.handle) await audit(env, u.actor, col === 'report' ? 'report_closed' : 'admin_delete', `${col} ${id} by @${old.owner}`, col === 'post' ? String(old.d?.text || '').slice(0, 160) : (old.d?.name || old.d?.title || ''));
  await env.DB.prepare(`UPDATE items SET data = NULL, deleted = 1, seq = ? WHERE col = ? AND id = ?`).bind(await nextSeq(env), col, String(id)).run();
  if (col === 'group') await env.DB.prepare(`DELETE FROM members WHERE gid = ?`).bind(String(id)).run();
}
async function op(env, u, {col, id, op, arg}) {
  const h = u.handle; id = String(id || '');
  if (col === 'profile' && (op === 'follow' || op === 'unfollow')) {
    if (id === h) return;
    const t = await env.DB.prepare(`SELECT * FROM users WHERE handle = ?`).bind(id).first(); if (!t) return;
    if (op === 'follow') await env.DB.prepare(`INSERT OR IGNORE INTO reactions (col, id, handle, kind) VALUES ('profile', ?, ?, 'follow')`).bind(id, h).run();
    else await env.DB.prepare(`DELETE FROM reactions WHERE col = 'profile' AND id = ? AND handle = ? AND kind = 'follow'`).bind(id, h).run();
    await putProfile(env, t); await putProfile(env, u); return;
  }
  const it = await getItem(env, col, id); if (!it || it.deleted || !it.d) return;
  const d = it.d;
  if (col === 'post' && ['like', 'unlike', 'repost', 'unrepost'].includes(op)) {
    const kind = op.replace('un', '');
    if (op.startsWith('un')) await env.DB.prepare(`DELETE FROM reactions WHERE col = 'post' AND id = ? AND handle = ? AND kind = ?`).bind(id, h, kind).run();
    else await env.DB.prepare(`INSERT OR IGNORE INTO reactions (col, id, handle, kind) VALUES ('post', ?, ?, ?)`).bind(id, h, kind).run();
    d[kind + 's'] = (await env.DB.prepare(`SELECT COUNT(*) n FROM reactions WHERE col = 'post' AND id = ? AND kind = ?`).bind(id, kind).first()).n;
    return bump(env, col, id, d);
  }
  if (col === 'post' && op === 'reply') {
    if (u.under13) fail(403, 'under13');
    const r = {...(arg || {}), by:h, text:clean(arg && arg.text, 4000), ts:+(arg && arg.ts) || now()}; if (!r.text) return;
    d.replies = (d.replies || []).filter(x => !(x.by === h && x.ts === r.ts)); d.replies.push(r); d.replies.sort((a, b) => a.ts - b.ts);
    if (d.replies.length > 2000) d.replies = d.replies.slice(-2000);
    return bump(env, col, id, d);
  }
  if (col === 'post' && op === 'unreply') {
    const by = String(arg && arg.by || h), ts = +(arg && arg.ts);
    if (by !== h && it.owner !== h && !u.admin) fail(403, 'not_yours');
    d.replies = (d.replies || []).filter(x => !(x.by === by && x.ts === ts)); return bump(env, col, id, d);
  }
  if (col === 'group' && ['join', 'leave', 'request', 'unrequest'].includes(op)) {
    if (op === 'join' && u.under13) fail(403, 'under13');
    const rm = a => (a || []).filter(x => x !== h);
    if (op === 'join') { if (d.privacy === 'private') { d.requests = [...rm(d.requests), h]; } else { d.members = [...rm(d.members), h]; d.requests = rm(d.requests); await env.DB.prepare(`INSERT OR IGNORE INTO members (gid, handle) VALUES (?, ?)`).bind(id, h).run(); } }
    if (op === 'request') d.requests = [...rm(d.requests), h];
    if (op === 'unrequest') d.requests = rm(d.requests);
    if (op === 'leave') { if (d.owner === h) return; d.members = rm(d.members); d.admins = rm(d.admins); d.requests = rm(d.requests); await env.DB.prepare(`DELETE FROM members WHERE gid = ? AND handle = ?`).bind(id, h).run(); }
    return bump(env, col, id, d);
  }
}

/* one call does it all: send my changes, get everything new since last time */
async function sync(req, env, u) {
  const b = await body(req, 4 * 1024 * 1024), res = {results:[], items:[]};
  const work = [...(b.puts || []).map(x => ['put', x]), ...(b.dels || []).map(x => ['del', x]), ...(b.ops || []).map(x => ['op', x])].slice(0, 400);
  if (work.length) await limit(env, 'w:' + u.id, 600, 6e4);
  for (const [k, x] of work) {
    try { if (k === 'put') await put(env, u, x); else if (k === 'del') await del(env, u, x); else await op(env, u, x); res.results.push({k, col:x.col, id:x.id, ok:true}); }
    catch (e) { if (!(e instanceof Http)) throw e; res.results.push({k, col:x.col, id:x.id, ok:false, error:e.body.error, status:e.status}); }
  }
  if (b.profile && typeof b.profile === 'object') {
    const p = b.profile, extra = {}; for (const f of ['bio', 'location', 'color', 'photo', 'avatar', 'joined', 'cover']) if (p[f] != null && !(typeof p[f] === 'string' && p[f].startsWith('data:'))) extra[f] = typeof p[f] === 'string' ? p[f].slice(0, 2000) : p[f];
    const old = await getItem(env, 'profile', u.id), want = JSON.stringify(extra), have = JSON.stringify(Object.fromEntries(Object.keys(extra).map(k => [k, old?.d?.[k]])));
    if (want !== have) await putProfile(env, u, extra);
  }
  const since = Math.max(0, +b.since || 0), h = u.handle;
  const rows = (await env.DB.prepare(`SELECT col, id, owner, data, seq, deleted FROM items WHERE seq > ?1 AND (
      deleted = 1 OR vis = 'public' OR owner = ?2 OR party = ?2 OR (vis = 'review' AND ?3 = 1)
      OR (vis = 'group' AND scope IN (SELECT gid FROM members WHERE handle = ?2)) OR (vis = 'group' AND ?3 = 1))
    ORDER BY seq LIMIT ?4`).bind(since, h, u.admin ? 1 : 0, PAGE + 1).all()).results;
  res.more = rows.length > PAGE; const page = rows.slice(0, PAGE);
  const postIds = page.filter(r => r.col === 'post' && !r.deleted).map(r => r.id), mine = new Set();
  for (let i = 0; i < postIds.length; i += 90) {
    const ids = postIds.slice(i, i + 90), q = await env.DB.prepare(`SELECT id, kind FROM reactions WHERE col = 'post' AND handle = ? AND id IN (${ids.map(() => '?').join(',')})`).bind(h, ...ids).all();
    q.results.forEach(r => mine.add(r.id + ':' + r.kind));
  }
  for (const r of page) {
    const o = {col:r.col, id:r.id, owner:r.owner, seq:r.seq};
    if (r.deleted) o.deleted = true; else { o.data = JSON.parse(r.data); if (r.col === 'post') { o.liked = mine.has(r.id + ':like'); o.reposted = mine.has(r.id + ':repost'); } }
    res.items.push(o);
  }
  res.seq = page.length ? page[page.length - 1].seq : since;
  res.following = (await env.DB.prepare(`SELECT id FROM reactions WHERE col = 'profile' AND handle = ? AND kind = 'follow'`).bind(h).all()).results.map(r => r.id);
  res.followers = (await env.DB.prepare(`SELECT handle FROM reactions WHERE col = 'profile' AND id = ? AND kind = 'follow'`).bind(h).all()).results.map(r => r.handle);
  return json(res);
}

/* ---------- routes ---------- */
async function route(req, env, url, ctx) {
  const p = url.pathname.replace(/^\/api/, ''), m = req.method, ip = req.headers.get('cf-connecting-ip') || 'x';
  REQ_IP = ip;
  if (p === '/health') return json({ok:true, version:'91', email:!!env.RESEND_API_KEY, password:true, google:!!env.GOOGLE_CLIENT_ID});
  if (m === 'GET' && p.startsWith('/media/')) return media(env, decodeURIComponent(p.slice(7)));

  if (m === 'POST' && p === '/auth/dev' && env.DEV_LOGIN === 'local-test-only' && ['localhost', '127.0.0.1'].includes(url.hostname)) {   // for testing on a computer only; never on the live site
    const b = await body(req, 10000); return json(await signIn(env, String(b.email || ''), String(b.name || ''), String(b.dob || '')));
  }
  if (m === 'POST' && p === '/auth/google') {
    await limit(env, 'g:' + ip, 30, 6e5);
    const b = await body(req, 10000), g = await google(env, String(b.access_token || ''));
    return json(await signIn(env, g.email, g.name || g.given_name, String(b.dob || '')));
  }
  /* email + password */
  if (m === 'POST' && p === '/auth/signup') {
    const b = await body(req, 10000), email = String(b.email || '').toLowerCase().trim(), pw = String(b.password || '');
    if (!emailOk(email)) fail(400, 'invalid_email');
    if (!pwOk(pw)) fail(400, 'weak_password');
    await limit(env, 'su:' + ip, 10, 36e5);
    const u = await env.DB.prepare(`SELECT pw FROM users WHERE email = ?`).bind(email).first();
    if (u) fail(409, u.pw ? 'email_taken' : 'use_google');
    if (!String(b.dob || '')) fail(400, 'invalid_dob');
    const nu = await createUser(env, email, String(b.name || ''), String(b.dob || ''), {pw:await pwHash(pw)});
    await audit(env, email, 'sign_up', email, 'email and password');
    return json(await newSession(env, nu));
  }
  if (m === 'POST' && p === '/auth/login') {
    const b = await body(req, 10000), email = String(b.email || '').toLowerCase().trim(), pw = String(b.password || '');
    if (!emailOk(email) || !pw) fail(400, 'wrong_password');
    await limit(env, 'li:' + ip, 30, 9e5); await limit(env, 'le:' + email, 10, 9e5);
    const u = await env.DB.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();
    if (u && !u.pw) fail(400, 'use_google');
    if (!u || !(await pwCheck(pw, u.pw))) { await audit(env, email, 'sign_in_failed', email, 'wrong password'); fail(401, 'wrong_password'); }
    if (u.banned) { await audit(env, email, 'sign_in_blocked', email, 'banned'); fail(403, 'banned'); }
    await audit(env, email, 'sign_in', email, 'email and password');
    return json(await newSession(env, u));
  }
  if (m === 'POST' && p === '/auth/forgot') {
    if (!env.RESEND_API_KEY) fail(503, 'email_not_configured');
    const b = await body(req, 10000), email = String(b.email || '').toLowerCase().trim();
    if (!emailOk(email)) fail(400, 'invalid_email');
    await limit(env, 'fp:' + ip, 10, 36e5); await limit(env, 'fe:' + email, 4, 36e5);
    const u = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
    if (u) { const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1e6).padStart(6, '0');
      await env.DB.prepare(`INSERT OR REPLACE INTO codes (email, hash, expires, tries, name, dob, sent) VALUES (?, ?, ?, 0, 'reset', '', ?)`).bind(email, await sha(email + ':reset:' + code), now() + 6e5, now()).run();
      await sendCode(env, email, code); }
    return json({ok:true});                                                   // same answer whether or not the email has an account
  }
  if (m === 'POST' && p === '/auth/reset') {
    const b = await body(req, 10000), email = String(b.email || '').toLowerCase().trim(), code = String(b.code || '').replace(/\D/g, ''), pw = String(b.password || '');
    if (!pwOk(pw)) fail(400, 'weak_password');
    const c = await env.DB.prepare(`SELECT * FROM codes WHERE email = ? AND name = 'reset'`).bind(email).first();
    if (!c || c.expires < now()) fail(400, 'code_expired'); if (c.tries >= 5) fail(429, 'too_many');
    if (c.hash !== await sha(email + ':reset:' + code)) { await env.DB.prepare(`UPDATE codes SET tries = tries + 1 WHERE email = ?`).bind(email).run(); fail(400, 'wrong_code'); }
    const u = await env.DB.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first(); if (!u) fail(400, 'code_expired');
    await env.DB.batch([env.DB.prepare(`UPDATE users SET pw = ?, verified = 1 WHERE id = ?`).bind(await pwHash(pw), u.id), env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(u.id), env.DB.prepare(`DELETE FROM codes WHERE email = ?`).bind(email)]);
    u.verified = 1; await audit(env, email, 'password_reset', email, 'email code'); return json(await newSession(env, u));
  }
  if (m === 'POST' && p === '/auth/start') {
    if (!env.RESEND_API_KEY) fail(503, 'email_not_configured');
    const b = await body(req, 10000), email = String(b.email || '').toLowerCase().trim();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 200) fail(400, 'invalid_email');
    await limit(env, 's:' + ip, 20, 36e5); await limit(env, 'se:' + email, 5, 36e5);
    const exists = await env.DB.prepare(`SELECT 1 FROM users WHERE email = ?`).bind(email).first();
    if (!exists) { const a = ageOf(String(b.dob || '')); if (a === null || a > 120) fail(400, 'invalid_dob'); if (a < 5) fail(400, 'dob_too_young'); }
    const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1e6).padStart(6, '0');
    await env.DB.prepare(`INSERT OR REPLACE INTO codes (email, hash, expires, tries, name, dob, sent) VALUES (?, ?, ?, 0, ?, ?, ?)`).bind(email, await sha(email + ':' + code), now() + 6e5, clean(b.name, 60), String(b.dob || ''), now()).run();
    await sendCode(env, email, code);
    return json({ok:true});
  }
  if (m === 'POST' && p === '/auth/verify') {
    const b = await body(req, 10000), email = String(b.email || '').toLowerCase().trim(), code = String(b.code || '').replace(/\D/g, '');
    const c = await env.DB.prepare(`SELECT * FROM codes WHERE email = ?`).bind(email).first();
    if (!c) fail(400, 'code_expired');
    if (c.expires < now()) fail(400, 'code_expired');
    if (c.tries >= 5) fail(429, 'too_many');
    if (c.hash !== await sha(email + ':' + code)) { await env.DB.prepare(`UPDATE codes SET tries = tries + 1 WHERE email = ?`).bind(email).run(); fail(400, 'wrong_code'); }
    await env.DB.prepare(`DELETE FROM codes WHERE email = ?`).bind(email).run();
    return json(await signIn(env, email, c.name, c.dob));
  }

  const u = await auth(req, env);
  if (m === 'POST' && p === '/auth/logout') { await env.DB.prepare(`DELETE FROM sessions WHERE token = ?`).bind(await sha((req.headers.get('authorization') || '').replace(/^Bearer\s+/i, ''))).run(); return json({ok:true}); }
  if (m === 'GET' && p === '/handle') {
    await limit(env, 'hcheck:' + u.id, 120, 60e3);
    const h = String(url.searchParams.get('u') || '').trim().toLowerCase().replace(/^@/, ''), base = clean(url.searchParams.get('base') || u.name, 40);
    if (!h) return json({ok:false, message:'', suggestions:await suggestHandles(env, base)});
    if (h === u.handle) return json({ok:true, mine:true, message:'This is your username'});
    const why = handleRule(h); if (why) return json({ok:false, message:why, suggestions:await suggestHandles(env, base)});
    if (await env.DB.prepare(`SELECT 1 FROM users WHERE handle = ?`).bind(h).first()) return json({ok:false, taken:true, message:'This username is already taken. Try another one', suggestions:await suggestHandles(env, base)});
    return json({ok:true, message:'Available'});
  }
  if (m === 'GET' && p === '/me') return json({user:userOut(u), admin:!!u.role, role:u.role, unlocked:u.admin});
  if (m === 'PUT' && p === '/me') {
    const b = await body(req, 10000), name = clean(b.name, 40), handle = String(b.handle || '').trim().toLowerCase().replace(/^@/, '');
    if (!name) fail(400, 'invalid');
    const old = u.handle, change = handle !== old;
    if (change) {
      const why = handleRule(handle); if (why) return json({error:'invalid_handle', message:why}, 400);
      if (await env.DB.prepare(`SELECT 1 FROM users WHERE handle = ?`).bind(handle).first()) return json({error:'taken', message:'This username is already taken. Try another one', suggestions:await suggestHandles(env, name)}, 409);
      const wait = u.handle_set && u.handle_changed ? u.handle_changed + 30 * 864e5 - now() : 0;
      if (wait > 0) return json({error:'handle_wait', message:`You can change your username again in ${Math.ceil(wait / 864e5)} days`}, 429);
      await limit(env, 'handle:' + u.id, 5, 3600e3);
    }
    await env.DB.prepare(`UPDATE users SET name = ?, handle = ?, handle_set = 1, handle_changed = ? WHERE id = ?`).bind(name, handle, change && u.handle_set ? now() : (u.handle_changed || 0), u.id).run();
    if (change) { await moveHandle(env, old, handle); await audit(env, '@' + handle, 'username_changed', '@' + old, '@' + handle); }
    if (change && u.handle_set) u.handle_changed = now();
    u.name = name; u.handle = handle; u.handle_set = 1; await putProfile(env, u);
    return json({user:userOut(u)});
  }
  if (m === 'GET' && p === '/state') {
    const t = await store.text(env, `state/${u.id}.json`);
    return json({version:u.state_version || 0, data:t ? JSON.parse(t) : null});
  }
  if (m === 'PUT' && p === '/state') {
    const b = await body(req, MAX_STATE);
    if ((+b.base_version || 0) !== (u.state_version || 0)) { const t = await store.text(env, `state/${u.id}.json`); return json({version:u.state_version, data:t ? JSON.parse(t) : null}, 409); }
    if (!b.data || typeof b.data !== 'object') fail(400, 'bad_data');
    const adult = !u.under13 && (ageOf(u.dob) ?? 0) >= 18;
    if (!adult && (b.data.events || []).some(e => e && e.by === u.handle && e.status !== 'draft' && paidOrSupport(e))) fail(422, 'adults_only');
    const v = (u.state_version || 0) + 1;
    await store.put(env, `state/${u.id}.json`, JSON.stringify(b.data), 'application/json');
    await env.DB.prepare(`UPDATE users SET state_version = ? WHERE id = ?`).bind(v, u.id).run();
    return json({version:v});
  }
  if (m === 'POST' && p === '/me/password') {                           // set or change your password (Google accounts can add one too)
    const b = await body(req, 10000), pw = String(b.password || '');
    if (!pwOk(pw)) fail(400, 'weak_password');
    if (u.pw && !(await pwCheck(String(b.old || ''), u.pw))) fail(401, 'wrong_password');
    await env.DB.prepare(`UPDATE users SET pw = ? WHERE id = ?`).bind(await pwHash(pw), u.id).run();
    await audit(env, u.actor, 'password_changed', u.email); return json({ok:true});
  }
  if (m === 'GET' && p === '/me/password') return json({has:!!u.pw});
  /* ----- the Admin Studio: admin password, admins list, audit log ----- */
  if (m === 'GET' && p === '/admin/status') {
    if (!u.role) fail(403, 'not_admin');
    return json({role:u.role, unlocked:u.admin, hasPassword:!!(await env.DB.prepare(`SELECT 1 FROM admin_pw WHERE email = ?`).bind(u.email).first())});
  }
  if (m === 'POST' && p === '/admin/unlock') {
    if (!u.role) fail(403, 'not_admin');
    await limit(env, 'au:' + u.id, 6, 9e5);
    const b = await body(req, 10000), pw = String(b.password || ''), row = await env.DB.prepare(`SELECT hash FROM admin_pw WHERE email = ?`).bind(u.email).first();
    if (!row) {                                                              // first time: this sets the admin password
      if (!pwOk(pw)) fail(400, 'weak_password');
      if (u.pw && await pwCheck(pw, u.pw)) fail(400, 'same_as_login');
      await env.DB.prepare(`INSERT INTO admin_pw (email, hash, set_at) VALUES (?, ?, ?)`).bind(u.email, await pwHash(pw), now()).run();
      await audit(env, u.actor, 'admin_password_set', u.email);
    } else if (!(await pwCheck(pw, row.hash))) { await audit(env, u.actor, 'admin_unlock_failed', u.email); fail(401, 'wrong_password'); }
    const key = rid(32);
    await env.DB.prepare(`INSERT INTO admin_keys (key, user_id, expires) VALUES (?, ?, ?)`).bind(await sha(key), u.id, now() + 30 * 6e4).run();
    await audit(env, u.actor, 'admin_unlock', u.email);
    return json({key, minutes:30, role:u.role});
  }
  if (m === 'POST' && p === '/admin/lock') {
    const k = req.headers.get('x-nuru-admin'); if (k) await env.DB.prepare(`DELETE FROM admin_keys WHERE key = ?`).bind(await sha(k)).run();
    return json({ok:true});
  }
  if (m === 'GET' && p === '/admin/admins') {
    if (!u.admin) fail(403, 'admin_locked');
    const extra = (await env.DB.prepare(`SELECT a.email, a.added_by, a.added_at, u.name, u.handle FROM admins a LEFT JOIN users u ON u.email = a.email ORDER BY a.added_at`).all()).results;
    const owners = [];
    for (const e of admins(env)) { const x = await env.DB.prepare(`SELECT name, handle FROM users WHERE email = ?`).bind(e).first(); owners.push({email:e, name:x?.name || '', handle:x?.handle || '', role:'owner'}); }
    return json({owners, admins:extra.map(x => ({...x, role:'admin'}))});
  }
  if (m === 'POST' && p === '/admin/admins') {                            // owners add or remove admins
    if (!u.admin) fail(403, 'admin_locked'); if (u.role !== 'owner') fail(403, 'owners_only');
    const b = await body(req, 10000), email = String(b.email || '').toLowerCase().trim();
    if (!emailOk(email)) fail(400, 'invalid_email');
    if (b.remove) {
      if (admins(env).includes(email)) fail(400, 'cannot_remove_owner');
      const t = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
      await env.DB.batch([env.DB.prepare(`DELETE FROM admins WHERE email = ?`).bind(email), env.DB.prepare(`DELETE FROM admin_pw WHERE email = ?`).bind(email),
        env.DB.prepare(`DELETE FROM admin_keys WHERE user_id = ?`).bind(t?.id || '-')]);
      await audit(env, u.actor, 'admin_removed', email); return json({ok:true});
    }
    if (admins(env).includes(email)) fail(400, 'already_admin');
    await env.DB.prepare(`INSERT OR IGNORE INTO admins (email, added_by, added_at) VALUES (?, ?, ?)`).bind(email, u.email, now()).run();
    await audit(env, u.actor, 'admin_added', email); return json({ok:true});
  }
  if (m === 'POST' && p === '/admin/admin-password-reset') {             // owners: an admin forgot their admin password
    if (!u.admin) fail(403, 'admin_locked'); if (u.role !== 'owner') fail(403, 'owners_only');
    const b = await body(req, 10000), email = String(b.email || '').toLowerCase().trim();
    if (email === u.email) fail(400, 'not_yourself');
    const t = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first();
    await env.DB.batch([env.DB.prepare(`DELETE FROM admin_pw WHERE email = ?`).bind(email), env.DB.prepare(`DELETE FROM admin_keys WHERE user_id = ?`).bind(t?.id || '-')]);
    await audit(env, u.actor, 'admin_password_cleared', email); return json({ok:true});
  }
  if (m === 'GET' && p === '/admin/audit') {
    if (!u.admin) fail(403, 'admin_locked');
    const before = +url.searchParams.get('before') || 9e15, kind = url.searchParams.get('kind') || 'all';
    const W = {all:'1 = 1', admin:`action NOT IN ('sign_in', 'sign_up', 'sign_in_failed', 'sign_in_blocked', 'password_reset')`, signin:`action IN ('sign_in', 'sign_up', 'sign_in_failed', 'sign_in_blocked', 'password_reset', 'admin_unlock', 'admin_unlock_failed')`, pay:`action LIKE 'payment_%'`}[kind] || '1 = 1';
    const rows = (await env.DB.prepare(`SELECT * FROM audit WHERE id < ? AND ${W} ORDER BY id DESC LIMIT 100`).bind(before).all()).results;
    return json({rows});
  }
  if (m === 'POST' && p === '/admin/password') {                        // admins: give someone a temporary password after checking who they are
    if (!u.admin) fail(403, 'admin_locked');
    const b = await body(req, 10000), email = String(b.email || '').toLowerCase().trim();
    const t = await env.DB.prepare(`SELECT id FROM users WHERE email = ?`).bind(email).first(); if (!t) fail(404, 'no_account');
    const temp = 'Nuru' + String(crypto.getRandomValues(new Uint32Array(1))[0] % 1e6).padStart(6, '0') + rid(2);
    await env.DB.batch([env.DB.prepare(`UPDATE users SET pw = ? WHERE id = ?`).bind(await pwHash(temp), t.id), env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(t.id)]);
    await audit(env, u.actor, 'user_password_reset', email); return json({temp});
  }
  if (m === 'POST' && p === '/upload') return upload(req, env, u);
  if (m === 'POST' && p === '/sync') return sync(req, env, u);
  if (m === 'POST' && p === '/me/delete') {
    const b = await body(req, 1000); if (b.confirm !== true) fail(400, 'confirm');
    await audit(env, u.actor, 'account_deleted', '@' + u.handle);
    const h = u.handle;
    for (const r of (await env.DB.prepare(`SELECT col, id FROM items WHERE owner = ? AND deleted = 0`).bind(h).all()).results)
      await env.DB.prepare(`UPDATE items SET data = NULL, deleted = 1, seq = ? WHERE col = ? AND id = ?`).bind(await nextSeq(env), r.col, r.id).run();
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM reactions WHERE handle = ? OR (col = 'profile' AND id = ?)`).bind(h, h),
      env.DB.prepare(`DELETE FROM members WHERE handle = ?`).bind(h),
      env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(u.id),
      env.DB.prepare(`DELETE FROM users WHERE id = ?`).bind(u.id)
    ]);
    ctx.waitUntil((async () => { await store.delPrefix(env, `p/${u.id}/`); await store.delPrefix(env, `state/${u.id}.json`); })());
    return json({ok:true});
  }
  fail(404, 'not_found');
}
