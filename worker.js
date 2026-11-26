/* Nuru server on Cloudflare
   - Serves the website (index.html, privacy.html, terms.html) from the same Worker.
   - /api/... : sign-in with Google (or an emailed code when RESEND_API_KEY is set), each person's saved data,
     the shared community (posts, replies, likes, groups, group chat, shop listings, events, registrations, shop chats,
     profiles and follows) and photos.
   Storage: D1 database "DB" for accounts, shared items, photos and each person's saved app data. If an R2 bucket is bound
   as "MEDIA", photos and saved data go there instead (R2 needs a payment method on the Cloudflare account; D1 does not).
   Settings (wrangler.jsonc "vars"): GOOGLE_CLIENT_ID, ADMIN_EMAILS. Optional secrets: RESEND_API_KEY, MAIL_FROM. */

const MAX_ITEM = 300 * 1024, MAX_STATE = 1900 * 1024, MAX_PHOTO = 1900 * 1024, PAGE = 300;   // D1 keeps up to 2 MB in one row
const COLS = new Set(['post', 'listing', 'event', 'group', 'gmsg', 'reg', 'dm', 'profile', 'pay']);
const OWNER_FIELD = {post:'by', listing:'by', event:'by', group:'owner', gmsg:'by', reg:'user', dm:'from', profile:'handle', pay:'payer'};
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
  return o ? {'access-control-allow-origin':o, 'access-control-allow-headers':'authorization, content-type', 'access-control-allow-methods':'GET, POST, PUT, DELETE, OPTIONS', 'vary':'origin'} : {};
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
const admins = env => String(env.ADMIN_EMAILS || '').toLowerCase().split(/[\s,]+/).filter(Boolean);

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
    env.DB.prepare(`INSERT OR IGNORE INTO meta (k, v) VALUES ('seq', 0)`)
  ]);
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
const userOut = u => ({id:u.id, email:u.email, name:u.name, handle:u.handle, dob:u.under13 ? null : u.dob, under13:!!u.under13});
async function freeHandle(env, base) {
  let h = (base || 'friend').toLowerCase().normalize('NFKD').replace(/[^a-z0-9_]/g, '').slice(0, 14) || 'friend';
  if (h.length < 3) h = (h + 'friend').slice(0, 8);
  for (let i = 0; i < 30; i++) {
    const c = i ? h + '_' + Math.floor(Math.random() * (i < 10 ? 1000 : 100000)) : h;
    if (!(await env.DB.prepare(`SELECT 1 FROM users WHERE handle = ?`).bind(c).first())) return c;
  }
  return h + '_' + rid(4);
}
/* find or create the account, then open a session */
async function signIn(env, email, name, dob) {
  email = String(email).toLowerCase().trim();
  let u = await env.DB.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();
  if (!u) {
    if (!dob) throw new Http(428, {error:'need_birthday', name:clean(name, 60)});   // new account: the app asks "When's your birthday?" then tries again
    const age = ageOf(dob);
    if (age === null || age > 120) fail(400, 'invalid_dob');
    if (age < 5) fail(400, 'dob_too_young');
    u = {id:'u' + rid(12), email, name:clean(name || email.split('@')[0], 60), handle:await freeHandle(env, name || email.split('@')[0]), dob:age < 13 ? null : dob, under13:age < 13 ? 1 : 0, created:now()};
    await env.DB.prepare(`INSERT INTO users (id, email, name, handle, dob, under13, created) VALUES (?, ?, ?, ?, ?, ?, ?)`).bind(u.id, u.email, u.name, u.handle, u.dob, u.under13, u.created).run();
    await putProfile(env, u);
  }
  if (u.banned) fail(403, 'banned');
  const token = rid(32);
  await env.DB.prepare(`INSERT INTO sessions (token, user_id, expires) VALUES (?, ?, ?)`).bind(await sha(token), u.id, now() + SESSION_DAYS * 864e5).run();
  return {token, user:userOut(u), admin:admins(env).includes(u.email)};
}
async function auth(req, env) {
  const t = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!t) fail(401, 'signed_out');
  const r = await env.DB.prepare(`SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires > ?`).bind(await sha(t), now()).first();
  if (!r) fail(401, 'signed_out');
  if (r.banned) fail(403, 'banned');
  r.admin = admins(env).includes(r.email);
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
  if (col === 'pay') return ['review', null, null];                // M-Pesa payments: the payer and admins only
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

async function put(env, u, {col, id, data}) {
  if (!COLS.has(col) || col === 'profile') fail(400, 'bad_col');
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
    if (u.under13 && col !== 'reg' && col !== 'pay') fail(403, 'under13');
    if (col === 'post') { d.replies = []; d.likes = 0; d.reposts = 0; }
    if (col === 'reg') { const e = await getItem(env, 'event', String(data.eventId || '')); if (!e || !e.d) fail(404, 'no_event'); d.host = e.d.by; }
    if (col === 'gmsg') { const g = await getItem(env, 'group', String(data.gid || '')); if (!g || !g.d) fail(404, 'no_group');
      if (!(g.d.members || []).includes(h) && g.d.owner !== h) fail(403, 'not_member'); }
    if (col === 'dm' && !data.to) fail(400, 'no_recipient');
  }
  if (col === 'event' && paidOrSupport(d) && (old?.owner || h) === h && (u.under13 || (ageOf(u.dob) ?? 0) < 18)) fail(422, 'adults_only');
  if (col === 'listing' && !u.admin && ['live', 'active'].includes(d.status) && !(live && ['live', 'active', 'sold'].includes(old.d.status))) d.status = 'pending';   // only admins approve listings
  if (col === 'pay') {                                                  // only admins confirm or reject; each M-Pesa code counts once
    if (!u.admin) d.status = live ? old.d.status : 'pending';
    d.code = String(d.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12);
    if (!live && d.code && await env.DB.prepare(`SELECT 1 FROM items WHERE col = 'pay' AND id <> ? AND deleted = 0 AND json_extract(data, '$.code') = ?`).bind(id, d.code).first()) d.status = 'duplicate';
    d.payer = live ? old.d.payer : h; d.email = live ? old.d.email : u.email;
  }
  delete d.liked; delete d.reposted;
  await writeItem(env, col, id, live ? old.owner : h, d, old?.created);
  if (col === 'group' && (!live || old.d.owner === h || (old.d.admins || []).includes(h) || u.admin)) await syncMembers(env, id, d.members);
}
async function del(env, u, {col, id}) {
  if (!COLS.has(col) || col === 'profile') fail(400, 'bad_col');
  const old = await getItem(env, col, String(id)); if (!old || old.deleted) return;
  if (col === 'pay' && !u.admin) fail(403, 'not_yours');                 // payment records stay
  const ok = old.owner === u.handle || u.admin || (col === 'gmsg' && await isGroupAdmin(env, String(old.d?.gid), u.handle)) || (col === 'post' && old.d?.groupId && await isGroupAdmin(env, String(old.d.groupId), u.handle));
  if (!ok) fail(403, 'not_yours');
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
  if (p === '/health') return json({ok:true, email:!!env.RESEND_API_KEY, google:!!env.GOOGLE_CLIENT_ID});
  if (m === 'GET' && p.startsWith('/media/')) return media(env, decodeURIComponent(p.slice(7)));

  if (m === 'POST' && p === '/auth/dev' && env.DEV_LOGIN === 'local-test-only' && ['localhost', '127.0.0.1'].includes(url.hostname)) {   // for testing on a computer only; never on the live site
    const b = await body(req, 10000); return json(await signIn(env, String(b.email || ''), String(b.name || ''), String(b.dob || '')));
  }
  if (m === 'POST' && p === '/auth/google') {
    await limit(env, 'g:' + ip, 30, 6e5);
    const b = await body(req, 10000), g = await google(env, String(b.access_token || ''));
    return json(await signIn(env, g.email, g.name || g.given_name, String(b.dob || '')));
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
  if (m === 'GET' && p === '/me') return json({user:userOut(u), admin:u.admin});
  if (m === 'PUT' && p === '/me') {
    const b = await body(req, 10000), name = clean(b.name, 60), handle = String(b.handle || '').toLowerCase();
    if (!name || !/^[a-z0-9_]{3,20}$/.test(handle)) fail(400, 'invalid');
    if (handle !== u.handle && await env.DB.prepare(`SELECT 1 FROM users WHERE handle = ?`).bind(handle).first()) fail(409, 'taken');
    await env.DB.prepare(`UPDATE users SET name = ?, handle = ? WHERE id = ?`).bind(name, handle, u.id).run();
    u.name = name; u.handle = handle; await putProfile(env, u);
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
  if (m === 'POST' && p === '/upload') return upload(req, env, u);
  if (m === 'POST' && p === '/sync') return sync(req, env, u);
  if (m === 'POST' && p === '/me/delete') {
    const b = await body(req, 1000); if (b.confirm !== true) fail(400, 'confirm');
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
