/* Nuru offline helper: always tries the internet first, and uses the last saved copy when offline.
   The server's /api is never cached. The saved Bible (cache "nuru-bible") is kept across updates. */
const CACHE = 'nuru-v98', KEEP = ['nuru-bible'];
self.addEventListener('install', e => { self.skipWaiting(); e.waitUntil(caches.open(CACHE).then(c => c.addAll(['/', '/manifest.webmanifest', '/icon-192.png'])).catch(() => {})); });
self.addEventListener('activate', e => e.waitUntil((async () => { for (const k of await caches.keys()) if (k !== CACHE && !KEEP.includes(k)) await caches.delete(k); await self.clients.claim(); })()));
self.addEventListener('fetch', e => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/api/') || u.pathname.startsWith('/bible/')) return;
  const key = r.mode === 'navigate' ? '/' : r;
  e.respondWith(fetch(r).then(res => { if (res.ok && res.type === 'basic') { const c = res.clone(); caches.open(CACHE).then(x => x.put(key, c)); } return res; })
    .catch(() => caches.match(key).then(m => m || Response.error())));
});
