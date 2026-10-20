// Ponte no celular: guarda a página para abrir rápido (os dados sempre vêm da internet) e mostra as notificações
const CACHE = 'ponte-app-v4';
self.addEventListener('install', (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(['./', 'index.html', 'icon.png', 'manifest.webmanifest']))); self.skipWaiting(); });
self.addEventListener('activate', (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))); self.clients.claim(); });
self.addEventListener('fetch', (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== 'GET' || u.origin !== location.origin) return;
  e.respondWith(fetch(e.request).then((r) => { const copy = r.clone(); caches.open(CACHE).then((c) => c.put(e.request, copy)); return r; }).catch(() => caches.match(e.request)));
});
// notificação mandada pelo computador principal da loja
self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = { title: 'Ponte', body: e.data ? e.data.text() : '' }; }
  e.waitUntil(self.registration.showNotification(d.title || 'Ponte', {
    body: d.body || '', tag: d.tag || 'ponte', renotify: true, icon: 'icon.png', badge: 'icon.png',
    data: { url: d.url || '' }, vibrate: [200, 100, 200],
  }));
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const hash = (e.notification.data && e.notification.data.url) || '#inicio';
  const target = new URL('./' + (hash.startsWith('#') ? hash : '#' + hash), self.registration.scope).href;
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
    for (const c of list) { if (c.url.startsWith(self.registration.scope)) { c.focus(); return c.navigate ? c.navigate(target) : null; } }
    return self.clients.openWindow(target);
  }));
});
