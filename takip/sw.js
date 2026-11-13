const C = 'takip-v2';
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(
  caches.keys().then(ks => Promise.all(ks.filter(k => k.startsWith('takip-') && k !== C).map(k => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET' || /\/api\//.test(e.request.url)) return;
  e.respondWith(caches.open(C).then(async c => {
    const hit = await c.match(e.request, { ignoreSearch: e.request.mode === 'navigate' });
    if (e.request.mode === 'navigate')  // the app itself: newest when online
      return fetch(e.request).then(r => { if (r.ok) c.put(e.request, r.clone()); return r; }).catch(() => hit);
    const net = fetch(e.request).then(r => { if (r.ok || r.type === 'opaque') c.put(e.request, r.clone()); return r; }).catch(() => hit);
    return hit || net;
  }));
});
self.addEventListener('push', e => {
  let d = {};
  try { d = e.data.json(); } catch (err) { /* empty push */ }
  e.waitUntil(self.registration.showNotification(d.title || 'Günlük Takip', {
    body: d.body || 'Şimdiye kadar nasılsın?', tag: d.tag || 'takip', icon: 'icon-512.png', badge: 'icon-512.png', renotify: true,
  }));
});
self.addEventListener('notificationclick', e => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(cs => {
    const c = cs.find(x => x.url.startsWith(self.registration.scope));
    if (c) { c.postMessage({ checkin: 1 }); return c.focus(); }
    return self.clients.openWindow(self.registration.scope + '?c=1');
  }));
});
