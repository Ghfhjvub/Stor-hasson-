// admin-sw.js — ارفعه في نفس مجلد index.html
// وظيفته: يجعل تطبيق المدير قابلاً للتثبيت، ويعرض الإشعارات، ويفتح التطبيق عند الضغط على إشعار.

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

// مطلوب ليعتبر المتصفح الموقع تطبيقاً قابلاً للتثبيت (لا يغيّر أي طلب)
self.addEventListener('fetch', () => {});

self.addEventListener('notificationclick', (e) => {
    e.notification.close();
    const fallback = new URL('./?app=admin', self.registration.scope).href;
    const url = (e.notification.data && e.notification.data.url) || fallback;
    e.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
            for (const c of list) { if ('focus' in c) return c.focus(); }
            return self.clients.openWindow(url);
        })
    );
});
