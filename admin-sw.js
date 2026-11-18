// admin-sw.js — ارفعه في نفس مجلد index.html (استبدل القديم)
// وظيفته:
//  1) يجعل تطبيق المدير قابلاً للتثبيت.
//  2) يستقبل الإشعارات من السيرفر (FCM) ويعرضها حتى والتطبيق مغلق — مثل واتساب.
//  3) يعرض رقماً أحمر على أيقونة التطبيق = عدد التنبيهات غير المقروءة.
//  4) يفتح التطبيق عند الضغط على الإشعار.

const BADGE_CACHE = 'adm-badge-v1';
const badgeReq = () => new Request(new URL('__adm_badge__', self.registration.scope).href);

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

// مطلوب ليعتبر المتصفح الموقع تطبيقاً قابلاً للتثبيت (لا يغيّر أي طلب)
self.addEventListener('fetch', () => {});

/* ---------- عدّاد غير المقروء (يبقى محفوظاً حتى لو أُوقف الـ service worker) ---------- */
async function getCount() {
    try {
        const c = await caches.open(BADGE_CACHE);
        const r = await c.match(badgeReq());
        return r ? (parseInt(await r.text(), 10) || 0) : 0;
    } catch (e) { return 0; }
}

async function setCount(n) {
    n = Math.max(0, parseInt(n, 10) || 0);
    try { const c = await caches.open(BADGE_CACHE); await c.put(badgeReq(), new Response(String(n))); } catch (e) {}
    try {
        if (n > 0) { if (self.navigator.setAppBadge) await self.navigator.setAppBadge(n); }
        else if (self.navigator.clearAppBadge) await self.navigator.clearAppBadge();
    } catch (e) {}
    return n;
}

/* ---------- استقبال الإشعار وعرضه ---------- */
self.addEventListener('push', (event) => {
    event.waitUntil((async () => {
        let p = {};
        try { p = event.data ? event.data.json() : {}; }
        catch (e) { try { p = { body: event.data.text() }; } catch (_) { p = {}; } }

        // FCM يضع حقول الرسالة داخل data (وأحياناً notification)
        const d = Object.assign({}, p, p.notification || {}, p.data || {});
        const title = d.title || '7ASSON Admin';
        const tag = d.tag || ('adm-' + Date.now());
        const url = d.url || new URL('./?app=admin', self.registration.scope).href;
        const isTest = /^adm-test/.test(tag);

        // إن كان التطبيق مفتوحاً أمامك الآن فالتنبيه يظهر داخله، فلا داعي لإشعار النظام
        const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
        if (!isTest && wins.some((c) => c.visibilityState === 'visible')) return;

        const already = (await self.registration.getNotifications({ tag })).length > 0;
        const icon = new URL('1.jpg', self.registration.scope).href;

        await self.registration.showNotification(title, {
            body: d.body || '',
            icon,
            badge: icon,
            tag,                       // نفس الحدث لا يظهر مرتين
            renotify: true,
            dir: 'rtl',
            lang: 'ar',
            vibrate: [200, 100, 200],
            timestamp: Date.now(),
            data: { url }
        });

        // الرقم الأحمر على الأيقونة
        await setCount((await getCount()) + (already ? 0 : 1));
    })());
});

/* ---------- رسائل من الصفحة: ضبط/تصفير الرقم ---------- */
self.addEventListener('message', (e) => {
    const m = e.data || {};
    if (m.type === 'badge') e.waitUntil(setCount(m.n));
});

/* ---------- الضغط على الإشعار ---------- */
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
