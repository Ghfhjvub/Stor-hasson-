/**
 * admin-push-worker.js — سيرفر الإشعارات الحقيقية لتطبيق المدير (Cloudflare Worker مجاني، بدون بطاقة)
 *
 * يعمل كل دقيقة: يقرأ الأحداث الجديدة من Firestore (activity + logs) ويرسلها لهاتفك عبر Firebase Cloud Messaging،
 * فيصلك إشعار حقيقي حتى لو كان التطبيق مغلقاً. التأخير الأقصى نحو دقيقة.
 *
 * ── خطوات الإعداد (مرة واحدة) ───────────────────────────────────────────────
 * 1) Firebase Console > Project settings > Cloud Messaging:
 *      - تأكد أن «Firebase Cloud Messaging API (V1)» مفعّل.
 *      - Web Push certificates > Generate key pair > انسخ المفتاح وضعه في index.html مكان ADM_VAPID_KEY.
 * 2) Firebase Console > Project settings > Service accounts > Generate new private key > يُنزَّل ملف JSON.
 * 3) cloudflare.com (حساب مجاني) > Workers & Pages > Create > Create Worker > Deploy
 *      ثم Edit code > الصق هذا الملف كاملاً > Deploy.
 * 4) Storage & Databases > KV > Create namespace (اسمه مثلاً admin-push).
 * 5) في الـ Worker: Settings > Bindings > Add > KV namespace:
 *      Variable name = PUSH_KV  ، Namespace = الذي أنشأته.
 * 6) Settings > Variables and Secrets > Add:
 *      FIREBASE_SERVICE_ACCOUNT (نوع Secret) = محتوى ملف JSON كاملاً
 *      ADMIN_CODE               (نوع Secret) = رمز سرّي طويل تختاره أنت (12 حرفاً فأكثر) — ستكتبه مرة واحدة في التطبيق
 *      SITE_URL (اختياري، Text)  = رابط تطبيق المدير مثل https://موقعك/index.html?app=admin
 * 7) Settings > Trigger Events > Cron Triggers > Add > Cron expression:  * * * * *
 * 8) انسخ رابط الـ Worker (…workers.dev) وضعه في index.html مكان ADM_WORKER_URL، ثم ارفع index.html و admin-sw.js.
 * 9) في تطبيق المدير: الجرس > «ربط الإشعارات الحقيقية» > اسمح بالإشعارات > اكتب ADMIN_CODE > «إشعار تجريبي».
 */

const CORS = {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'POST, GET, OPTIONS',
    'access-control-allow-headers': 'content-type'
};
const SCOPES = 'https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/firebase.messaging';
const TYPES = {
    login:    ['🔑', 'تسجيل دخول'],
    register: ['🆕', 'مستخدم جديد'],
    request:  ['📥', 'طلب تنزيل'],
    download: ['⬇️', 'تنزيل جديد'],
    comment:  ['💬', 'رسالة جديدة'.replace('رسالة', 'تعليق')],
    message:  ['✉️', 'رسالة جديدة'],
    dev:      ['👨‍💻', 'المطورون']
};
const ITEM = { game: 'اللعبة', app: 'التطبيق', wallpaper: 'الخلفية', file: 'الملف' };
const MAX_TOKENS = 5;     // عدد الأجهزة المسموح بها
const MAX_SINGLE = 5;     // أكثر من هذا في دقيقة واحدة => إشعار تلخيصي واحد

const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...CORS } });

async function sameCode(a, b) {
    const enc = new TextEncoder();
    const [x, y] = await Promise.all([crypto.subtle.digest('SHA-256', enc.encode(String(a))), crypto.subtle.digest('SHA-256', enc.encode(String(b)))]);
    const u = new Uint8Array(x), v = new Uint8Array(y);
    let d = 0;
    for (let i = 0; i < u.length; i++) d |= u[i] ^ v[i];
    return d === 0;
}

const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64uStr = (s) => b64u(new TextEncoder().encode(s));

async function accessToken(sa, state) {
    const now = Math.floor(Date.now() / 1000);
    if (state.at && state.at.exp - 300 > now) return state.at.token;
    const head = b64uStr(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const claim = b64uStr(JSON.stringify({ iss: sa.client_email, scope: SCOPES, aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 }));
    const der = Uint8Array.from(atob(sa.private_key.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(head + '.' + claim));
    const r = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + head + '.' + claim + '.' + b64u(sig)
    });
    if (!r.ok) throw new Error('oauth ' + r.status + ' ' + (await r.text()).slice(0, 200));
    const j = await r.json();
    state.at = { token: j.access_token, exp: now + (j.expires_in || 3600) };
    state.dirty = true;
    return state.at.token;
}

async function newDocs(pid, at, coll, field, sinceIso) {
    const r = await fetch(`https://firestore.googleapis.com/v1/projects/${pid}/databases/(default)/documents:runQuery`, {
        method: 'POST',
        headers: { authorization: 'Bearer ' + at, 'content-type': 'application/json' },
        body: JSON.stringify({ structuredQuery: {
            from: [{ collectionId: coll }],
            where: { fieldFilter: { field: { fieldPath: field }, op: 'GREATER_THAN', value: { timestampValue: sinceIso } } },
            orderBy: [{ field: { fieldPath: field }, direction: 'ASCENDING' }],
            limit: 30
        } })
    });
    if (!r.ok) throw new Error('firestore ' + coll + ' ' + r.status + ' ' + (await r.text()).slice(0, 200));
    return (await r.json()).filter(x => x.document).map(x => x.document);
}

async function push(pid, at, token, m) {
    const r = await fetch(`https://fcm.googleapis.com/v1/projects/${pid}/messages:send`, {
        method: 'POST',
        headers: { authorization: 'Bearer ' + at, 'content-type': 'application/json' },
        body: JSON.stringify({ message: {
            token,
            data: { title: m.title, body: m.body, tag: m.tag, url: m.url || '' },
            webpush: { headers: { Urgency: 'high', TTL: '86400' } }
        } })
    });
    if (r.ok) return 'ok';
    const t = await r.text();
    if (r.status === 404 || /UNREGISTERED|NOT_FOUND/.test(t)) return 'dead';
    console.log('fcm error', r.status, t.slice(0, 200));
    return 'fail';
}

async function sendAll(pid, at, tokens, msgs) {
    const dead = new Set();
    let ok = 0, fail = 0;
    for (const m of msgs) {
        for (const t of tokens) {
            if (dead.has(t)) continue;
            const s = await push(pid, at, t, m);
            if (s === 'ok') ok++; else if (s === 'dead') dead.add(t); else fail++;
        }
    }
    return { ok, fail, dead: [...dead] };
}

const text = (v) => (v && v.stringValue) || '';
const clip = (s) => String(s).slice(0, 200);

function toEvent(kind, doc, env) {
    const id = doc.name.split('/').pop(), f = doc.fields || {};
    if (kind === 'a') {
        const type = text(f.type) || 'activity', body = text(f.text);
        if (type === 'dev' && /^المدير/.test(body)) return null;           // أفعال المدير نفسه
        const t = TYPES[type] || ['🔔', 'نشاط جديد'];
        return { key: 'a:' + id, ts: Date.parse((f.createdAt || {}).timestampValue || ''), title: t[0] + ' ' + t[1], body: clip(body), tag: 'a:' + id, url: env.SITE_URL || '' };
    }
    const who = text(f.userName) || 'زائر', what = ITEM[text(f.itemType)] || ITEM.game, name = text(f.itemTitle) || text(f.gameTitle);
    return { key: 'l:' + id, ts: Date.parse((f.timestamp || {}).timestampValue || ''), title: TYPES.download[0] + ' ' + TYPES.download[1], body: clip(`${who} نزّل ${what} «${name}»`), tag: 'l:' + id, url: env.SITE_URL || '' };
}

async function poll(env) {
    const tokens = (await env.PUSH_KV.get('tokens', 'json')) || [];
    if (!tokens.length) return;                                              // لا أجهزة مسجّلة: لا شيء يُرسل ولا قراءات
    const state = (await env.PUSH_KV.get('state', 'json')) || {};
    if (!state.last) { state.last = new Date().toISOString(); state.seen = []; await env.PUSH_KV.put('state', JSON.stringify(state)); return; }

    const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT), pid = sa.project_id;
    const at = await accessToken(sa, state);
    const since = new Date(Date.parse(state.last) - 5000).toISOString();     // تداخل بسيط، والتكرار يُمنع بقائمة seen
    const [acts, logs] = await Promise.all([newDocs(pid, at, 'activity', 'createdAt', since), newDocs(pid, at, 'logs', 'timestamp', since)]);

    const seen = new Set(state.seen || []);
    const events = [];
    for (const d of acts) { const e = toEvent('a', d, env); if (e && !seen.has(e.key)) events.push(e); }
    for (const d of logs) { const e = toEvent('l', d, env); if (e && !seen.has(e.key)) events.push(e); }
    events.sort((x, y) => x.ts - y.ts);

    if (!events.length) { if (state.dirty) { delete state.dirty; await env.PUSH_KV.put('state', JSON.stringify(state)); } return; }

    const msgs = events.length <= MAX_SINGLE ? events
        : [{ title: '🔔 ' + events.length + ' أحداث جديدة', body: events[events.length - 1].body, tag: 'adm-batch-' + events[events.length - 1].key, url: env.SITE_URL || '' }];
    const res = await sendAll(pid, at, tokens, msgs);
    if (res.dead.length) await env.PUSH_KV.put('tokens', JSON.stringify(tokens.filter(t => !res.dead.includes(t))));

    const newest = Math.max(...events.map(e => e.ts).filter(Number.isFinite), Date.parse(state.last));
    state.last = new Date(newest).toISOString();
    state.seen = [...(state.seen || []), ...events.map(e => e.key)].slice(-200);
    delete state.dirty;
    await env.PUSH_KV.put('state', JSON.stringify(state));
}

async function readBody(req) { try { return await req.json(); } catch (e) { return {}; } }

export default {
    async fetch(req, env) {
        const url = new URL(req.url), path = url.pathname.replace(/\/+$/, '') || '/';
        if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
        if (req.method === 'GET' && path === '/') return new Response('admin-push ok', { headers: CORS });
        if (req.method !== 'POST') return json({ error: 'not_found' }, 404);
        if (!env.ADMIN_CODE || !env.PUSH_KV) return json({ error: 'server_not_configured' }, 500);

        const b = await readBody(req);
        if (!(await sameCode(b.code || '', env.ADMIN_CODE))) return json({ error: 'bad_code' }, 401);

        let tokens = (await env.PUSH_KV.get('tokens', 'json')) || [];

        if (path === '/register') {
            const t = String(b.token || '');
            if (t.length < 100 || t.length > 4096) return json({ error: 'bad_token' }, 400);
            if (!tokens.length) await env.PUSH_KV.put('state', JSON.stringify({ last: new Date().toISOString(), seen: [] }));   // لا نرسل أحداثاً قديمة عند أول جهاز
            tokens = [t, ...tokens.filter(x => x !== t)].slice(0, MAX_TOKENS);
            await env.PUSH_KV.put('tokens', JSON.stringify(tokens));
            return json({ ok: true, devices: tokens.length });
        }
        if (path === '/unregister') {
            tokens = tokens.filter(x => x !== String(b.token || ''));
            await env.PUSH_KV.put('tokens', JSON.stringify(tokens));
            return json({ ok: true, devices: tokens.length });
        }
        if (path === '/test') {
            if (!tokens.length) return json({ error: 'no_devices' }, 400);
            const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
            const state = (await env.PUSH_KV.get('state', 'json')) || {};
            const at = await accessToken(sa, state);
            if (state.dirty) { delete state.dirty; await env.PUSH_KV.put('state', JSON.stringify(state)); }
            const res = await sendAll(sa.project_id, at, tokens, [{ title: '✅ إشعار تجريبي', body: 'الإشعارات الحقيقية تعمل — ستصلك الأحداث حتى والتطبيق مغلق.', tag: 'adm-test-' + Date.now(), url: env.SITE_URL || '' }]);
            if (res.dead.length) await env.PUSH_KV.put('tokens', JSON.stringify(tokens.filter(t => !res.dead.includes(t))));
            return json({ sent: res.ok, failed: res.fail, removed: res.dead.length });
        }
        return json({ error: 'not_found' }, 404);
    },

    async scheduled(event, env, ctx) {
        ctx.waitUntil(poll(env).catch(e => console.log('poll error', String(e))));
    }
};
