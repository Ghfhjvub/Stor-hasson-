/**
 * 7asson-worker.js — سيرفر موقع 7ASSON GAMING (Cloudflare Worker مجاني، بدون بطاقة)
 * يقوم بخدمتين:
 *   1) الإشعارات الحقيقية لتطبيق المدير (تصل حتى والتطبيق مغلق) — يفحص Firestore كل دقيقة ويرسل عبر FCM.
 *   2) رمز التحقق بالبريد عند التسجيل (صالح 5 دقائق) ثم إنشاء الحساب في Firebase Authentication.
 *
 * ── الإعداد الأساسي (مشترك) ──────────────────────────────────────────────────
 * 1) Firebase Console > Authentication > Get started (يكفي الضغط عليها مرة واحدة؛ تفعيل Email/Password لا يضر).
 * 2) Firebase Console > Project settings > Service accounts > Generate new private key (ينزل ملف JSON).
 * 3) cloudflare.com (حساب مجاني) > Workers & Pages > Create > Create Worker > Deploy > Edit code >
 *    الصق هذا الملف كاملاً > Deploy.
 * 4) Storage & Databases > KV > Create namespace (مثلاً 7asson) ثم في الـ Worker:
 *    Settings > Bindings > Add > KV namespace: Variable name = PUSH_KV.
 * 5) Settings > Variables and Secrets (أنشئ كلاً منها كـ Secret):
 *      FIREBASE_SERVICE_ACCOUNT = محتوى ملف JSON كاملاً
 *      ADMIN_CODE               = رمز سرّي طويل تختاره (12 حرفاً فأكثر) لربط تطبيق المدير
 * 6) انسخ رابط الـ Worker (…workers.dev) وضعه في index.html مكان WORKER_URL، ثم ارفع index.html و admin-sw.js.
 *
 * ── إشعارات المدير الحقيقية ──────────────────────────────────────────────────
 * 7) Firebase Console > Project settings > Cloud Messaging: تأكد أن «Firebase Cloud Messaging API (V1)» مفعّل،
 *    ثم Web Push certificates > Generate key pair > ضع المفتاح في index.html مكان ADM_VAPID_KEY.
 * 8) Worker > Settings > Trigger Events > Cron Triggers > Add > Cron expression:  * * * * *
 * 9) (اختياري) SITE_URL (نوع Text) = https://موقعك/index.html?app=admin  ليُفتح التطبيق عند الضغط على الإشعار.
 * 10) في تطبيق المدير: الجرس > «ربط الإشعارات الحقيقية» > اسمح > اكتب ADMIN_CODE > «إشعار تجريبي».
 *
 * ── رمز التحقق بالبريد (يحتاج خدمة إرسال بريد مجانية) ───────────────────────────
 * 11) brevo.com (مجاني 300 رسالة/يوم): Senders, Domains & Dedicated IPs > Senders > Add a sender
 *     (بريدك الرسمي) وأكّده من الرسالة التي تصلك. ثم SMTP & API > API keys > Generate a new API key.
 * 12) أضف في الـ Worker (Secrets/Text):
 *       BREVO_API_KEY = المفتاح          (Secret)
 *       MAIL_FROM     = بريدك الرسمي المؤكَّد في Brevo   (Text)
 *       MAIL_NAME     = 7ASSON GAMING                      (Text، اختياري)
 *       DAILY_MAIL_LIMIT = 200                              (Text، اختياري: الحد اليومي للرسائل)
 *     بديل: Resend بدل Brevo => RESEND_API_KEY + MAIL_FROM (يتطلب نطاقاً/دومين موثّقاً لديهم).
 *
 * ملاحظة: KV المجاني يسمح بنحو 1000 عملية كتابة يومياً؛ كل تسجيل جديد يستهلك عدداً قليلاً منها.
 */

const CORS = {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'POST, GET, OPTIONS',
    'access-control-allow-headers': 'content-type'
};
const SCOPES = 'https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/firebase.messaging';
const CUSTOM_TOKEN_AUD = 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit';
const TYPES = {
    login:    ['🔑', 'تسجيل دخول'],
    register: ['🆕', 'مستخدم جديد'],
    request:  ['📥', 'طلب تنزيل'],
    download: ['⬇️', 'تنزيل جديد'],
    comment:  ['💬', 'تعليق جديد'],
    message:  ['✉️', 'رسالة جديدة'],
    dev:      ['👨‍💻', 'المطورون']
};
const ITEM = { game: 'اللعبة', app: 'التطبيق', wallpaper: 'الخلفية', file: 'الملف' };
const MAX_TOKENS = 5;        // عدد أجهزة المدير المسموح بها
const MAX_SINGLE = 5;        // أكثر من هذا في دقيقة واحدة => إشعار تلخيصي واحد
const OTP_TTL_MS = 5 * 60 * 1000;
const COOLDOWN_MS = 60 * 1000;
const MAX_TRIES = 5;

const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...CORS } });
const hex = (buf) => Array.from(new Uint8Array(buf), x => x.toString(16).padStart(2, '0')).join('');
const clip = (s) => String(s).slice(0, 200);
const text = (v) => (v && v.stringValue) || '';

async function sha256hex(s) { return hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))); }
async function sameCode(a, b) {            // مقارنة بزمن ثابت
    const [x, y] = await Promise.all([sha256hex(String(a)), sha256hex(String(b))]);
    let d = 0;
    for (let i = 0; i < x.length; i++) d |= x.charCodeAt(i) ^ y.charCodeAt(i);
    return d === 0;
}

const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const b64uStr = (s) => b64u(new TextEncoder().encode(s));

async function signJwt(sa, claims) {
    const head = b64uStr(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const body = b64uStr(JSON.stringify(claims));
    const der = Uint8Array.from(atob(sa.private_key.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(head + '.' + body));
    return head + '.' + body + '.' + b64u(sig);
}

let MEM_AT = null;
async function accessToken(env, sa) {
    const now = Math.floor(Date.now() / 1000);
    if (MEM_AT && MEM_AT.exp - 300 > now) return MEM_AT.token;
    const cached = await env.PUSH_KV.get('at', 'json');
    if (cached && cached.exp - 300 > now) { MEM_AT = cached; return cached.token; }
    const jwt = await signJwt(sa, { iss: sa.client_email, scope: SCOPES, aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 });
    const r = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + jwt
    });
    if (!r.ok) throw new Error('oauth ' + r.status + ' ' + (await r.text()).slice(0, 200));
    const j = await r.json();
    MEM_AT = { token: j.access_token, exp: now + (j.expires_in || 3600) };
    await env.PUSH_KV.put('at', JSON.stringify(MEM_AT), { expirationTtl: 3300 });
    return MEM_AT.token;
}

/* ===================================================== الإشعارات الحقيقية ===================================================== */

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
    const at = await accessToken(env, sa);
    const since = new Date(Date.parse(state.last) - 5000).toISOString();     // تداخل بسيط، والتكرار يُمنع بقائمة seen
    const [acts, logs] = await Promise.all([newDocs(pid, at, 'activity', 'createdAt', since), newDocs(pid, at, 'logs', 'timestamp', since)]);

    const seen = new Set(state.seen || []);
    const events = [];
    for (const d of acts) { const e = toEvent('a', d, env); if (e && !seen.has(e.key)) events.push(e); }
    for (const d of logs) { const e = toEvent('l', d, env); if (e && !seen.has(e.key)) events.push(e); }
    events.sort((x, y) => x.ts - y.ts);
    if (!events.length) return;

    const msgs = events.length <= MAX_SINGLE ? events
        : [{ title: '🔔 ' + events.length + ' أحداث جديدة', body: events[events.length - 1].body, tag: 'adm-batch-' + events[events.length - 1].key, url: env.SITE_URL || '' }];
    const res = await sendAll(pid, at, tokens, msgs);
    if (res.dead.length) await env.PUSH_KV.put('tokens', JSON.stringify(tokens.filter(t => !res.dead.includes(t))));

    const newest = Math.max(...events.map(e => e.ts).filter(Number.isFinite), Date.parse(state.last));
    state.last = new Date(newest).toISOString();
    state.seen = [...(state.seen || []), ...events.map(e => e.key)].slice(-200);
    await env.PUSH_KV.put('state', JSON.stringify(state));
}

/* ===================================================== رمز التحقق بالبريد + Firebase Authentication ===================================================== */

function normEmail(v) {
    v = String(v || '').trim().toLowerCase();
    return v.length <= 100 && /^[a-z0-9._%+\-]+@[a-z0-9\-]+(\.[a-z0-9\-]+)*\.[a-z]{2,}$/.test(v) ? v : '';
}
const codeHash = (env, email, code) => sha256hex(`${email}|${code}|${env.OTP_PEPPER || env.ADMIN_CODE || ''}`);

function otpMail(code, name) {
    const subject = `رمز التحقق ${code} — ${name}`;
    const plain = `رمز التحقق الخاص بك في ${name}: ${code}\nالرمز صالح لمدة 5 دقائق. إذا لم تطلبه فتجاهل هذه الرسالة.`;
    const html = `<div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;max-width:480px;margin:auto;padding:24px;border:1px solid #e5e0f5;border-radius:16px;background:#faf8ff;color:#1a1333">
<h2 style="margin:0 0 8px;color:#6d28d9">${name}</h2>
<p style="margin:0 0 16px">رمز التحقق الخاص بك لإنشاء الحساب:</p>
<div style="font-size:34px;letter-spacing:10px;font-weight:700;text-align:center;background:#fff;border:1px dashed #8b5cf6;border-radius:12px;padding:14px 0" dir="ltr">${code}</div>
<p style="margin:16px 0 0;font-size:13px;color:#555">الرمز صالح لمدة <b>5 دقائق</b> ويُستخدم مرة واحدة. إذا لم تطلب هذا الرمز فتجاهل الرسالة.</p></div>`;
    return { subject, plain, html };
}

async function sendMail(env, to, m) {
    const name = env.MAIL_NAME || '7ASSON GAMING';
    if (env.BREVO_API_KEY) {
        const r = await fetch('https://api.brevo.com/v3/smtp/email', {
            method: 'POST',
            headers: { 'api-key': env.BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
            body: JSON.stringify({ sender: { name, email: env.MAIL_FROM }, to: [{ email: to }], subject: m.subject, htmlContent: m.html, textContent: m.plain })
        });
        if (!r.ok) throw new Error('brevo ' + r.status + ' ' + (await r.text()).slice(0, 200));
        return;
    }
    const r = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { authorization: 'Bearer ' + env.RESEND_API_KEY, 'content-type': 'application/json' },
        body: JSON.stringify({ from: `${name} <${env.MAIL_FROM}>`, to: [to], subject: m.subject, html: m.html, text: m.plain })
    });
    if (!r.ok) throw new Error('resend ' + r.status + ' ' + (await r.text()).slice(0, 200));
}

async function emailExists(pid, at, email) {
    try {
        const r = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${pid}/accounts:lookup`, {
            method: 'POST',
            headers: { authorization: 'Bearer ' + at, 'content-type': 'application/json' },
            body: JSON.stringify({ email: [email] })
        });
        if (!r.ok) return false;                                             // إن تعذّر الفحص نكمل (الإنشاء نفسه يرفض المكرر)
        const j = await r.json();
        return Array.isArray(j.users) && j.users.length > 0;
    } catch (e) { return false; }
}

async function createAuthUser(pid, at, uid, email, name) {
    const r = await fetch(`https://identitytoolkit.googleapis.com/v1/projects/${pid}/accounts`, {
        method: 'POST',
        headers: { authorization: 'Bearer ' + at, 'content-type': 'application/json' },
        body: JSON.stringify({ localId: uid, email, emailVerified: true, displayName: name || undefined })
    });
    if (r.ok) return { ok: true };
    const t = await r.text();
    if (/EMAIL_EXISTS/.test(t)) return { ok: false, code: 'email_exists' };
    return { ok: false, code: 'create_failed', detail: t.slice(0, 200) };
}

const mailReady = (env) => !!(env.PUSH_KV && env.FIREBASE_SERVICE_ACCOUNT && env.MAIL_FROM && (env.BREVO_API_KEY || env.RESEND_API_KEY));

async function otpSend(b, env) {
    const email = normEmail(b.email);
    if (!email) return json({ error: 'bad_email' }, 400);
    if (!mailReady(env)) return json({ error: 'server_not_configured' }, 500);

    const key = 'otp:' + email, now = Date.now();
    const old = await env.PUSH_KV.get(key, 'json');
    if (old && now - old.sentAt < COOLDOWN_MS) return json({ error: 'cooldown', retryAfter: Math.ceil((COOLDOWN_MS - (now - old.sentAt)) / 1000) }, 429);

    const dk = 'mailcnt:' + new Date().toISOString().slice(0, 10);
    const used = +(await env.PUSH_KV.get(dk)) || 0;
    if (used >= (+env.DAILY_MAIL_LIMIT || 200)) return json({ error: 'daily_limit' }, 503);

    const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
    const at = await accessToken(env, sa);
    if (await emailExists(sa.project_id, at, email)) return json({ error: 'email_exists' }, 409);

    const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
    await env.PUSH_KV.put(key, JSON.stringify({ h: await codeHash(env, email, code), sentAt: now, exp: now + OTP_TTL_MS, tries: 0 }), { expirationTtl: 600 });
    try {
        await sendMail(env, email, otpMail(code, env.MAIL_NAME || '7ASSON GAMING'));
    } catch (e) {
        await env.PUSH_KV.delete(key);
        console.log('mail error', String(e));
        return json({ error: 'mail_failed', detail: String(e).slice(0, 160) }, 502);
    }
    await env.PUSH_KV.put(dk, String(used + 1), { expirationTtl: 172800 });
    return json({ ok: true, expiresIn: OTP_TTL_MS / 1000, resendIn: COOLDOWN_MS / 1000 });
}

async function otpVerify(b, env) {
    const email = normEmail(b.email), code = String(b.code || '').replace(/\D/g, '');
    if (!email || code.length !== 6) return json({ error: 'bad_code' }, 400);
    if (!mailReady(env)) return json({ error: 'server_not_configured' }, 500);

    const key = 'otp:' + email, now = Date.now();
    const rec = await env.PUSH_KV.get(key, 'json');
    if (!rec || rec.exp < now) { if (rec) await env.PUSH_KV.delete(key); return json({ error: 'expired' }, 410); }
    if (rec.tries >= MAX_TRIES) { await env.PUSH_KV.delete(key); return json({ error: 'too_many' }, 429); }

    if (!(await sameCode(rec.h, await codeHash(env, email, code)))) {
        rec.tries++;
        if (rec.tries >= MAX_TRIES) { await env.PUSH_KV.delete(key); return json({ error: 'too_many' }, 429); }
        await env.PUSH_KV.put(key, JSON.stringify(rec), { expiration: Math.ceil(rec.exp / 1000) + 60 });
        return json({ error: 'bad_code', left: MAX_TRIES - rec.tries }, 400);
    }
    await env.PUSH_KV.delete(key);                                           // الرمز يُستعمل مرة واحدة فقط

    const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
    const at = await accessToken(env, sa);
    const uid = crypto.randomUUID().replace(/-/g, '');
    const made = await createAuthUser(sa.project_id, at, uid, email, String(b.name || '').trim().slice(0, 40));
    if (!made.ok) {
        console.log('create user failed', made.code, made.detail || '');
        return json({ error: made.code, detail: made.detail || '' }, made.code === 'email_exists' ? 409 : 502);
    }
    const iat = Math.floor(Date.now() / 1000);
    const token = await signJwt(sa, { iss: sa.client_email, sub: sa.client_email, aud: CUSTOM_TOKEN_AUD, iat, exp: iat + 3600, uid });
    return json({ ok: true, uid, token });
}

/* ===================================================== الموجّه ===================================================== */

async function readBody(req) { try { return await req.json(); } catch (e) { return {}; } }

export default {
    async fetch(req, env) {
        try {
            const url = new URL(req.url), path = url.pathname.replace(/\/+$/, '') || '/';
            if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
            if (req.method === 'GET' && path === '/') return new Response('7asson worker ok', { headers: CORS });
            if (req.method !== 'POST') return json({ error: 'not_found' }, 404);

            const b = await readBody(req);
            if (path === '/otp/send') return await otpSend(b, env);
            if (path === '/otp/verify') return await otpVerify(b, env);

            // ---- مسارات المدير (تتطلب ADMIN_CODE)
            if (!env.ADMIN_CODE || !env.PUSH_KV) return json({ error: 'server_not_configured' }, 500);
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
                const at = await accessToken(env, sa);
                const res = await sendAll(sa.project_id, at, tokens, [{ title: '✅ إشعار تجريبي', body: 'الإشعارات الحقيقية تعمل — ستصلك الأحداث حتى والتطبيق مغلق.', tag: 'adm-test-' + Date.now(), url: env.SITE_URL || '' }]);
                if (res.dead.length) await env.PUSH_KV.put('tokens', JSON.stringify(tokens.filter(t => !res.dead.includes(t))));
                return json({ sent: res.ok, failed: res.fail, removed: res.dead.length });
            }
            return json({ error: 'not_found' }, 404);
        } catch (e) {
            console.log('worker error', String(e));
            return json({ error: 'server_error', detail: String(e).slice(0, 200) }, 500);
        }
    },

    async scheduled(event, env, ctx) {
        ctx.waitUntil(poll(env).catch(e => console.log('poll error', String(e))));
    }
};
