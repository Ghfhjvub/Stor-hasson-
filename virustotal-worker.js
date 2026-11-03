// Cloudflare Worker — فاحص فيروسات للروابط عبر VirusTotal (يُخفي مفتاح API عن المتصفح)
// الإعداد: Workers & Pages > Create Worker > الصق هذا الملف > Settings > Variables:
//   VT_API_KEY  (Secret)  = مفتاحك من virustotal.com (الحساب المجاني يكفي: 4 طلبات/دقيقة)
//   ALLOW_ORIGIN (اختياري) = https://موقعك.com لتقييد الاستخدام بموقعك فقط
// ثم انسخ رابط الـ Worker وضعه في index.html داخل: const SCAN_API_URL = '...';
const MAX_BYTES = 32 * 1024 * 1024; // حد رفع الملفات في VirusTotal العادي

export default {
  async fetch(req, env) {
    const cors = { 'Access-Control-Allow-Origin': env.ALLOW_ORIGIN || '*', 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' };
    const out = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...cors, 'Content-Type': 'application/json' } });
    if (req.method === 'OPTIONS') return new Response(null, { headers: cors });
    if (req.method !== 'POST') return out({ error: 'POST only' }, 405);
    if (!env.VT_API_KEY) return out({ verdict: 'unscanned', detail: 'مفتاح VirusTotal غير مضبوط' });

    let url;
    try { url = new URL((await req.json()).url); if (!/^https?:$/.test(url.protocol)) throw 0; }
    catch (e) { return out({ verdict: 'unscanned', detail: 'رابط غير صالح' }, 400); }

    // روابط Google Drive -> رابط تنزيل مباشر
    if (/(^|\.)drive\.google\.com$/.test(url.hostname)) {
      const m = url.pathname.match(/\/d\/([\w-]+)/) || [null, url.searchParams.get('id')];
      if (m[1]) url = new URL('https://drive.google.com/uc?export=download&id=' + m[1]);
    }
    const H = { 'x-apikey': env.VT_API_KEY };
    try {
      // 1) نحمّل الملف بحد أقصى للحجم
      const r = await fetch(url.toString(), { redirect: 'follow', headers: { 'User-Agent': 'Mozilla/5.0 (7asson-scanner)' } });
      if (!r.ok) return out({ verdict: 'unscanned', detail: 'تعذّر تنزيل الملف للفحص (HTTP ' + r.status + ')' });
      if ((r.headers.get('content-type') || '').includes('text/html')) return out({ verdict: 'unscanned', detail: 'الرابط يفتح صفحة ويب وليس ملفاً مباشراً (أو الملف كبير على Drive)' });
      const len = +r.headers.get('content-length') || 0;
      if (len > MAX_BYTES) return out({ verdict: 'unscanned', detail: 'الملف أكبر من 32MB' });
      const chunks = []; let total = 0; const rd = r.body.getReader();
      for (;;) { const { done, value } = await rd.read(); if (done) break; total += value.length; if (total > MAX_BYTES) { await rd.cancel(); return out({ verdict: 'unscanned', detail: 'الملف أكبر من 32MB' }); } chunks.push(value); }
      const buf = new Uint8Array(total); let o = 0; for (const c of chunks) { buf.set(c, o); o += c.length; }
      const sha = [...new Uint8Array(await crypto.subtle.digest('SHA-256', buf))].map(b => b.toString(16).padStart(2, '0')).join('');
      const pack = st => out({ verdict: 'done', malicious: st.malicious || 0, suspicious: st.suspicious || 0, harmless: st.harmless || 0, undetected: st.undetected || 0, sha256: sha, permalink: 'https://www.virustotal.com/gui/file/' + sha });

      // 2) هل سبق فحص هذا الملف؟
      const known = await fetch('https://www.virustotal.com/api/v3/files/' + sha, { headers: H });
      if (known.ok) { const j = await known.json(); const st = j.data.attributes.last_analysis_stats; if ((st.harmless || 0) + (st.undetected || 0) + (st.malicious || 0) > 0) return pack(st); }

      // 3) نرفعه للفحص وننتظر النتيجة
      const fd = new FormData(); fd.append('file', new Blob([buf]), 'upload.bin');
      const up = await fetch('https://www.virustotal.com/api/v3/files', { method: 'POST', headers: H, body: fd });
      if (!up.ok) return out({ verdict: 'unscanned', detail: 'رفض VirusTotal الطلب (حد الاستخدام؟)' });
      const id = (await up.json()).data.id;
      for (let i = 0; i < 12; i++) {
        await new Promise(r => setTimeout(r, 5000));
        const a = await (await fetch('https://www.virustotal.com/api/v3/analyses/' + id, { headers: H })).json();
        if (a.data && a.data.attributes.status === 'completed') return pack(a.data.attributes.stats);
      }
      return out({ verdict: 'unscanned', detail: 'استغرق الفحص وقتاً أطول من المتوقع' });
    } catch (e) { return out({ verdict: 'unscanned', detail: 'خطأ أثناء الفحص' }); }
  }
};
