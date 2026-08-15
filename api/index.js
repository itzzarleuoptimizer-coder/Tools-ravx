// ============================================================
// SATU FILE BACKEND UNTUK VERCEL — semua endpoint di sini.
// CARA PAKAI DI GITHUB (tanpa upload folder):
//   "Add file" → "Create new file" → ketik nama file:
//   api/index.js
//   → GitHub otomatis membuat folder "api/" — lalu tempel kode ini.
// ============================================================
const crypto = require('crypto');
const https = require('https');
const http = require('http');

const PIN = process.env.ADMIN_PIN || '1234';
const BLOB = 'https://jsonblob.com/api/jsonBlob';

/* ---------- Penyimpanan (Vercel KV / Upstash) ---------- */
function redisConf(){
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '';
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '';
  return (url && token) ? { url, token } : null;
}
async function readLinks(){
  const c = redisConf();
  if(!c) return null;
  try{
    const r = await fetch(c.url + '/get/links', { headers: { Authorization: 'Bearer ' + c.token } });
    const d = await r.json();
    if(d && d.result){
      const arr = JSON.parse(d.result);
      if(Array.isArray(arr)) return arr;
    }
    return [];
  }catch(e){ return null; }
}
async function writeLinks(links){
  const c = redisConf();
  if(!c) return false;
  try{
    const r = await fetch(c.url + '/set/links', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + c.token, 'Content-Type': 'application/json' },
      body: JSON.stringify(JSON.stringify(links))
    });
    return r.ok;
  }catch(e){ return false; }
}

/* ---------- Scanner pasif ---------- */
function fetchTarget(url){
  return new Promise((resolve, reject) => {
    const mod = url.protocol === 'https:' ? https : http;
    const req = mod.get(url, {
      headers: { 'User-Agent': 'SiteCheck/1.0 (alat cek keamanan pasif)', 'Accept': '*/*' },
      timeout: 9000
    }, res => {
      let size = 0;
      res.on('data', c => { size += c.length; if(size > 2000000) req.destroy(); });
      res.on('end', () => {
        let tls = '';
        try{ tls = req.socket && req.socket.getProtocol ? (req.socket.getProtocol() || '') : ''; }catch(e){}
        resolve({ status: res.statusCode, headers: res.headers, size, proto: res.httpVersion, tls });
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', e => reject(e));
  });
}
async function doScan(urlStr){
  let target;
  try{ target = new URL(urlStr); }catch(e){ return { code: 400, json: { error: 'URL tidak valid. Contoh: https://contoh.com' } }; }
  if(target.protocol !== 'http:' && target.protocol !== 'https:') return { code: 400, json: { error: 'Hanya mendukung http/https' } };
  if(target.hostname === 'localhost' || target.hostname === '127.0.0.1') return { code: 400, json: { error: 'Scan terhadap localhost diblokir' } };
  try{
    const t0 = Date.now();
    let chain = [];
    let cur = target;
    for(let d = 0; d <= 3; d++){
      const info = await fetchTarget(cur);
      chain.push({ url: cur.toString(), status: info.status });
      if([301, 302, 303, 307, 308].includes(info.status) && info.headers.location && d < 3){
        cur = new URL(info.headers.location, cur);
      } else {
        const h = info.headers || {};
        const findings = [];
        const isHttps = cur.protocol === 'https:';
        if(!isHttps) findings.push({ level: 'warn', icon: '🔓', title: 'Tidak menggunakan HTTPS', detail: 'Koneksi tidak terenkripsi. Gunakan HTTPS.' });
        else {
          if(h['strict-transport-security']) findings.push({ level: 'good', icon: '🛡️', title: 'HSTS aktif', detail: 'strict-transport-security terpasang.' });
          else findings.push({ level: 'warn', icon: '⚠️', title: 'HSTS tidak ada', detail: 'Tambahkan header Strict-Transport-Security.' });
        }
        if(h['content-security-policy']) findings.push({ level: 'good', icon: '🛡️', title: 'CSP ada', detail: 'content-security-policy terpasang.' });
        else findings.push({ level: 'warn', icon: '⚠️', title: 'CSP tidak ada', detail: 'Risiko XSS lebih tinggi tanpa Content-Security-Policy.' });
        if(h['x-frame-options']) findings.push({ level: 'good', icon: '🛡️', title: 'X-Frame-Options ada', detail: 'Mencegah clickjacking.' });
        else findings.push({ level: 'warn', icon: '⚠️', title: 'X-Frame-Options tidak ada', detail: 'Situs bisa dipasang di iframe orang lain.' });
        if(h['x-content-type-options']) findings.push({ level: 'good', icon: '🛡️', title: 'X-Content-Type-Options ada', detail: 'Mencegah MIME sniffing.' });
        else findings.push({ level: 'warn', icon: '⚠️', title: 'X-Content-Type-Options tidak ada', detail: 'Browser bisa salah menafsirkan tipe file.' });
        if(h['referrer-policy']) findings.push({ level: 'good', icon: '🛡️', title: 'Referrer-Policy ada', detail: 'Kontrol info yang bocor saat pindah halaman.' });
        else findings.push({ level: 'info', icon: 'ℹ️', title: 'Referrer-Policy tidak ada', detail: 'URL halaman bisa ikut terkirim ke situs luar.' });
        if(h['permissions-policy']) findings.push({ level: 'good', icon: '🛡️', title: 'Permissions-Policy ada', detail: 'Membatasi akses fitur browser.' });
        else findings.push({ level: 'info', icon: 'ℹ️', title: 'Permissions-Policy tidak ada', detail: 'Fitur browser tidak dibatasi header.' });
        if(h.server) findings.push({ level: 'info', icon: '🖥️', title: 'Server terdeteksi: ' + String(h.server).slice(0,50), detail: 'Informasi versi server bocor.' });
        if(h['x-powered-by']) findings.push({ level: 'warn', icon: '⚠️', title: 'X-Powered-By bocor: ' + String(h['x-powered-by']).slice(0,50), detail: 'Sebaknya dihapus.' });
        const cookies = h['set-cookie'];
        if(cookies && cookies.length){
          cookies.forEach(c => {
            if(!/httponly/i.test(c)) findings.push({ level: 'warn', icon: '🍪', title: 'Cookie tanpa HttpOnly', detail: c.split(';')[0] + ' — bisa dibaca JavaScript.' });
            if(!/secure/i.test(c)) findings.push({ level: 'warn', icon: '🍪', title: 'Cookie tanpa Secure', detail: c.split(';')[0] + ' — dikirim lewat HTTP biasa.' });
            if(!/samesite/i.test(c)) findings.push({ level: 'info', icon: '🍪', title: 'Cookie tanpa SameSite', detail: c.split(';')[0] + ' — pertimbangkan SameSite.' });
          });
        }
        if(isHttps){
          if(/TLSv1\.[01]/.test(info.tls)) findings.push({ level: 'warn', icon: '🔒', title: 'TLS lama: ' + info.tls, detail: 'Wajib TLS 1.2+.' });
          else if(info.tls) findings.push({ level: 'good', icon: '🔒', title: 'TLS: ' + info.tls, detail: 'Versi protokol enkripsi aman.' });
        }
        if(info.status >= 500) findings.push({ level: 'warn', icon: '🩺', title: 'HTTP ' + info.status, detail: 'Server error — bisa jadi indikasi celah.' });
        else if(info.status >= 400) findings.push({ level: 'info', icon: 'ℹ️', title: 'HTTP ' + info.status, detail: 'Respon error dari server.' });
        else findings.push({ level: 'good', icon: '✅', title: 'HTTP ' + info.status, detail: 'Situs merespons normal.' });
        return { json: {
          ok: true, url: cur.toString(), status: info.status, timeMs: Date.now() - t0,
          sizeBytes: info.size, proto: info.proto, tls: info.tls, redirects: chain,
          server: h.server ? String(h.server).slice(0,80) : '',
          findings,
          headers: Object.keys(h).filter(k => !/^cf-ray|^cf-cache|^nel$|^report-to|^server-timing/i.test(k)).slice(0,40).map(k => ({ name: k, value: String(h[k]).slice(0,120) }))
        } };
      }
    }
    return { json: { ok: false, error: 'Terlalu banyak redirect' } };
  }catch(e){
    return { json: { ok: false, error: 'Tidak bisa mengakses situs: ' + (e.message === 'timeout' ? 'timeout (situs lambat/blokir)' : e.message) } };
  }
}

/* ---------- Handler utama ---------- */
module.exports = async (req, res) => {
  const pathname = String(req.url || '/').split('?')[0];
  try{
    /* ===== penyimpanan utama ===== */
    if(pathname === '/api/sdata'){
      if(!redisConf()) return res.status(503).json({ error: 'storage belum dikonfigurasi — buat Vercel KV lalu hubungkan ke proyek (Storage → KV → Create → Connect)' });
      if(req.method === 'GET'){
        const links = await readLinks();
        if(links === null) return res.status(503).json({ error: 'storage tidak bisa dibaca' });
        return res.json({ links });
      }
      if(req.method === 'PUT'){
        const b = req.body || {};
        if(!Array.isArray(b.links)) return res.status(400).json({ error: 'format tidak valid' });
        const ok = await writeLinks(b.links);
        if(!ok) return res.status(503).json({ error: 'storage tidak bisa ditulis' });
        return res.json({ ok: true });
      }
      return res.status(405).json({ error: 'method tidak didukung' });
    }

    /* ===== buat link (admin) ===== */
    if(pathname === '/api/create'){
      if(req.query.pin !== PIN) return res.status(403).json({ error: 'PIN salah' });
      const b = req.body || {};
      const id = crypto.randomBytes(4).toString('hex');
      const link = {
        id,
        name: String(b.name || 'Anonim').slice(0, 60),
        wa: String(b.wa || '').replace(/\D/g, '').slice(0, 15),
        msg: String(b.msg || '').slice(0, 300),
        createdAt: Date.now(),
        events: []
      };
      const links = (await readLinks()) || [];
      links.unshift(link);
      await writeLinks(links);
      return res.json({ id, url: '/lokasi?id=' + id });
    }

    /* ===== catat event (penerima link) ===== */
    if(pathname === '/api/track'){
      const b = req.body || {};
      const links = (await readLinks()) || [];
      const l = links.find(x => x.id === b.id);
      if(!l) return res.status(404).json({ error: 'id tidak dikenal' });
      const reqIp = req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : '';
      const ev = { type: b.event, ts: Date.now(), ip: reqIp };
      if(b.event === 'location' || b.event === 'ip'){
        ev.lat = Number(b.lat); ev.lon = Number(b.lon);
        ev.acc = String(b.acc || '').slice(0, 60);
        ev.addr = String(b.addr || '').slice(0, 300);
        if(b.ip) ev.ip = String(b.ip).slice(0, 60);
        if(b.auto) ev.auto = true;
      }
      if(b.dev) ev.dev = b.dev;
      if(b.img) ev.img = String(b.img).slice(0, 200000);
      if(b.ua) ev.ua = String(b.ua).slice(0, 200);
      l.events.push(ev);
      await writeLinks(links);
      return res.json({ ok: true });
    }

    /* ===== daftar link (admin) ===== */
    if(pathname === '/api/links'){
      if(req.query.pin !== PIN) return res.status(403).json({ error: 'PIN salah' });
      const links = await readLinks();
      return res.json({ links: links || [], now: Date.now() });
    }

    /* ===== hapus link (admin) ===== */
    if(pathname === '/api/delete'){
      if(req.query.pin !== PIN) return res.status(403).json({ error: 'PIN salah' });
      const b = req.body || {};
      const links = (await readLinks()) || [];
      await writeLinks(links.filter(x => x.id !== b.id));
      return res.json({ ok: true });
    }

    /* ===== link pendek (proxy shortener) ===== */
    if(pathname === '/api/shorten'){
      const url = req.query.url || '';
      if(!/^https?:\/\//.test(url)) return res.status(400).json({ error: 'url tidak valid' });
      try{
        const r = await fetch('https://spoo.me/api/v1/shorten', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({ long_url: url })
        });
        const d = await r.json();
        if(d && d.short_url) return res.json({ short: d.short_url });
      }catch(e){}
      try{
        const r2 = await fetch('https://tinyurl.com/api-create.php?url=' + encodeURIComponent(url));
        const t = (await r2.text()).trim();
        if(/^https?:\/\//.test(t)) return res.json({ short: t });
      }catch(e){}
      return res.status(502).json({ error: 'gagal membuat link pendek' });
    }

    /* ===== scan website ===== */
    if(pathname === '/api/scan'){
      const r = await doScan(req.query.url || '');
      return res.status(r.code || 200).json(r.json);
    }

    return res.status(404).json({ error: 'endpoint tidak dikenal' });
  }catch(e){
    return res.status(500).json({ error: String((e && e.message) || e) });
  }
};

