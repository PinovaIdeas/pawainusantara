# Pawai Nusantara — Mirror Server

Reverse proxy untuk **pawainusantara.vercel.app** yang menyajikan konten di
domain mirror kamu (**pawainusantara.co**) tanpa memunculkan **Vercel Security
Checkpoint** — SEO safe.

## Kenapa harus server (bukan Cloudflare Worker)?

Origin memakai **Attack Challenge Mode** Vercel:

- Tantangannya berupa **proof-of-work WebAssembly**, dan
- cookie hasil solve (`_vcrcs`) **diikat ke sidik jari TLS (JA3)** browser yang
  menyelesaikannya.

Akibatnya, HTTP client biasa (fetch/undici/curl, bahkan `curl-impersonate`)
**selalu ditolak (429)** walau cookie-nya benar. Cloudflare Worker pun tidak
bisa. Satu-satunya cara andal: jalankan **Chromium headless** dan lakukan semua
request ke origin **dari dalam browser itu** sehingga TLS-nya cocok dan cookie
otomatis dipakai. Itulah yang dilakukan `server.js`.

## Isi

| File | Fungsi |
| --- | --- |
| `server.js` | Reverse proxy lewat Chromium + auto-solve checkpoint + rewrite SEO + 404 kustom |
| `Dockerfile` | Node.js 20 + Chromium |
| `railway.json` | Konfigurasi build & deploy Railway |
| `package.json` | Dependensi (`express`, `puppeteer-core`) |

## Cara kerja singkat

1. Saat start, server membuka Chromium, mengunjungi origin, dan menyelesaikan
   checkpoint (cookie `_vcrcs` tersimpan di browser).
2. Setiap request pengunjung diteruskan ke origin **via `fetch` di dalam page**
   (TLS = Chromium, cookie otomatis) → origin balas konten asli.
3. Isi teks (HTML/CSS/JS/JSON/XML) ditulis ulang: `pawainusantara.vercel.app`
   → domain mirror. Aset biner (gambar/font) diteruskan apa adanya.
4. Kalau cookie kedaluwarsa (kena checkpoint lagi), server solve ulang otomatis.

## Deploy ke Railway

1. Push repo ini ke GitHub.
2. Railway → **New Project → Deploy from GitHub repo** → pilih repo ini.
3. Railway otomatis memakai `Dockerfile` (lihat `railway.json`).
4. Tunggu log: `Mirror listening on :8080` lalu `[browser] checkpoint solved.`
5. **Settings → Networking → Custom Domain** → tambahkan `pawainusantara.co`
   (dan `www` bila perlu) dan arahkan DNS sesuai instruksi Railway.

> Chromium butuh RAM. Pakai plan dengan **≥ 1 GB** memori. Untuk memori kecil,
> set variabel `POOL_SIZE=1`.

## Variabel lingkungan

| Variabel | Default | Keterangan |
| --- | --- | --- |
| `PORT` | `8080` | Port HTTP (Railway mengisinya otomatis) |
| `CHROMIUM_PATH` | `/usr/bin/chromium` | Lokasi binary Chromium |
| `POOL_SIZE` | `2` | Jumlah tab paralel (naikkan untuk trafik lebih tinggi) |
| `REQ_TIMEOUT_MS` | `45000` | Batas waktu tiap request ke origin |
| `BROWSER_UA` | Chrome desktop | User-Agent browser headless |

## Jalankan lokal (opsional)

```bash
npm install
# pakai Chrome/Chromium yang ada di sistem
CHROMIUM_PATH=/usr/bin/google-chrome-stable PORT=8080 npm start
# buka http://localhost:8080
```

## Catatan

- Konstanta tema 404 & `ORIGIN_HOST` ada di bagian atas `server.js`.
- `/.well-known/vercel/*` diteruskan apa adanya (tidak ditulis ulang).
- Cookie khusus per-pengunjung dari origin tidak diteruskan (sesi ditangani di
  sisi server), jadi ini paling cocok untuk situs publik/statis.