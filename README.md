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
| `server.js` | Reverse proxy lewat Chromium + auto-solve checkpoint + rewrite SEO + 404 kustom + inject token Turnstile |
| `ezsolver/` | Solver Cloudflare Turnstile (Python + nodriver, berbasis EzSolver) — service HTTP `:8191` |
| `start.sh` | Entrypoint: jalankan Xvfb + service solver + `server.js` |
| `Dockerfile` | Node.js 20 + Chromium + Python + nodriver + Xvfb |
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

## Cloudflare Turnstile (halaman voting `/mobil-XX`)

Halaman voting origin memasang **Cloudflare Turnstile** yang **terkunci ke domain**
`pawainusantara.vercel.app`. Di domain mirror, widget-nya gagal (`error`) sehingga
muncul **"Halaman belum siap. Periksa koneksi, lalu coba lagi."** dan form tidak
bisa dipakai. Penanganannya:

1. **Respons `/api/voting/bootstrap` ditulis ulang** → `turnstileSiteKey` di-null-kan
   supaya klien berhenti mewajibkan Turnstile (form langsung bisa dipakai, error
   "Halaman belum siap" hilang). Field lain (`voteIntentToken`, PoW, dll) tetap utuh.
2. **Token Turnstile asli disuntik di sisi server** ke body `POST /api/votes`. Token
   disolve oleh **EzSolver** (`ezsolver/`, nodriver) terhadap domain origin, ditampung
   di buffer, dan dipakai sekali per vote.

> **Penting — IP tepercaya.** Turnstile menilai reputasi IP + fingerprint browser.
> Dari IP **datacenter** (Railway/VPS) tanpa GPU, Cloudflare menahan token untuk
> widget invisible ini. **Terbukti bekerja** dengan **proxy residensial** (mis. IP
> Indonesia) via `SOLVER_PROXY` + `SOLVER_HOSTMAP=1` (default): halaman origin
> disajikan lokal (lewat checkpoint) sementara trafik challenge Turnstile keluar
> lewat IP residensial → token terbit.
>
> **Set kredensial proxy di Environment Variables Railway, JANGAN di kode**
> (repo publik). Format `SOLVER_PROXY` yang didukung:
> `host:port:user:pass` atau `http://user:pass@host:port`.
> Matikan solver total dengan `TURNSTILE_SOLVER_ENABLED=0` (perbaikan UI tetap jalan).

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
| `TURNSTILE_SOLVER_ENABLED` | `1` | `0` untuk mematikan solver (UI tetap diperbaiki) |
| `SOLVER_PROXY` | _(kosong)_ | Proxy residensial — **wajib** agar token terbit. Set di env Railway (bukan di kode). Format `host:port:user:pass` atau URL |
| `SOLVER_URL` | `http://127.0.0.1:8191` | Alamat service EzSolver |
| `SOLVER_SITEURL` | `<origin>/mobil-17` | Halaman origin tempat token disolve |
| `SOLVER_ACTION` | `vote` | Nilai `action` widget Turnstile |
| `TURNSTILE_SITEKEY` | `0x4AAAAAAEQG3hb7XG-CUqRR` | Sitekey awal (auto-update dari bootstrap) |
| `TOKEN_BUFFER_TARGET` | `3` | Jumlah token pra-solve yang disimpan |
| `MAX_WORKERS` | `1` | Chrome solver paralel (`~500 MB` RAM masing-masing) |
| `SOLVER_HOSTMAP` | `1` | Bypass Vercel checkpoint via host-map (dipakai bersama proxy) |

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