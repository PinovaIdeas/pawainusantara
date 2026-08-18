/**
 * Pawai Nusantara — Mirror Server (Railway / VPS / Render)
 * =======================================================
 * Origin (web asli)   : pawainusantara.vercel.app
 * Mirror (domain kamu): pawainusantara.co
 *
 * Masalah:
 *   Origin memasang "Vercel Security Checkpoint" (Attack Challenge Mode) —
 *   proof-of-work WebAssembly + pengikatan cookie ke sidik jari TLS (JA3)
 *   browser. Artinya:
 *     - Cookie hasil solve HANYA berlaku untuk klien dengan TLS yang sama
 *       persis dengan browser yang menyelesaikannya.
 *     - HTTP client biasa (fetch/undici/curl, bahkan curl-impersonate) DITOLAK
 *       (429) walau cookie benar.
 *
 * Solusi (terbukti):
 *   Semua request ke origin dijalankan LEWAT browser Chromium yang sama yang
 *   sudah lolos checkpoint (via `fetch` di dalam page). Dengan begitu sidik
 *   jari TLS selalu cocok, cookie `_vcrcs` otomatis terpakai, dan origin
 *   membalas konten asli (200). Pengunjung tidak pernah melihat checkpoint.
 *
 * Fitur:
 *   1. Reverse proxy penuh via browser (HTML, CSS, JS, gambar, font, API).
 *   2. Auto-solve checkpoint saat start & saat cookie kedaluwarsa.
 *   3. Rewrite semua referensi domain origin -> domain mirror (SEO safe).
 *   4. Halaman 404 kustom responsif.
 */

"use strict";

const express = require("express");
const puppeteer = require("puppeteer-core");

// ==== KONFIGURASI ====
const ORIGIN_HOST = "pawainusantara.vercel.app";
const ORIGIN = `https://${ORIGIN_HOST}`;
const PORT = process.env.PORT || 8080;
const CHROMIUM_PATH = process.env.CHROMIUM_PATH || "/usr/bin/chromium";
const POOL_SIZE = Number(process.env.POOL_SIZE || 2); // jumlah tab paralel
const REQ_TIMEOUT_MS = Number(process.env.REQ_TIMEOUT_MS || 45000);

const BROWSER_UA =
  process.env.BROWSER_UA ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

// Tema halaman 404 kustom.
const SITE_NAME = "Pawai Nusantara";
const BRAND_PRIMARY = "#c8102e";
const BRAND_ACCENT = "#f6a609";
const BRAND_DARK = "#0f172a";

const REWRITABLE_TYPES = [
  "text/html",
  "text/xml",
  "application/xml",
  "application/rss+xml",
  "application/atom+xml",
  "image/svg+xml",
  "text/plain",
  "application/json",
  "application/ld+json",
  "text/css",
  "application/javascript",
  "text/javascript",
  "application/manifest+json",
];

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);

// Header response yang tidak diteruskan ke pengunjung.
const STRIP_RES_HEADERS = new Set([
  "content-encoding", // body sudah ter-decode oleh browser
  "content-length", // dihitung ulang
  "transfer-encoding",
  "connection",
  "keep-alive",
  "x-vercel-mitigated",
  "x-robots-tag",
  "content-security-policy",
  "content-security-policy-report-only",
  "report-to",
  "nel",
  "set-cookie",
]);

// ==== TURNSTILE / SOLVER (EzSolver) ====
// Origin memasang Cloudflare Turnstile (domain-locked) di halaman voting.
// Di domain mirror widget-nya gagal ("Halaman belum siap"). Solusi:
//   1. Null-kan `turnstileSiteKey` di respons /api/voting/bootstrap -> klien
//      berhenti mewajibkan Turnstile, form bisa dipakai.
//   2. Suntik token Turnstile asli (disolve EzSolver terhadap domain origin)
//      ke body POST /api/votes sebelum diteruskan ke origin.
const SOLVER_ENABLED = process.env.TURNSTILE_SOLVER_ENABLED !== "0";
const SOLVER_URL = process.env.SOLVER_URL || "http://127.0.0.1:8191";
const SOLVER_SITEURL = process.env.SOLVER_SITEURL || `${ORIGIN}/mobil-17`;
const SOLVER_ACTION = process.env.SOLVER_ACTION || "vote";
const SOLVER_TIMEOUT_S = Number(process.env.SOLVER_TIMEOUT_S || 60);
const TOKEN_BUFFER_TARGET = Number(process.env.TOKEN_BUFFER_TARGET || 3);
const TOKEN_TTL_MS = Number(process.env.TOKEN_TTL_MS || 240000); // < 5 mnt (batas CF)
const VOTE_WAIT_MS = Number(process.env.VOTE_WAIT_MS || 8000);
const VOTE_PATHS = (process.env.VOTE_PATHS || "/api/votes")
  .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const BOOTSTRAP_PATHS = (process.env.BOOTSTRAP_PATHS || "/api/voting/bootstrap")
  .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const TURNSTILE_TOKEN_FIELD = process.env.TURNSTILE_TOKEN_FIELD || "turnstileToken";
const TURNSTILE_SITEKEY_FIELD = process.env.TURNSTILE_SITEKEY_FIELD || "turnstileSiteKey";
let discoveredSiteKey =
  process.env.TURNSTILE_SITEKEY || "0x4AAAAAAEQG3hb7XG-CUqRR";

// ---------------------------------------------------------------------------
// BROWSER MANAGER
// ---------------------------------------------------------------------------
let browser = null;
let pool = []; // array of Page
let rr = 0; // round-robin index
let initPromise = null;

async function launch() {
  browser = await puppeteer.launch({
    executablePath: CHROMIUM_PATH,
    headless: true,
    args: [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--disable-blink-features=AutomationControlled",
      "--lang=en-US,en",
    ],
  });
  browser.on("disconnected", () => {
    browser = null;
    pool = [];
    initPromise = null;
  });
}

async function newPage() {
  const page = await browser.newPage();
  await page.setUserAgent(BROWSER_UA);
  await page.setExtraHTTPHeaders({ "accept-language": "en-US,en;q=0.9" });
  await page.evaluateOnNewDocument(() => {
    Object.defineProperty(navigator, "webdriver", { get: () => undefined });
    Object.defineProperty(navigator, "languages", { get: () => ["en-US", "en"] });
    window.chrome = { runtime: {} };
  });
  return page;
}

async function waitForCookie(page, tries = 45) {
  for (let i = 0; i < tries; i++) {
    const cs = await page.cookies();
    if (cs.some((c) => /^_vcrc/i.test(c.name))) return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

// Inisialisasi browser + pool + solve checkpoint (dedupe).
function init() {
  if (initPromise) return initPromise;
  initPromise = (async () => {
    if (!browser) await launch();
    console.log("[browser] solving Vercel checkpoint…");
    // Halaman pertama menyelesaikan checkpoint; cookie masuk ke jar bersama.
    const first = await newPage();
    await first.goto(`${ORIGIN}/`, { waitUntil: "networkidle2", timeout: 60000 });
    const ok = await waitForCookie(first);
    console.log(ok ? "[browser] checkpoint solved." : "[browser] WARN: cookie tidak muncul.");
    pool = [first];
    // Sisa tab pool tinggal ikut memakai cookie yang sama.
    for (let i = 1; i < POOL_SIZE; i++) {
      const p = await newPage();
      await p.goto(`${ORIGIN}/`, { waitUntil: "domcontentloaded", timeout: 60000 }).catch(() => {});
      pool.push(p);
    }
    return ok;
  })().catch((e) => {
    console.error("[browser] init error:", e.message);
    initPromise = null;
    throw e;
  });
  return initPromise;
}

// Solve ulang (cookie kedaluwarsa): navigasikan satu tab ke "/".
let resolving = null;
function resolveChallenge() {
  if (resolving) return resolving;
  resolving = (async () => {
    try {
      const page = pool[0];
      if (!page) return init();
      console.log("[browser] re-solving checkpoint…");
      await page.goto(`${ORIGIN}/`, { waitUntil: "networkidle2", timeout: 60000 });
      await waitForCookie(page);
    } finally {
      resolving = null;
    }
  })();
  return resolving;
}

function pickPage() {
  if (!pool.length) return null;
  rr = (rr + 1) % pool.length;
  return pool[rr];
}

// Ambil resource dari origin LEWAT browser (TLS cocok + cookie otomatis).
async function fetchViaBrowser(page, url, method, headers, bodyB64) {
  const evalPromise = page.evaluate(
    async (url, method, headers, bodyB64) => {
      const opts = { method, headers, credentials: "include", redirect: "manual" };
      if (bodyB64) {
        opts.body = Uint8Array.from(atob(bodyB64), (c) => c.charCodeAt(0));
      }
      const r = await fetch(url, opts);
      const buf = await r.arrayBuffer();
      const bytes = new Uint8Array(buf);
      let bin = "";
      const chunk = 0x8000;
      for (let i = 0; i < bytes.length; i += chunk) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
      }
      const hdrs = {};
      r.headers.forEach((v, k) => (hdrs[k] = v));
      return {
        status: r.status,
        type: r.type,
        redirected: r.redirected,
        finalUrl: r.url,
        headers: hdrs,
        bodyB64: btoa(bin),
      };
    },
    url,
    method,
    headers,
    bodyB64
  );

  const timeout = new Promise((_, rej) =>
    setTimeout(() => rej(new Error("browser fetch timeout")), REQ_TIMEOUT_MS)
  );
  return Promise.race([evalPromise, timeout]);
}

function isChallengeResult(result) {
  if (!result) return false;
  if (result.status === 429) return true;
  const mit = String(result.headers["x-vercel-mitigated"] || "").toLowerCase();
  return mit.includes("challenge");
}

// ---------------------------------------------------------------------------
// TURNSTILE TOKEN BUFFER (pre-solved via EzSolver service)
// ---------------------------------------------------------------------------
const tokenBuffer = []; // { token, exp }
let refilling = false;
let nextRefillAt = 0;
const REFILL_BACKOFF_MS = Number(process.env.REFILL_BACKOFF_MS || 60000);

async function solveOneToken() {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), (SOLVER_TIMEOUT_S + 10) * 1000);
  try {
    const r = await fetch(`${SOLVER_URL}/solve`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sitekey: discoveredSiteKey,
        siteurl: SOLVER_SITEURL,
        action: SOLVER_ACTION,
        timeout: SOLVER_TIMEOUT_S,
      }),
      signal: ctrl.signal,
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok || !data.token) throw new Error(data.error || `solver HTTP ${r.status}`);
    return data.token;
  } finally {
    clearTimeout(timer);
  }
}

function pruneTokens() {
  const now = Date.now();
  for (let i = tokenBuffer.length - 1; i >= 0; i--) {
    if (tokenBuffer[i].exp <= now) tokenBuffer.splice(i, 1);
  }
}

async function refillTokens() {
  if (!SOLVER_ENABLED || refilling) return;
  if (Date.now() < nextRefillAt) return;
  refilling = true;
  try {
    pruneTokens();
    while (tokenBuffer.length < TOKEN_BUFFER_TARGET) {
      const token = await solveOneToken();
      tokenBuffer.push({ token, exp: Date.now() + TOKEN_TTL_MS });
      console.log(`[turnstile] token buffered (${tokenBuffer.length}/${TOKEN_BUFFER_TARGET})`);
    }
  } catch (e) {
    nextRefillAt = Date.now() + REFILL_BACKOFF_MS;
    console.warn("[turnstile] refill failed, backing off:", e.message);
  } finally {
    refilling = false;
  }
}

// Ambil satu token (sekali pakai). Tunggu sampai `waitMs` bila buffer kosong.
async function takeToken(waitMs = 0) {
  pruneTokens();
  if (tokenBuffer.length) {
    const t = tokenBuffer.shift();
    refillTokens().catch(() => {});
    return t.token;
  }
  refillTokens().catch(() => {});
  // Jangan menunggu bila sedang backoff (solve pasti gagal) — hindari delay sia-sia.
  if (Date.now() < nextRefillAt) return null;
  const deadline = Date.now() + waitMs;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 500));
    pruneTokens();
    if (tokenBuffer.length) return tokenBuffer.shift().token;
  }
  return null;
}

// Suntik token Turnstile ke body POST /api/votes.
async function injectVoteToken(rawBody) {
  let obj;
  try {
    obj = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return rawBody;
  }
  if (!obj || typeof obj !== "object") return rawBody;
  const token = await takeToken(SOLVER_ENABLED ? VOTE_WAIT_MS : 0);
  if (token) {
    obj[TURNSTILE_TOKEN_FIELD] = token;
    console.log("[turnstile] injected token into vote submission");
  } else {
    console.warn("[turnstile] no token available for vote submission");
  }
  return Buffer.from(JSON.stringify(obj), "utf8");
}

// Null-kan sitekey di respons bootstrap (klien berhenti mewajibkan Turnstile)
// sekaligus catat sitekey asli untuk dipakai solver.
function rewriteBootstrap(bodyBuf) {
  try {
    const obj = JSON.parse(bodyBuf.toString("utf8"));
    if (obj && typeof obj === "object") {
      const sk = obj[TURNSTILE_SITEKEY_FIELD];
      if (sk && sk !== discoveredSiteKey) {
        discoveredSiteKey = sk;
        console.log("[turnstile] discovered sitekey:", discoveredSiteKey);
      }
      obj[TURNSTILE_SITEKEY_FIELD] = null;
      return Buffer.from(JSON.stringify(obj), "utf8");
    }
  } catch {}
  return bodyBuf;
}

// ---------------------------------------------------------------------------
// UTIL
// ---------------------------------------------------------------------------
function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function rewriteText(text, mirrorHost) {
  if (!text) return text;
  const esc = escapeRegExp(ORIGIN_HOST);
  return text
    .replace(new RegExp(`https?:\\/\\/${esc}`, "gi"), `https://${mirrorHost}`)
    .replace(new RegExp(`\\/\\/${esc}`, "gi"), `//${mirrorHost}`)
    .replace(new RegExp(esc, "gi"), mirrorHost);
}

function ensureSelfCanonical(html, pathname, mirrorHost) {
  if (/<link[^>]+rel=["']canonical["']/i.test(html)) return html;
  const canonicalUrl = `https://${mirrorHost}${pathname}`;
  const tag = `<link rel="canonical" href="${canonicalUrl}"/>`;
  if (/<\/head>/i.test(html)) return html.replace(/<\/head>/i, `${tag}</head>`);
  return html;
}

// ---------------------------------------------------------------------------
// SERVER
// ---------------------------------------------------------------------------
const app = express();
app.disable("x-powered-by");
app.get("/healthz", (_req, res) => res.status(200).send("ok"));
app.use(express.raw({ type: () => true, limit: "50mb" }));

app.use(async (req, res) => {
  const mirrorHost = req.headers["x-forwarded-host"] || req.headers.host;
  const path = req.originalUrl;
  const pathname = path.split("?")[0];
  const pathLower = pathname.toLowerCase();
  const targetUrl = ORIGIN + path;

  // Header aman untuk diteruskan ke fetch di dalam browser.
  const fwdHeaders = {};
  if (req.headers["accept"]) fwdHeaders["accept"] = req.headers["accept"];
  if (req.headers["content-type"]) fwdHeaders["content-type"] = req.headers["content-type"];

  let reqBodyBuf =
    Buffer.isBuffer(req.body) && req.body.length ? req.body : null;
  if (reqBodyBuf && req.method === "POST" && VOTE_PATHS.includes(pathLower)) {
    reqBodyBuf = await injectVoteToken(reqBodyBuf);
  }
  const bodyB64 = reqBodyBuf ? reqBodyBuf.toString("base64") : null;

  try {
    await init();

    let page = pickPage();
    if (!page) throw new Error("no browser page available");

    let result = await fetchViaBrowser(page, targetUrl, req.method, fwdHeaders, bodyB64);

    // Kalau kena checkpoint: solve ulang lalu coba lagi sekali.
    if (isChallengeResult(result)) {
      await resolveChallenge();
      page = pickPage() || page;
      result = await fetchViaBrowser(page, targetUrl, req.method, fwdHeaders, bodyB64);
    }

    const status = result.status || 200;
    const h = result.headers || {};
    const contentType = String(h["content-type"] || "").toLowerCase();
    const bodyBuf = Buffer.from(result.bodyB64 || "", "base64");

    // ---- Redirect (kalau ada) ----
    if (REDIRECT_STATUS.has(status) && h["location"]) {
      res.status(status);
      res.setHeader("location", rewriteText(String(h["location"]), mirrorHost));
      return res.end();
    }

    // ---- 404 kustom (navigasi HTML) ----
    const acceptsHtml = String(req.headers["accept"] || "").includes("text/html");
    if (status === 404 && acceptsHtml) {
      res.status(404);
      res.setHeader("content-type", "text/html; charset=utf-8");
      res.setHeader("cache-control", "no-store");
      res.setHeader("x-robots-tag", "noindex");
      return res.end(render404());
    }

    const isVercelAsset = pathLower.startsWith("/.well-known/vercel/");
    const looksXml = pathLower.endsWith(".xml") || pathLower.endsWith(".txt");
    const rewritable =
      !isVercelAsset &&
      (REWRITABLE_TYPES.some((t) => contentType.includes(t)) || looksXml);

    // ---- Salin header (bersih) ----
    res.status(status);
    for (const [k, v] of Object.entries(h)) {
      if (!STRIP_RES_HEADERS.has(k.toLowerCase())) res.setHeader(k, v);
    }

    if (!rewritable) {
      res.setHeader("content-length", bodyBuf.length);
      return res.end(bodyBuf);
    }

    // ---- Teks: tulis ulang origin -> mirror ----
    let srcBuf = bodyBuf;
    if (BOOTSTRAP_PATHS.includes(pathLower) && contentType.includes("application/json")) {
      srcBuf = rewriteBootstrap(bodyBuf);
    }
    let body = rewriteText(srcBuf.toString("utf8"), mirrorHost);
    if (contentType.includes("text/html")) {
      body = ensureSelfCanonical(body, pathname, mirrorHost);
    }
    const out = Buffer.from(body, "utf8");
    res.setHeader("content-length", out.length);
    return res.end(out);
  } catch (err) {
    console.error("[proxy] error:", err.message);
    res.status(502);
    res.setHeader("content-type", "text/html; charset=utf-8");
    res.setHeader("retry-after", "5");
    return res.end(
      `<!doctype html><meta charset="utf-8"><title>502</title>` +
        `<p style="font:16px system-ui;padding:24px">Sedang menyiapkan koneksi ke server. Muat ulang sebentar lagi.</p>`
    );
  }
});

app.listen(PORT, () => {
  console.log(`Mirror listening on :${PORT} -> ${ORIGIN}`);
  init().catch(() => {});
  if (SOLVER_ENABLED) {
    console.log(`[turnstile] solver enabled -> ${SOLVER_URL} (buffer ${TOKEN_BUFFER_TARGET})`);
    refillTokens().catch(() => {});
    setInterval(() => refillTokens().catch(() => {}), 15000);
  } else {
    console.log("[turnstile] solver disabled (TURNSTILE_SOLVER_ENABLED=0)");
  }
});

// ---------------------------------------------------------------------------
// Halaman 404 kustom
// ---------------------------------------------------------------------------
function render404() {
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta name="robots" content="noindex, follow"/>
<title>404 \u2014 Halaman Tidak Ditemukan | ${SITE_NAME}</title>
<link rel="icon" href="/favicon.ico"/>
<style>
  *,*::before,*::after{box-sizing:border-box}
  html,body{margin:0;padding:0}
  body{
    min-height:100vh;min-height:100dvh;
    display:flex;align-items:center;justify-content:center;padding:24px;
    font-family:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    color:${BRAND_DARK};
    background:
      radial-gradient(1200px 600px at 100% 0%, ${BRAND_ACCENT}22, transparent 60%),
      radial-gradient(1000px 600px at 0% 100%, ${BRAND_PRIMARY}22, transparent 55%),
      #f8fafc;
  }
  .card{
    width:100%;max-width:560px;text-align:center;background:#fff;
    border:1px solid #e2e8f0;border-radius:24px;padding:clamp(28px,6vw,56px);
    box-shadow:0 30px 60px -20px rgba(2,6,23,.25);
  }
  .code{
    margin:0;font-weight:800;line-height:1;letter-spacing:-.03em;
    font-size:clamp(5rem,22vw,9rem);
    background:linear-gradient(135deg,${BRAND_PRIMARY},${BRAND_ACCENT});
    -webkit-background-clip:text;background-clip:text;color:transparent;
  }
  h1{font-size:clamp(1.25rem,5vw,1.75rem);margin:8px 0 6px}
  .desc{margin:0 auto 28px;max-width:40ch;color:#475569;
    font-size:clamp(.95rem,3.4vw,1.05rem);line-height:1.6}
  .actions{display:flex;flex-wrap:wrap;gap:12px;justify-content:center}
  .btn{display:inline-flex;align-items:center;justify-content:center;
    padding:12px 22px;border-radius:9999px;font-weight:600;text-decoration:none;
    font-size:1rem;transition:transform .15s ease,opacity .15s ease}
  .btn:active{transform:translateY(1px)}
  .btn-primary{color:#fff;
    background:linear-gradient(135deg,${BRAND_PRIMARY},${BRAND_ACCENT});
    box-shadow:0 10px 20px -8px ${BRAND_PRIMARY}aa}
  .btn-primary:hover{opacity:.92}
  .btn-ghost{color:${BRAND_DARK};background:#fff;border:1px solid #cbd5e1}
  .btn-ghost:hover{background:#f1f5f9}
  .brand{margin-top:26px;font-size:.85rem;color:#94a3b8}
</style>
</head>
<body>
  <main class="card">
    <p class="code">404</p>
    <h1>Halaman tidak ditemukan</h1>
    <p class="desc">Maaf, halaman yang kamu cari tidak ada, sudah dipindahkan, atau tautannya salah.</p>
    <div class="actions">
      <a class="btn btn-primary" href="/">Kembali ke Beranda</a>
      <a class="btn btn-ghost" href="/" onclick="history.back();return false;">Halaman Sebelumnya</a>
    </div>
    <div class="brand">${SITE_NAME}</div>
  </main>
</body>
</html>`;
}
