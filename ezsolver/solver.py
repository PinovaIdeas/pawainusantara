import asyncio
import json
import os
import platform
import random
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
"""
Cloudflare Turnstile solver — adapted for the Pawai Nusantara mirror.

Based on EzSolver by Ismoiloff (MIT). Adaptations for this deployment:
  * Runs inside a container / headless server (sandbox disabled, no-sandbox args).
  * Accepts an optional `action` so the token matches the origin widget
    (rendered with action:"vote").
  * Optional outbound proxy via SOLVER_PROXY (a residential proxy is required
    for Cloudflare to trust a datacenter host and actually issue a token).
  * Optional checkpoint bypass (SOLVER_HOSTMAP=1): the origin host is mapped to a
    tiny local HTTPS page so the widget renders on the locked domain without the
    upstream Vercel Security Checkpoint (which a fresh browser cannot pass).

USE AT YOUR OWN RISK — only against sites you own or are authorised to automate.
"""
import nodriver as uc

from proxyauth import proxy_chrome_arg

ORIGIN_HOST = os.environ.get("ORIGIN_HOST", "pawainusantara.vercel.app")
SOLVER_PROXY = os.environ.get("SOLVER_PROXY", "").strip()
USE_HOSTMAP = os.environ.get("SOLVER_HOSTMAP", "0") == "1"
HOSTMAP_PORT = int(os.environ.get("SOLVER_HOSTMAP_PORT", "8471"))
CERT_FILE = os.environ.get("SOLVER_CERT", "/tmp/solver_cert.pem")
KEY_FILE = os.environ.get("SOLVER_KEY", "/tmp/solver_key.pem")


def _find_chrome() -> str:
    """Return the Chrome/Chromium executable path, checking common locations."""
    if os.environ.get("CHROME_PATH"):
        return os.environ["CHROME_PATH"]

    if platform.system() == "Windows":
        candidates = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        ]
    else:
        candidates = [
            "/usr/bin/google-chrome-stable",
            "/usr/bin/google-chrome",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
        ]

    for path in candidates:
        if os.path.isfile(path):
            return path

    raise FileNotFoundError(
        "Chrome not found in default locations. "
        "Set the CHROME_PATH environment variable to your Chrome executable."
    )


def _get_profile_dir() -> str:
    """Return a persistent Chrome profile directory for the current OS."""
    if os.environ.get("TS_PROFILE_DIR"):
        return os.environ["TS_PROFILE_DIR"]
    if platform.system() == "Windows":
        base = os.environ.get("TEMP") or os.environ.get("TMP") or r"C:\Temp"
        return os.path.join(base, "ts_profile")
    return "/tmp/ts_profile"


def _start_xvfb_if_needed() -> Optional[subprocess.Popen]:
    """On Linux headless servers, start a virtual display so Chrome can run."""
    if platform.system() != "Linux":
        return None
    if os.environ.get("DISPLAY"):
        return None
    proc = subprocess.Popen(
        ["Xvfb", ":99", "-screen", "0", "1280x900x24"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    os.environ["DISPLAY"] = ":99"
    time.sleep(0.5)
    return proc


def _browser_args() -> list:
    """Chrome flags: container-safe + a more realistic GPU fingerprint."""
    args = [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        # SwiftShader still exposes WebGL (fully disabling GPU is a stronger bot signal).
        "--use-gl=angle",
        "--use-angle=swiftshader",
        "--enable-unsafe-swiftshader",
        "--ignore-gpu-blocklist",
        "--lang=en-US,en",
    ]
    if SOLVER_PROXY:
        proxy_arg = proxy_chrome_arg(SOLVER_PROXY)
        if proxy_arg:
            args.append(proxy_arg)
            # When proxied, the locally-mapped origin host must go direct.
            if USE_HOSTMAP:
                args.append(f"--proxy-bypass-list={ORIGIN_HOST};127.0.0.1;localhost")
    if USE_HOSTMAP:
        args.append(f"--host-resolver-rules=MAP {ORIGIN_HOST} 127.0.0.1:{HOSTMAP_PORT}")
        args.append("--ignore-certificate-errors")
    return args


# --- Optional local HTTPS page for the checkpoint-bypass (host-map) mode --------
_hostmap_started = False
_hostmap_lock = threading.Lock()


def _ensure_selfsigned_cert():
    if os.path.isfile(CERT_FILE) and os.path.isfile(KEY_FILE):
        return
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", KEY_FILE,
         "-out", CERT_FILE, "-days", "365", "-nodes",
         "-subj", f"/CN={ORIGIN_HOST}",
         "-addext", f"subjectAltName=DNS:{ORIGIN_HOST}"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def _start_hostmap_server():
    """Serve a minimal widget page for any path on the mapped origin host."""
    global _hostmap_started
    with _hostmap_lock:
        if _hostmap_started:
            return
        _ensure_selfsigned_cert()

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                page = (
                    "<!doctype html><html><head><meta charset='utf-8'>"
                    "<title>solver</title></head><body style='background:#fff'>"
                    "<div id='_ts_box'></div></body></html>"
                ).encode()
                self.send_response(200)
                self.send_header("content-type", "text/html; charset=utf-8")
                self.send_header("content-length", str(len(page)))
                self.end_headers()
                self.wfile.write(page)

        httpd = HTTPServer(("127.0.0.1", HOSTMAP_PORT), _H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        _hostmap_started = True


async def _solve(sitekey: str, siteurl: str, timeout: int, action: str = "") -> str:
    if USE_HOSTMAP:
        _start_hostmap_server()
        # Load the locked domain locally (bypasses the upstream checkpoint).
        siteurl = f"https://{ORIGIN_HOST}/__ts_solve"

    browser = await uc.start(
        browser_executable_path=_find_chrome(),
        headless=False,
        user_data_dir=_get_profile_dir(),
        sandbox=False,
        browser_args=_browser_args(),
    )

    token = None
    try:
        page = await browser.get(siteurl)
        await asyncio.sleep(random.uniform(2.0, 3.0))

        action_line = f"action: '{action}'," if action else ""
        # Inject the widget into the live page DOM.
        await page.evaluate("""
            (() => {
                if (document.getElementById('_ts_box_w')) return;
                window._tsToken = null;
                let host = document.getElementById('_ts_box');
                if (!host) {
                    host = document.createElement('div');
                    host.id = '_ts_box';
                    host.style = 'position:fixed;top:20px;left:20px;z-index:2147483647;';
                    document.body.appendChild(host);
                }
                const marker = document.createElement('span');
                marker.id = '_ts_box_w';
                host.appendChild(marker);
                window._tsLoad = function () {
                    turnstile.render('#_ts_box', {
                        sitekey: '%SITEKEY%',
                        %ACTION%
                        callback: function(token) { window._tsToken = token; }
                    });
                };
                const s = document.createElement('script');
                s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=_tsLoad&render=explicit';
                s.async = true;
                document.head.appendChild(s);
            })();
        """.replace("%SITEKEY%", sitekey).replace("%ACTION%", action_line))

        # Give Turnstile time to load and potentially auto-complete (invisible mode).
        await asyncio.sleep(5.0)

        async def get_token() -> Optional[str]:
            return await page.evaluate("""
                (() => {
                    if (window._tsToken) return window._tsToken;
                    const inp = document.querySelector('#_ts_box [name="cf-turnstile-response"]');
                    return (inp && inp.value) ? inp.value : null;
                })()
            """)

        async def get_cf_iframe_rect() -> Optional[dict]:
            raw = await page.evaluate("""
                JSON.stringify((() => {
                    for (const f of document.querySelectorAll('iframe')) {
                        const src = f.src || f.getAttribute('src') || '';
                        if (!src.includes('challenges.cloudflare.com')) continue;
                        const r = f.getBoundingClientRect();
                        if (r.width > 50 && r.height > 20) return {x:r.x, y:r.y, w:r.width, h:r.height};
                    }
                    return null;
                })())
            """)
            if raw and raw != 'null':
                return json.loads(raw)
            return None

        async def do_click(rect: Optional[dict]):
            if rect:
                cx = rect["x"] + 28 + random.uniform(-3, 3)
                cy = rect["y"] + rect["h"] / 2 + random.uniform(-3, 3)
                print(f"[solver] clicking Cloudflare iframe at ({cx:.0f}, {cy:.0f})")
            else:
                cx = 20 + 28 + random.uniform(-3, 3)
                cy = 20 + 32 + random.uniform(-3, 3)
                print(f"[solver] iframe not in DOM, clicking fixed position ({cx:.0f}, {cy:.0f})")
            await page.mouse_move(cx - 80, cy - 20)
            await asyncio.sleep(random.uniform(0.15, 0.25))
            await page.mouse_move(cx, cy)
            await asyncio.sleep(random.uniform(0.08, 0.15))
            await page.mouse_click(cx, cy)

        token = await get_token()
        if token:
            return token

        rect = None
        for _ in range(20):
            rect = await get_cf_iframe_rect()
            if rect:
                break
            await asyncio.sleep(0.5)

        deadline = asyncio.get_event_loop().time() + timeout
        click_count = 0
        last_click = 0.0

        while asyncio.get_event_loop().time() < deadline:
            token = await get_token()
            if token:
                break

            now = asyncio.get_event_loop().time()
            if click_count == 0 or (not token and now - last_click > 8):
                if click_count >= 3:
                    await asyncio.sleep(0.3)
                    continue
                await do_click(rect)
                last_click = asyncio.get_event_loop().time()
                click_count += 1
                await asyncio.sleep(1.0)
                rect = await get_cf_iframe_rect() or rect
                continue

            await asyncio.sleep(0.3)

    finally:
        browser.stop()

    if not token:
        raise TimeoutError(f"Turnstile token not obtained within {timeout}s")

    return token


def solve(sitekey: str, siteurl: str, timeout: int = 45, action: str = "") -> str:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return asyncio.run(_solve(sitekey, siteurl, timeout, action))


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python solver.py <sitekey> <siteurl> [action]")
        sys.exit(1)

    xvfb = _start_xvfb_if_needed()
    try:
        act = sys.argv[3] if len(sys.argv) > 3 else ""
        token = solve(sys.argv[1], sys.argv[2], action=act)
        print(token)
    finally:
        if xvfb:
            xvfb.terminate()
