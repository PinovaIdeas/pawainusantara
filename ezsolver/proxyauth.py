"""
Local proxy auth relay.

Chrome's --proxy-server flag cannot carry username:password. This starts a tiny
local proxy that Chrome talks to (no auth), and forwards every connection to the
upstream authenticated proxy, injecting the Proxy-Authorization header.

Done at the socket level (no CDP / Fetch domain), so it does not interfere with
Turnstile's automation detection.
"""

import base64
import select
import socket
import threading
import urllib.parse


def parse_proxy(s):
    """Accept 'scheme://user:pass@host:port' or 'host:port:user:pass' or 'host:port'."""
    s = (s or "").strip()
    if not s:
        return None
    if "://" in s:
        u = urllib.parse.urlparse(s)
        return {
            "scheme": u.scheme or "http",
            "host": u.hostname,
            "port": u.port,
            "user": urllib.parse.unquote(u.username) if u.username else None,
            "pass": urllib.parse.unquote(u.password) if u.password else None,
        }
    parts = s.split(":")
    if len(parts) >= 4:
        return {"scheme": "http", "host": parts[0], "port": int(parts[1]),
                "user": parts[2], "pass": ":".join(parts[3:])}
    if len(parts) == 2:
        return {"scheme": "http", "host": parts[0], "port": int(parts[1]),
                "user": None, "pass": None}
    return None


def _pipe(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 120)
            if not r:
                break
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except Exception:
        pass
    finally:
        for s in (a, b):
            try:
                s.close()
            except Exception:
                pass


class ProxyAuthRelay:
    def __init__(self, upstream):
        self.up = upstream
        self.auth_line = None
        if upstream.get("user"):
            raw = f"{upstream['user']}:{upstream['pass']}".encode()
            self.auth_line = b"Proxy-Authorization: Basic " + base64.b64encode(raw)
        self.port = None

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(128)
        self.port = srv.getsockname()[1]
        threading.Thread(target=self._serve, args=(srv,), daemon=True).start()
        return self.port

    def _serve(self, srv):
        while True:
            try:
                client, _ = srv.accept()
            except Exception:
                break
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client):
        up = None
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = client.recv(4096)
                if not chunk:
                    client.close()
                    return
                buf += chunk
                if len(buf) > 65536:
                    break
            head, _, rest = buf.partition(b"\r\n\r\n")
            lines = [l for l in head.split(b"\r\n")
                     if not l.lower().startswith(b"proxy-authorization:")]
            if self.auth_line:
                lines.insert(1, self.auth_line)
            new_head = b"\r\n".join(lines) + b"\r\n\r\n"

            up = socket.create_connection((self.up["host"], self.up["port"]), timeout=30)
            up.sendall(new_head + rest)
            _pipe(client, up)
        except Exception:
            try:
                client.close()
            except Exception:
                pass
            if up:
                try:
                    up.close()
                except Exception:
                    pass


_relay = None
_relay_lock = threading.Lock()


def proxy_chrome_arg(solver_proxy):
    """Return a Chrome --proxy-server value for the given proxy string, or None.

    For authenticated proxies a local relay is started (once) and Chrome is
    pointed at it; for unauthenticated proxies the upstream is used directly.
    """
    up = parse_proxy(solver_proxy)
    if not up:
        return None
    if up.get("user"):
        global _relay
        with _relay_lock:
            if _relay is None:
                _relay = ProxyAuthRelay(up)
                _relay.start()
            port = _relay.port
        return f"--proxy-server=http://127.0.0.1:{port}"
    return f"--proxy-server={up['scheme']}://{up['host']}:{up['port']}"
