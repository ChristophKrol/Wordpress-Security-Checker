"""A tiny fake WordPress site (tests/fixtures/site) served on localhost for end-to-end scanner tests."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pytest

SITE = Path(__file__).parent / "fixtures" / "site"

ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/about/": ("about.html", "text/html; charset=utf-8"),
    "/feed/": ("feed.xml", "application/rss+xml"),
    "/wp-json/": ("wp-json.json", "application/json"),
}


class FakeWordPress(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output quiet
        pass

    def _send(self, status, body=b"", ctype="text/plain", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "Apache/2.4.57 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/8.1.2-1ubuntu2.14")
        self.send_header("Link", f'<http://{self.headers["Host"]}/wp-json/>; rel="https://api.w.org/"')
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/" and url.query == "author=1":
            return self._send(302, extra={"Location": "/author/admin/"})
        if url.path == "/xmlrpc.php":
            return self._send(405, b"XML-RPC server accepts POST requests only.")
        if url.path == "/wp-json/wp/v2/users":
            return self._send(200, b'[{"id":1,"slug":"admin"}]', "application/json")
        if url.path in ROUTES:
            name, ctype = ROUTES[url.path]
            return self._send(200, (SITE / name).read_bytes(), ctype)
        target = (SITE / url.path.lstrip("/")).resolve()
        if SITE.resolve() in target.parents and target.is_file():
            return self._send(200, target.read_bytes())
        return self._send(404, b"not found")


@pytest.fixture(scope="session")
def fake_site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeWordPress)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
