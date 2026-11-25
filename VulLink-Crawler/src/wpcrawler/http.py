"""Polite HTTP client: one host only, fixed delay between requests, size cap, request counter."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

DEFAULT_USER_AGENT = "VulLink-Crawler/0.1 (WordPress security self-assessment)"
MAX_BODY_BYTES = 5 * 1024 * 1024


@dataclass
class Response:
    url: str
    status: int
    headers: dict
    text: str

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


class Fetcher:
    def __init__(self, base_url: str, delay: float = 1.0, timeout: float = 15.0,
                 user_agent: str = DEFAULT_USER_AGENT, verify_tls: bool = True, max_requests: int = 300):
        self.base_url = base_url
        self.host = urlparse(base_url).netloc
        self.delay = delay
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.max_requests = max_requests
        self.requests_made = 0
        self.errors: list = []
        self._last = 0.0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent, "Accept": "*/*"})

    def same_host(self, url: str) -> bool:
        return urlparse(url).netloc in ("", self.host)

    def absolute(self, path_or_url: str) -> str:
        return urljoin(self.base_url, path_or_url)

    def get(self, path_or_url: str, allow_redirects: bool = True) -> Optional[Response]:
        url = self.absolute(path_or_url)
        if not self.same_host(url):
            return None
        if self.requests_made >= self.max_requests:
            self.errors.append(f"request budget ({self.max_requests}) exhausted, skipped {url}")
            return None
        wait = self.delay - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        self.requests_made += 1
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=allow_redirects,
                                    verify=self.verify_tls, stream=True)
            body = resp.raw.read(MAX_BODY_BYTES, decode_content=True)
            resp.close()
        except requests.RequestException as exc:
            self.errors.append(f"{url}: {exc.__class__.__name__}: {exc}")
            return None
        # requests falls back to ISO-8859-1 for text/* without a charset (RFC 2616), which garbles the
        # UTF-8 that WordPress serves (readme.txt, style.css). Only trust an explicitly declared charset.
        declared = "charset=" in resp.headers.get("content-type", "").lower()
        encoding = (resp.encoding if declared else None) or "utf-8"
        return Response(url=resp.url, status=resp.status_code,
                        headers={k.lower(): v for k, v in resp.headers.items()},
                        text=body.decode(encoding, errors="replace"))
