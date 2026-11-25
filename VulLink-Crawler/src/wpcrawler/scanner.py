"""Orchestrates one scan: crawl pages, run detectors, optionally probe actively."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

from .fingerprint import active, passive
from .fingerprint.parsers import same_host_links
from .http import DEFAULT_USER_AGENT, Fetcher
from .models import ScanResult

log = logging.getLogger("wpcrawler")


@dataclass
class ScanOptions:
    max_pages: int = 5
    delay: float = 1.0
    timeout: float = 15.0
    user_agent: str = DEFAULT_USER_AGENT
    verify_tls: bool = True
    max_requests: int = 300
    aggressive: bool = False
    plugin_slugs: List[str] = field(default_factory=list)  # aggressive: slugs to probe


def normalise_target(target: str) -> str:
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"Not a valid http(s) URL: {target}")
    return f"{parsed.scheme}://{parsed.netloc}/"


def scan(target: str, options: Optional[ScanOptions] = None) -> ScanResult:
    opts = options or ScanOptions()
    base = normalise_target(target)
    result = ScanResult(target=base, scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        mode="aggressive" if opts.aggressive else "default")

    fetcher = Fetcher(base, delay=opts.delay, timeout=opts.timeout, user_agent=opts.user_agent,
                      verify_tls=opts.verify_tls, max_requests=opts.max_requests)
    home = fetcher.get(base)
    if home is None or home.status >= 400:
        result.errors.append(f"start page not reachable ({home.status if home else 'no response'})")
        result.errors.extend(fetcher.errors)
        result.requests_made = fetcher.requests_made
        return result

    # Redirects (http -> https, www) define the real site; keep scanning that host only.
    if urlparse(home.url).netloc != urlparse(base).netloc:
        base = normalise_target(home.url)
        fetcher.base_url, fetcher.host = base, urlparse(base).netloc
    result.final_url = home.url

    log.info("Scanning %s", home.url)
    passive.check_headers(result, home)
    passive.analyse_page(result, home)
    for url in same_host_links(home.text, home.url)[: max(0, opts.max_pages - 1)]:
        page = fetcher.get(url)
        if page and page.ok and "html" in page.headers.get("content-type", ""):
            passive.analyse_page(result, page)

    passive.check_feed(result, fetcher)
    passive.check_rest_api(result, fetcher, home.headers.get("link"))

    if opts.aggressive:
        log.info("Aggressive checks enabled")
        active.check_core_files(result, fetcher)
        if opts.plugin_slugs:
            n = active.enumerate_plugins(result, fetcher, opts.plugin_slugs)
            log.info("Plugin enumeration: %d of %d probed slugs found", n, len(opts.plugin_slugs))
        active.config_checks(result, fetcher)

    if result.is_wordpress:
        passive.enrich_plugins(result, fetcher)
        passive.enrich_themes(result, fetcher)
    passive.finalize(result)

    result.requests_made = fetcher.requests_made
    result.errors.extend(fetcher.errors)
    return result
