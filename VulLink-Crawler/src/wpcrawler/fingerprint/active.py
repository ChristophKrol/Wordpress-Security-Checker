"""Aggressive detectors: probe paths a normal visitor would never request.

Only run against sites you own or have written permission to test (the CLI enforces --authorized).
Nothing here sends data, logs in, or tries to exploit anything; it only issues GET requests and
never stores the content of sensitive files it finds, only the fact that they are reachable.
"""
from __future__ import annotations

import re
import secrets
from typing import Iterable

from ..http import Fetcher
from ..models import Evidence, Finding, ScanResult
from . import parsers as p


def enumerate_plugins(result: ScanResult, fetcher: Fetcher, slugs: Iterable[str]) -> int:
    """Probe /wp-content/plugins/<slug>/readme.txt for each slug. Returns the number of plugins found."""
    # Soft-404 guard: if a random slug also "exists", every probe would be a false positive.
    canary = fetcher.get(f"/wp-content/plugins/zz-{secrets.token_hex(6)}/readme.txt")
    if canary and canary.ok and any(p.parse_readme(canary.text)):
        result.errors.append("plugin enumeration skipped: server answers 200 with a readme for nonexistent plugins")
        return 0

    found = 0
    known = {c.slug for c in result.components.values() if c.type == "plugin"}
    for raw in slugs:
        slug = p.clean_slug(raw)
        if not slug or slug in known:
            continue
        resp = fetcher.get(f"/wp-content/plugins/{slug}/readme.txt")
        if not (resp and resp.ok):
            continue
        name, stable, changelog = p.parse_readme(resp.text)
        if not (name or stable or changelog):
            continue
        found += 1
        comp = result.component("plugin", slug, name)
        comp.add(Evidence("readme-probe", resp.url, None, "high"))
        if stable and changelog and stable == changelog:
            comp.add(Evidence("readme.txt", resp.url, stable, "high"))
        else:
            if stable:
                comp.add(Evidence("readme.txt:stable-tag", resp.url, stable, "medium"))
            if changelog:
                comp.add(Evidence("readme.txt:changelog", resp.url, changelog, "medium"))
    return found


def check_core_files(result: ScanResult, fetcher: Fetcher) -> None:
    resp = fetcher.get("/readme.html")
    if resp and resp.ok and "wordpress" in resp.text.lower():
        result.findings.append(Finding("readme-html", "WordPress readme.html is publicly accessible", "info", resp.url,
                                       "Reveals that the site runs WordPress; older versions also reveal the version."))
        ver = p.readme_html_version(resp.text)
        if ver:
            result.component("core", "wordpress", "WordPress").add(Evidence("readme.html", resp.url, ver, "medium"))


def config_checks(result: ScanResult, fetcher: Fetcher) -> None:
    resp = fetcher.get("/xmlrpc.php")
    if resp and resp.status == 405 and "XML-RPC server accepts POST requests only" in resp.text:
        result.findings.append(Finding(
            "xmlrpc-enabled", "XML-RPC is enabled", "low", resp.url,
            "Allows brute-force amplification (system.multicall) and pingback abuse if not needed."))

    resp = fetcher.get("/wp-json/wp/v2/users")
    if resp and resp.ok and resp.text.lstrip().startswith("["):
        users = re.findall(r'"slug"\s*:\s*"([^"]{1,60})"', resp.text)
        if users:
            result.findings.append(Finding(
                "user-enumeration-rest", "Usernames are listed by the REST API", "medium", resp.url,
                f"{len(users)} user slug(s) exposed: {', '.join(sorted(set(users))[:10])}"))

    resp = fetcher.get("/?author=1", allow_redirects=False)
    if resp and resp.status in (301, 302) and "/author/" in resp.headers.get("location", ""):
        result.findings.append(Finding(
            "user-enumeration-author", "Usernames can be enumerated via ?author=N", "medium", resp.url,
            f"Redirects to {resp.headers.get('location')}"))

    resp = fetcher.get("/wp-content/uploads/")
    if resp and resp.ok and "<title>Index of" in resp.text:
        result.findings.append(Finding(
            "directory-listing-uploads", "Directory listing is enabled for /wp-content/uploads/", "medium", resp.url,
            "Anyone can browse all uploaded files."))

    resp = fetcher.get("/wp-content/debug.log")
    if resp and resp.ok and re.search(r"PHP (Notice|Warning|Fatal error|Deprecated)", resp.text[:20000]):
        result.findings.append(Finding(
            "debug-log-exposed", "debug.log is publicly readable", "high", resp.url,
            "PHP error log may leak file paths, plugin details and sometimes credentials. Content not stored."))

    for path in ("/wp-config.php.bak", "/wp-config.php~", "/wp-config.old", "/wp-config.php.save",
                 "/wp-config.txt", "/.wp-config.php.swp"):
        resp = fetcher.get(path)
        if resp and resp.ok and "DB_PASSWORD" in resp.text:
            result.findings.append(Finding(
                "wp-config-backup", "A wp-config.php backup is publicly readable", "high", resp.url,
                "Contains database credentials and secret keys. Content not stored - remove the file and rotate secrets."))
