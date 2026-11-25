"""Default detectors: everything a normal visitor's browser would also load or could see.

Requests: the start page plus a few internal pages, the RSS feed, the REST API index, and
readme.txt / style.css of components that the pages already revealed.
"""
from __future__ import annotations

import json
from typing import Optional

from ..http import Fetcher, Response
from ..models import Evidence, Finding, ScanResult
from . import parsers as p


def analyse_page(result: ScanResult, resp: Response) -> None:
    html = resp.text
    urls = p.extract_urls(html, resp.url)

    for type_, slug, ver, url in p.wp_component_refs(urls):
        result.is_wordpress = True
        comp = result.component(type_, slug)
        comp.add(Evidence("asset-path", url, ver, "medium" if ver else "low"))

    for ver, url in p.core_asset_versions(urls):
        result.is_wordpress = True
        result.component("core", "wordpress", "WordPress").add(Evidence("core-asset-ver", url, ver, "low"))

    for content in p.meta_generators(html):
        name, ver = p.parse_generator(content)
        if name == "wordpress":
            result.is_wordpress = True
            result.component("core", "wordpress", "WordPress").add(
                Evidence("meta-generator", content[:120], ver, "high" if ver else "low"))
        elif name in p.GENERATOR_SLUGS:
            result.component("plugin", p.GENERATOR_SLUGS[name], content.split(";")[0][:80]).add(
                Evidence("meta-generator", content[:120], ver, "high" if ver else "low"))

    for slug, ver, text in p.comment_signatures(html):
        result.component("plugin", slug).add(Evidence("html-comment", text, ver, "high" if ver else "low"))

    if "/wp-includes/" in html or "/wp-content/" in html:
        result.is_wordpress = True


def check_headers(result: ScanResult, resp: Response) -> None:
    for slug, name, ver, header in p.server_software(resp.headers):
        comp = result.component("server", slug, name)
        comp.add(Evidence("header", header, ver, "high" if ver else "low"))
        distro = p.distro_package(header)
        if distro and ver:
            note = (f"{distro} package: security fixes are often backported without changing the version "
                    f"number, so version-based matches may be false positives. Check the distro's security tracker.")
            if note not in comp.notes:
                comp.notes.append(note)
    cdn = p.cdn_in_front(resp.headers)
    if cdn:
        result.findings.append(Finding(
            "cdn-detected", f"Site is served through {cdn}", "info", resp.url,
            "Server headers may describe the CDN, not the origin server; server versions may be hidden."))
    if p.rest_root_from_link_header(resp.headers.get("link")):
        result.is_wordpress = True


def check_feed(result: ScanResult, fetcher: Fetcher) -> None:
    resp = fetcher.get("/feed/")
    if resp and resp.ok:
        ver = p.feed_generator_version(resp.text)
        if ver:
            result.is_wordpress = True
            result.component("core", "wordpress", "WordPress").add(Evidence("feed-generator", resp.url, ver, "high"))


def check_rest_api(result: ScanResult, fetcher: Fetcher, link_header: Optional[str]) -> None:
    root = p.rest_root_from_link_header(link_header) or "/wp-json/"
    resp = fetcher.get(root)
    if not (resp and resp.ok):
        return
    try:
        data = json.loads(resp.text)
    except ValueError:
        return
    namespaces = [n for n in data.get("namespaces", []) if isinstance(n, str)] if isinstance(data, dict) else []
    if not namespaces:
        return
    result.is_wordpress = True
    result.rest_namespaces = sorted(set(namespaces))
    for ns in namespaces:
        prefix = ns.split("/")[0].lower()
        if prefix in p.CORE_NAMESPACES:
            continue
        slug = p.REST_NAMESPACE_SLUGS.get(prefix)
        if slug:
            result.component("plugin", slug).add(Evidence("rest-namespace", ns, None, "low"))


def enrich_plugins(result: ScanResult, fetcher: Fetcher) -> None:
    """Fetch readme.txt of every plugin already seen; it usually states the installed version."""
    for comp in [c for c in result.components.values() if c.type == "plugin"]:
        resp = fetcher.get(f"/wp-content/plugins/{comp.slug}/readme.txt")
        if not (resp and resp.ok):
            continue
        name, stable, changelog = p.parse_readme(resp.text)
        if not (name or stable or changelog):
            continue
        comp.name = comp.name or name
        if stable and changelog and stable == changelog:
            comp.add(Evidence("readme.txt", resp.url, stable, "high"))
        else:
            if stable:
                comp.add(Evidence("readme.txt:stable-tag", resp.url, stable, "medium"))
            if changelog:
                comp.add(Evidence("readme.txt:changelog", resp.url, changelog, "medium"))


def enrich_themes(result: ScanResult, fetcher: Fetcher) -> None:
    """style.css holds the installed theme version; child themes name their parent in Template:."""
    seen = set()
    queue = [c.slug for c in result.components.values() if c.type == "theme"]
    while queue:
        slug = queue.pop(0)
        if slug in seen:
            continue
        seen.add(slug)
        resp = fetcher.get(f"/wp-content/themes/{slug}/style.css")
        if not (resp and resp.ok):
            continue
        name, version, parent = p.parse_style_css(resp.text)
        comp = result.component("theme", slug, name)
        if version:
            comp.add(Evidence("style.css", resp.url, version, "high"))
        if parent and parent != slug:
            result.component("theme", parent).add(Evidence("child-theme-template", resp.url, None, "high"))
            queue.append(parent)


def finalize(result: ScanResult) -> None:
    """A plugin asset's ?ver= equal to the WordPress version is almost always the core version: downgrade it."""
    core = result.components.get("core:wordpress")
    core_ver = core.version if core else None
    if not core_ver:
        return
    for comp in result.components.values():
        if comp.type in ("plugin", "theme"):
            for e in comp.evidence:
                if e.source == "asset-path" and e.version == core_ver:
                    e.confidence = "low"
