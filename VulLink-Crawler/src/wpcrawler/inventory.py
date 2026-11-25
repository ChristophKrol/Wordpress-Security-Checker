"""Load a server-side inventory (VulLink-Collector, schema vullink-inventory/1) as a ScanResult.

The inventory comes from a server you control, but it is still treated as untrusted input: slugs and
versions pass the same validation as crawled values before they reach a query.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from .fingerprint.parsers import clean_slug, clean_version
from .models import Evidence, Finding, ScanResult

SCHEMA = "vullink-inventory/1"
COMPONENT_TYPES = {"core", "plugin", "theme", "server"}


def load(path: Union[str, Path]) -> ScanResult:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if data.get("schema") != SCHEMA:
        raise ValueError(f"{path}: not a VulLink inventory (expected schema {SCHEMA!r}, got {data.get('schema')!r})")

    site = data.get("site", {})
    result = ScanResult(target=site.get("url", ""), final_url=site.get("url", ""),
                        scanned_at=data.get("collectedAt", ""), mode="server-inventory", is_wordpress=True)

    for c in data.get("components", []):
        type_, slug = c.get("type"), clean_slug(str(c.get("slug", "")))
        if type_ not in COMPONENT_TYPES or not slug:
            result.errors.append(f"skipped invalid component: {c.get('type')}:{c.get('slug')}")
            continue
        comp = result.component(type_, slug, c.get("name"))
        version = clean_version(c.get("version"))
        comp.add(Evidence("server-inventory", c.get("source", ""), version, "high"))
        comp.details = c.get("details") or {}
        comp.notes.extend(n for n in c.get("notes", []) if n not in comp.notes)

    for f in data.get("findings", []):
        result.findings.append(Finding(f.get("id", ""), f.get("title", ""), f.get("severity", "info"),
                                       f.get("url", ""), f.get("detail", "")))

    result.extra = {
        "packages": data.get("packages", []),
        "libraries": data.get("libraries", []),
        "integrity": data.get("integrity", {}),
        "environment": data.get("environment", {}),
    }
    result.errors.extend(data.get("errors", []))
    return result
