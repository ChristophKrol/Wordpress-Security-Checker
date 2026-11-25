"""Wordfence Intelligence v3 vulnerability feed connector.

Docs: https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/
The production feed is a full snapshot (one JSON object keyed by Wordfence UUID), so every run:
  1. downloads the snapshot,
  2. groups records by vulnID (CVE id, else "WORDFENCE-<uuid>"; several Wordfence records can share a CVE),
  3. loads only groups whose content hash changed since the last load (hash stored on the node),
  4. withdraws vulnerabilities Wordfence no longer lists (incl. WORDFENCE-<uuid> placeholders that got a CVE).

Licence: Defiant's licence requires a hyperlink to the record and its copyright notice in any copy;
we store the record URLs on each vulnerability (wfURLs) and the notice/licence on (:DataSource {name:"wordfence"}).
"""
from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from datetime import date, datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .common import HttpClient, env, save_raw

log = logging.getLogger("sources.wordfence")

SOURCE = "wordfence"
FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
RECORD_URL = "https://www.wordfence.com/threat-intel/vulnerabilities/id/{id}"
MIN_EXPECTED_RECORDS = 10_000  # sanity floor: never treat a truncated feed as mass withdrawal

# Wordfence "core" slugs -> NVD CPE product names, so core vulns land on the same Product node as NVD's.
CORE_PRODUCTS = {"wordpress": "wordpress", "wpmu": "wordpress_mu"}


def make_client() -> HttpClient:
    key = env("WORDFENCE_API_KEY")
    if not key:
        raise SystemExit("WORDFENCE_API_KEY is not set (expected in the repo-root .env)")
    # The feed is a ~175 MB full snapshot and Wordfence rate-limits downloads (HTTP 429 without
    # Retry-After), so fail fast instead of hammering it; schedule syncs a few hours apart.
    return HttpClient({"Authorization": f"Bearer {key}"}, min_interval=1.0, timeout=600,
                      max_retries=3, retry_on_429=False)


def fetch(client: HttpClient, tag: str) -> Dict[str, Dict]:
    data = client.get_json(FEED_URL)
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected Wordfence feed format: {type(data).__name__}")
    save_raw(SOURCE, f"{tag}/production", data)
    log.info("Wordfence feed: %d records", len(data))
    return data


# --------------------------------------------------------------------------- transform

def _date(value: Optional[str]) -> Optional[date]:
    return datetime.fromisoformat(value[:10]).date() if value else None


def _datetime(value: Optional[str]) -> Optional[datetime]:
    return datetime.fromisoformat(value[:19]) if value else None


def product_for(sw: Dict) -> Tuple[str, str, Optional[str]]:
    """(productName, productType, vendorName) for a Wordfence software entry."""
    kind, slug = sw.get("type"), sw.get("slug")
    if kind == "core":
        return CORE_PRODUCTS.get(slug, slug), "application", "wordpress"
    # Namespaced so plugin/theme slugs never collide with NVD CPE product names.
    return f"wp-{kind}:{slug}", f"wordpress-{kind}", None


def version_ranges(affected: Dict[str, Dict]) -> Tuple[List[str], List[str]]:
    """Convert Wordfence ranges to the shared notation. Returns (exact versions, ranges)."""
    exact, ranges = set(), set()
    for r in affected.values():
        lo, hi = r.get("from_version", "*"), r.get("to_version", "*")
        lo_inc, hi_inc = r.get("from_inclusive", True), r.get("to_inclusive", True)
        if lo == hi and lo != "*" and lo_inc and hi_inc:
            exact.add(lo)
            continue
        parts = []
        if lo != "*":
            parts.append((">=" if lo_inc else ">") + lo)
        if hi != "*":
            parts.append(("<=" if hi_inc else "<") + hi)
        ranges.add(" ".join(parts) or "*")
    return sorted(exact), sorted(ranges)


def group_by_vuln(feed: Dict[str, Dict]) -> Dict[str, List[Dict]]:
    groups: Dict[str, List[Dict]] = defaultdict(list)
    for rec in feed.values():
        vuln_id = rec.get("cve") or f"WORDFENCE-{rec['id']}"
        groups[vuln_id].append(rec)
    for recs in groups.values():
        recs.sort(key=lambda r: r["id"])
    return groups


def content_hash(recs: List[Dict]) -> str:
    return hashlib.sha256(json.dumps(recs, sort_keys=True).encode()).hexdigest()


def transform(vuln_id: str, recs: List[Dict]) -> Dict:
    primary = max(recs, key=lambda r: (r.get("cvss") or {}).get("score") or 0)
    cvss = primary.get("cvss") or {}
    cwe = primary.get("cwe") or {}
    cve = primary.get("cve")

    props = {
        "wordfenceIDs": [r["id"] for r in recs],
        "wfTitle": primary.get("title"),
        "wfTitles": [r.get("title") for r in recs],
        "wfDescription": primary.get("description"),
        "wfURLs": [RECORD_URL.format(id=r["id"]) for r in recs],
        "wfCvssScore": cvss.get("score"),
        "wfCvssVector": cvss.get("vector"),
        "wfCvssRating": cvss.get("rating"),
        "wfCweID": str(cwe["id"]) if cwe.get("id") is not None else None,
        "wfInformational": any(r.get("informational") for r in recs),
        "wfPublished": min((d for d in (_date(r.get("published")) for r in recs) if d), default=None),
        "wfUpdated": max((d for d in (_datetime(r.get("updated")) for r in recs) if d), default=None),
        "wfHash": content_hash(recs),
        "isWordPress": True,
    }
    if cve:
        props["cveID"] = cve

    affects: Dict[str, Dict] = {}
    for r in recs:
        for sw in r.get("software") or []:
            name, ptype, vendor = product_for(sw)
            exact, ranges = version_ranges(sw.get("affected_versions") or {})
            a = affects.setdefault(name, {
                "productName": name, "productType": ptype, "vendorName": vendor,
                "slug": sw.get("slug"),
                "productProps": {"wpType": sw.get("type"), "displayName": sw.get("name")},
                "affectedVersion": set(), "versionRanges": set(), "patchedVersions": set(),
                "edgeProps": {"patched": False, "remediation": []},
            })
            a["affectedVersion"].update(exact)
            a["versionRanges"].update(ranges)
            a["patchedVersions"].update(sw.get("patched_versions") or [])
            a["edgeProps"]["patched"] = a["edgeProps"]["patched"] or bool(sw.get("patched"))
            if sw.get("remediation") and sw["remediation"] not in a["edgeProps"]["remediation"]:
                a["edgeProps"]["remediation"].append(sw["remediation"])
    for a in affects.values():
        for k in ("affectedVersion", "versionRanges", "patchedVersions"):
            a[k] = sorted(a[k])

    cwes = sorted({str((r.get("cwe") or {}).get("id")) for r in recs if (r.get("cwe") or {}).get("id") is not None})
    domains = sorted({(urlparse(u).hostname or "").lower() for r in recs for u in r.get("references") or []} - {""})
    researchers = sorted({n.strip() for r in recs for n in r.get("researchers") or [] if n and n.strip()})

    return {
        "vulnID": vuln_id,
        "props": {k: v for k, v in props.items() if v is not None},
        "fallback": {k: v for k, v in {
            "description": primary.get("description"),
            "publishedDate": props.get("wfPublished"),
        }.items() if v is not None},
        "weaknesses": cwes,
        "domains": domains,
        "researchers": researchers,
        "affects": list(affects.values()),
    }


def licence_info(feed: Dict[str, Dict]) -> Dict:
    sample = next(iter(feed.values()), {}).get("copyrights", {}).get("defiant", {})
    mitre = next((r["copyrights"]["mitre"] for r in feed.values() if "mitre" in r.get("copyrights", {})), {})
    return {
        "cveCopyrightNotice": mitre.get("notice"),
        "cveLicense": mitre.get("license"),
        "displayName": "Wordfence Intelligence",
        "url": "https://www.wordfence.com/threat-intel/",
        "copyrightNotice": sample.get("notice"),
        "license": sample.get("license"),
        "licenseUrl": sample.get("license_url"),
        "attribution": "Link to the record (Vulnerability.wfURLs) and reproduce the notice and licence.",
    }
