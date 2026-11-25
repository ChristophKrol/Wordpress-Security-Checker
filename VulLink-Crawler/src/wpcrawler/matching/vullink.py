"""Match detected components against VulLink through its read-only REST API (no direct DB access).

Values found on a website are untrusted. They are validated against a strict pattern and then encoded
character by character as Cypher \\uXXXX escapes, so they can neither break out of the string literal
nor trip the API's keyword filter (plugin slugs like "call-now-button" contain words such as CALL).
"""
from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional, Tuple

import requests

from ..models import Component, ScanResult
from . import version as v

log = logging.getLogger("wpcrawler.matching")

DEFAULT_API_URL = "http://localhost:8001/api/v1"
SAFE_VALUE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,120}$")

# Detected server software -> (VulLink productName, allowed vendor names)
SERVER_PRODUCTS: Dict[str, List[Tuple[str, List[str]]]] = {
    "apache": [("http_server", ["apache"])],
    "nginx": [("nginx", ["f5", "nginx"])],
    "php": [("php", ["php"])],
    "openlitespeed": [("openlitespeed", ["litespeedtech"])],
    "mysql": [("mysql", ["oracle"])],
    "mariadb": [("mariadb", ["mariadb"])],
    # "LiteSpeed" header can be either edition.
    "litespeed": [("litespeed_web_server", ["litespeedtech", "litespeed_technologies"]),
                  ("openlitespeed", ["litespeedtech"])],
}


def cypher_str(value: str) -> str:
    if not SAFE_VALUE.match(value):
        raise ValueError(f"refusing unsafe value for query: {value!r}")
    return "'" + "".join(f"\\u{ord(ch):04x}" for ch in value) + "'"


def products_for(comp: Component) -> List[Tuple[str, Optional[List[str]]]]:
    if comp.type == "core":
        return [("wordpress", ["wordpress"])]
    if comp.type == "plugin":
        return [(f"wp-plugin:{comp.slug}", None)]
    if comp.type == "theme":
        return [(f"wp-theme:{comp.slug}", None)]
    return SERVER_PRODUCTS.get(comp.slug, [])


def build_query(product: str, vendors: Optional[List[str]]) -> str:
    vendor_filter = ""
    if vendors:
        vendor_filter = ("MATCH (p)-[:BELONGS_TO]->(vd:Vendor) WHERE vd.vendorName IN ["
                         + ", ".join(cypher_str(x) for x in vendors) + "] ")
    # Also follow SAME_AS so NVD's CPE version data for the same plugin is used.
    return (
        f"MATCH (p:Product {{productName: {cypher_str(product)}}}) {vendor_filter}"
        "OPTIONAL MATCH (alias:Product)-[:SAME_AS]->(p) "
        "WITH [p] + collect(DISTINCT alias) AS prods UNWIND prods AS prod "
        "MATCH (vuln:Vulnerability)-[r:AFFECTS]->(prod) "
        "RETURN vuln.vulnID AS id, vuln.cveID AS cve, coalesce(vuln.wfTitle, left(vuln.description, 200)) AS title, "
        "vuln.wfCvssScore AS wfCvss, vuln.v3baseScore AS nvdCvss, "
        "coalesce(vuln.wfCvssRating, vuln.v3baseSeverity) AS severity, vuln.cisaKEV AS kev, "
        "vuln.wfURLs AS links, r.versionRanges AS ranges, r.affectedVersion AS exact, "
        "r.patchedVersions AS patched, r.patched AS hasPatch, prod.productName AS product, "
        "r.vendorRanges AS vendorRanges, r.vendorVersions AS vendorVersions "
        "LIMIT 5000"
    )


class VulLinkClient:
    def __init__(self, api_url: str = DEFAULT_API_URL, timeout: float = 60):
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout

    def query(self, cypher: str) -> List[Dict]:
        resp = requests.get(f"{self.api_url}/cypher_query/", params={"query": cypher, "limit": 10000},
                            timeout=self.timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"VulLink API {resp.status_code}: {resp.text[:300]}")
        return resp.json()


def _scope_to_vendors(row: Dict, vendors: List[str]) -> bool:
    """Product names are shared across vendors (e.g. http_server). NVD tags each range as "vendor|range";
    remove ranges that only other vendors contributed, keep this vendor's and untagged ones (Wordfence).
    Drops the row when nothing is left that applies to this vendor."""
    tagged = [(t.split("|", 1)[0], t.split("|", 1)[1]) for t in (row.get("vendorRanges") or []) if "|" in t]
    tagged_v = [(t.split("|", 1)[0], t.split("|", 1)[1]) for t in (row.get("vendorVersions") or []) if "|" in t]
    if not tagged and not tagged_v:
        return True
    ours_r = {r for vd, r in tagged if vd in vendors}
    ours_v = {x for vd, x in tagged_v if vd in vendors}
    foreign_r = {r for vd, r in tagged if vd not in vendors} - ours_r
    foreign_v = {x for vd, x in tagged_v if vd not in vendors} - ours_v
    row["ranges"] = [r for r in (row.get("ranges") or []) if r not in foreign_r]
    row["exact"] = [x for x in (row.get("exact") or []) if x not in foreign_v]
    return bool(row["ranges"] or row["exact"] or ours_r or ours_v)


def match_component(client: VulLinkClient, comp: Component) -> List[Dict]:
    rows: List[Dict] = []
    for product, vendors in products_for(comp):
        try:
            for row in client.query(build_query(product, vendors)):
                if vendors and not _scope_to_vendors(row, vendors):
                    continue
                rows.append(row)
        except ValueError as exc:
            log.warning("skipping %s: %s", comp.key, exc)
    version = comp.version

    by_id: Dict[str, Dict] = {}
    for row in rows:
        verdict = v.is_affected(version, row.get("ranges"), row.get("exact"), row.get("patched")) if version else None
        entry = by_id.setdefault(row["id"], {
            "id": row["id"], "cve": row.get("cve"), "title": row.get("title"),
            "cvss": row.get("wfCvss") if row.get("wfCvss") is not None else row.get("nvdCvss"),
            "severity": row.get("severity"), "actively_exploited": bool(row.get("kev")),
            "fixed_in": sorted(set(row.get("patched") or [])), "links": row.get("links") or [],
            "affected_ranges": [], "status": None,
        })
        entry["affected_ranges"] = sorted(set(entry["affected_ranges"]) | set(row.get("ranges") or [])
                                          | {"=" + x for x in row.get("exact") or []})
        entry["fixed_in"] = sorted(set(entry["fixed_in"]) | set(row.get("patched") or []))
        if row.get("hasPatch") is False and not entry["fixed_in"]:
            entry["no_fix_available"] = True
        # Any source saying "affected" wins; "not affected" only if no source says otherwise.
        if verdict is True:
            entry["status"] = "affected"
        elif verdict is False and entry["status"] != "affected":
            entry["status"] = "not_affected"
        elif verdict is None and entry["status"] is None:
            entry["status"] = "unknown_version" if not version else "no_version_data"

    for e in by_id.values():
        e["title"] = " ".join((e["title"] or "").split())
        if version and e["status"] == "affected":
            newer = [f for f in e["fixed_in"] if v.compare(f, version) > 0]
            if not newer:
                # NVD lists no fixed version, but "<X" in a range that matches means X is the fix.
                newer = [b for r in e["affected_ranges"] if v.in_range(version, r)
                         for b in re.findall(r"(?:^|\s)<([^=\s]+)", r)]
            e["upgrade_to"] = min(newer, key=v._key) if newer else None

    results = sorted(by_id.values(), key=lambda e: (-(e["cvss"] or 0), e["id"]))
    return [e for e in results if e["status"] != "not_affected"]


def match(result: ScanResult, api_url: str = DEFAULT_API_URL) -> None:
    client = VulLinkClient(api_url)
    for comp in result.components.values():
        comp.vulnerabilities = match_component(client, comp)
