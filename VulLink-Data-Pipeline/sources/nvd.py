"""NVD CVE API 2.0 connector (https://nvd.nist.gov/developers/vulnerabilities).

Full load pages through every CVE; incremental load asks for CVEs modified since the last
successful run (NVD caps lastMod windows at 120 days, so long gaps are split).
"""
from __future__ import annotations

import logging
import re
from datetime import date, datetime, timedelta, timezone
from typing import Dict, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlparse

from .common import HttpClient, env, save_raw

log = logging.getLogger("sources.nvd")

SOURCE = "nvd"
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
MAX_WINDOW = timedelta(days=120)
PART_TYPES = {"a": "application", "o": "operating_system", "h": "hardware"}


def make_client() -> HttpClient:
    key = env("NVD_API_KEY")
    if not key:
        log.warning("NVD_API_KEY not set: running at the public rate limit (much slower)")
    # NVD: 50 requests / 30 s with a key, 5 / 30 s without.
    return HttpClient({"apiKey": key} if key else {}, min_interval=0.8 if key else 6.5)


# --------------------------------------------------------------------------- extract

def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def fetch_pages(client: HttpClient, params: Dict[str, str], tag: str,
                max_pages: Optional[int] = None) -> Iterator[Dict]:
    start, page = 0, 0
    while True:
        data = client.get_json(API_URL, {**params, "startIndex": start, "resultsPerPage": PAGE_SIZE})
        save_raw(SOURCE, f"{tag}/page_{page:05d}", data)
        total = data.get("totalResults", 0)
        got = len(data.get("vulnerabilities", []))
        log.info("NVD %s: page %d, %d-%d of %d", tag, page, start, start + got, total)
        yield data
        start += got
        page += 1
        if got == 0 or start >= total or (max_pages and page >= max_pages):
            return


def windows(since: datetime, until: datetime) -> List[Tuple[datetime, datetime]]:
    out, cur = [], since
    while cur < until:
        nxt = min(cur + MAX_WINDOW, until)
        out.append((cur, nxt))
        cur = nxt
    return out


# --------------------------------------------------------------------------- transform

def _split_cpe(cpe: str) -> List[str]:
    return [p.replace("\\", "") for p in re.split(r"(?<!\\):", cpe)]


def _version_range(m: Dict) -> Optional[str]:
    parts = []
    if m.get("versionStartIncluding"):
        parts.append(">=" + m["versionStartIncluding"])
    if m.get("versionStartExcluding"):
        parts.append(">" + m["versionStartExcluding"])
    if m.get("versionEndIncluding"):
        parts.append("<=" + m["versionEndIncluding"])
    if m.get("versionEndExcluding"):
        parts.append("<" + m["versionEndExcluding"])
    return " ".join(parts) or None


def _affects(cve: Dict, stack: Set[Tuple[str, str]]) -> List[Dict]:
    products: Dict[str, Dict] = {}
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                parts = _split_cpe(m.get("criteria", ""))
                if len(parts) < 13:
                    continue
                part, vendor, product, version, target_sw = parts[2], parts[3], parts[4], parts[5], parts[10]
                entry = products.setdefault(product, {
                    "productName": product,
                    "productType": PART_TYPES.get(part, part),
                    "vendorName": vendor,
                    "slug": None,
                    "targetSoftware": set(),
                    "affectedVersion": set(),
                    "versionRanges": set(),
                    "patchedVersions": [],
                    "productProps": {"hostingStack": True} if (vendor, product) in stack else {},
                    # productName is not vendor-scoped (original VulKG schema), so several vendors' products
                    # can share a node; keep each range/version tagged with its CPE vendor as "vendor|value".
                    "vendorRanges": set(),
                    "vendorVersions": set(),
                })
                if target_sw not in ("*", "-"):
                    entry["targetSoftware"].add(target_sw)
                rng = _version_range(m)
                if rng:
                    entry["versionRanges"].add(rng)
                    entry["vendorRanges"].add(f"{vendor}|{rng}")
                elif version not in ("*", "-"):
                    entry["affectedVersion"].add(version)
                    entry["vendorVersions"].add(f"{vendor}|{version}")
                elif version == "*":
                    entry["versionRanges"].add("*")
                    entry["vendorRanges"].add(f"{vendor}|*")
    out = []
    for e in products.values():
        e["affectedVersion"] = sorted(e["affectedVersion"])
        e["versionRanges"] = sorted(e["versionRanges"])
        e["targetSoftware"] = sorted(e["targetSoftware"])
        e["vendorRanges"] = sorted(e["vendorRanges"])
        e["vendorVersions"] = sorted(e["vendorVersions"])
        out.append(e)
    return out


def _pick_metric(metrics: List[Dict]) -> Optional[Dict]:
    if not metrics:
        return None
    return next((m for m in metrics if m.get("type") == "Primary"), metrics[0])


def _date(value: Optional[str]) -> Optional[date]:
    return datetime.fromisoformat(value[:10]).date() if value else None


def _datetime(value: Optional[str]) -> Optional[datetime]:
    return datetime.fromisoformat(value[:19]) if value else None


def transform(cve: Dict, stack: Optional[Set[Tuple[str, str]]] = None) -> Dict:
    cve_id = cve["id"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
    refs = cve.get("references", [])
    props = {
        "cveID": cve_id,
        "description": desc,
        "publishedDate": _date(cve.get("published")),
        "lastModifiedDate": _datetime(cve.get("lastModified")),
        "vulnStatus": cve.get("vulnStatus"),
        "numOfReference": len(refs),
        "cisaKEV": bool(cve.get("cisaExploitAdd")),
        "cisaExploitAdd": _date(cve.get("cisaExploitAdd")),
    }

    metrics = cve.get("metrics", {})
    v2 = _pick_metric(metrics.get("cvssMetricV2", []))
    if v2:
        d = v2["cvssData"]
        props.update({
            "v2version": int(float(d.get("version", "2.0"))),
            "v2baseScore": d.get("baseScore"),
            "v2accessVector": d.get("accessVector"),
            "v2accessComplexity": d.get("accessComplexity"),
            "v2authentication": d.get("authentication"),
            "v2confidentialityImpact": d.get("confidentialityImpact"),
            "v2integrityImpact": d.get("integrityImpact"),
            "v2availabilityImpact": d.get("availabilityImpact"),
            "v2vectorString": d.get("vectorString"),
            "v2impactScore": v2.get("impactScore"),
            "v2exploitabilityScore": v2.get("exploitabilityScore"),
            "v2userInteractionRequired": v2.get("userInteractionRequired"),
            "v2severity": v2.get("baseSeverity"),
            "v2obtainUserPrivilege": v2.get("obtainUserPrivilege"),
            "v2obtainAllPrivilege": v2.get("obtainAllPrivilege"),
            "v2acInsufInfo": v2.get("acInsufInfo"),
            "v2obtainOtherPrivilege": v2.get("obtainOtherPrivilege"),
        })
    v3 = _pick_metric(metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", []))
    if v3:
        d = v3["cvssData"]
        props.update({
            "v3version": float(d.get("version", "3.1")),
            "v3baseScore": d.get("baseScore"),
            "v3attackVector": d.get("attackVector"),
            "v3attackComplexity": d.get("attackComplexity"),
            "v3privilegesRequired": d.get("privilegesRequired"),
            "v3userInteraction": d.get("userInteraction"),
            "v3scope": d.get("scope"),
            "v3confidentialityImpact": d.get("confidentialityImpact"),
            "v3integrityImpact": d.get("integrityImpact"),
            "v3availabilityImpact": d.get("availabilityImpact"),
            "v3vectorString": d.get("vectorString"),
            "v3impactScore": v3.get("impactScore"),
            "v3exploitabilityScore": v3.get("exploitabilityScore"),
            "v3baseSeverity": d.get("baseSeverity"),
        })
    v4 = _pick_metric(metrics.get("cvssMetricV40", []))
    if v4:
        d = v4["cvssData"]
        props.update({
            "v4baseScore": d.get("baseScore"),
            "v4baseSeverity": d.get("baseSeverity"),
            "v4vectorString": d.get("vectorString"),
        })

    weaknesses = sorted({
        d["value"][4:]
        for w in cve.get("weaknesses", [])
        for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    })
    domains = sorted({
        (urlparse(r["url"]).hostname or "").lower()
        for r in refs if r.get("url")
    } - {""})

    affects = _affects(cve, stack or set())
    return {
        "vulnID": cve_id,
        "props": {k: v for k, v in props.items() if v is not None},
        "weaknesses": weaknesses,
        "domains": domains,
        "affects": affects,
    }


# Server software WordPress sites run on, as CPE "vendor:product" pairs. Override with NVD_STACK_PRODUCTS
# in .env (comma-separated; empty string disables). nginx moved from vendor "nginx" to "f5" in newer CPEs.
DEFAULT_STACK_PRODUCTS = "php:php,oracle:mysql,mariadb:mariadb,apache:http_server,f5:nginx,nginx:nginx,litespeedtech:openlitespeed,litespeedtech:litespeed_web_server,litespeed_technologies:litespeed_web_server"


def stack_products() -> Set[Tuple[str, str]]:
    raw = env("NVD_STACK_PRODUCTS", DEFAULT_STACK_PRODUCTS) or ""
    return {tuple(x.strip().lower().split(":", 1)) for x in raw.split(",") if ":" in x}


def scope_signature(scope: str) -> str:
    """Identifies the active filter; when it changes, a full rescan is needed."""
    if scope != "wordpress":
        return scope
    return "wordpress+" + ",".join(sorted(f"{v}:{p}" for v, p in stack_products()))


def relevance(cve: Dict, known_cves: Set[str], stack: Set[Tuple[str, str]]) -> List[str]:
    """Why a CVE is in the WordPress scope (empty list = out of scope)."""
    reasons = set()
    if cve["id"] in known_cves:
        reasons.add("wordfence")
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = _split_cpe(m.get("criteria", ""))
                if len(parts) < 11:
                    continue
                if parts[10] == "wordpress" or parts[3] == "wordpress":
                    reasons.add("wordpress-cpe")
                if m.get("vulnerable") and (parts[3], parts[4]) in stack:
                    reasons.add(f"stack:{parts[4]}")
    if any("wordpress" in (d.get("value") or "").lower() for d in cve.get("descriptions", [])):
        reasons.add("wordpress-description")
    return sorted(reasons)


def split_page(page: Dict, known_cves: Optional[Set[str]] = None) -> Tuple[List[Dict], List[str], int]:
    """Returns (records to upsert, rejected CVE ids to remove, number skipped as out of scope).
    known_cves=None means no scope filter (load everything)."""
    stack = stack_products()
    records, rejected, skipped = [], [], 0
    for item in page.get("vulnerabilities", []):
        cve = item["cve"]
        if cve.get("vulnStatus") == "Rejected":
            rejected.append(cve["id"])
            continue
        if known_cves is None:
            records.append(transform(cve, stack))
            continue
        reasons = relevance(cve, known_cves, stack)
        if reasons:
            rec = transform(cve, stack)
            rec["props"]["wpRelevance"] = reasons
            records.append(rec)
        else:
            skipped += 1
    return records, rejected, skipped
