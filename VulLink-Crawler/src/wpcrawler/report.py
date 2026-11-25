"""Human-readable console report (the JSON output is ScanResult.to_dict())."""
from __future__ import annotations

from typing import List

from .matching.version import _key as version_key
from .models import ScanResult

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _status_counts(vulns: List[dict]) -> dict:
    counts: dict = {}
    for x in vulns:
        counts[x["status"]] = counts.get(x["status"], 0) + 1
    return counts


def render(result: ScanResult, matched: bool, max_listed: int = 10) -> str:
    out = [f"Target:      {result.final_url or result.target}",
           f"Scanned:     {result.scanned_at}  (mode: {result.mode}, {result.requests_made} requests)",
           f"WordPress:   {'yes' if result.is_wordpress else 'not detected'}", ""]

    data = result.to_dict()
    out.append("Detected components")
    if not data["components"]:
        out.append("  (none)")
    for c in data["components"]:
        ver = c["version"] or "version unknown"
        conf = f" [{c['versionConfidence']}]" if c["versionConfidence"] else ""
        conflict = f"  (also seen: {', '.join(c['versionConflicts'])})" if c["versionConflicts"] else ""
        name = f" - {c['name']}" if c["name"] and c["name"].lower() != c["slug"] else ""
        d = c.get("details") or {}
        status = f" ({d['status']})" if d.get("status") and d["status"] != "active" else ""
        update = f"  -> update available: {d['updateVersion']}" if d.get("updateVersion") else ""
        out.append(f"  {c['type']:<7} {c['slug']}{name}: {ver}{conf}{status}{conflict}{update}")
        for note in c.get("notes", []):
            out.append(f"          note: {note}")
    out.append("")

    if matched:
        out.append("Vulnerabilities (VulLink)")
        any_listed = False
        for c in data["components"]:
            vulns = c["vulnerabilities"]
            if not vulns:
                continue
            counts = _status_counts(vulns)
            affected = [x for x in vulns if x["status"] == "affected"]
            label = f"{c['type']} {c['slug']}" + (f" {c['version']}" if c["version"] else "")
            if affected:
                any_listed = True
                out.append(f"  {label}: {len(affected)} affecting this version")
                for x in affected[:max_listed]:
                    flags = []
                    if x.get("actively_exploited"):
                        flags.append("ACTIVELY EXPLOITED")
                    if x.get("no_fix_available"):
                        flags.append("no fix")
                    if x.get("upgrade_to"):
                        fix = f"upgrade to {x['upgrade_to']}"
                    elif x["fixed_in"]:
                        fix = "no fix newer than this version listed"
                    else:
                        fix = ""
                    extra = "; ".join(filter(None, [fix] + flags))
                    out.append(f"    - {x['id']} (CVSS {x['cvss'] if x['cvss'] is not None else '?'}) "
                               f"{(x['title'] or '')[:90]}" + (f"  [{extra}]" if extra else ""))
                if len(affected) > max_listed:
                    out.append(f"    ... {len(affected) - max_listed} more (see JSON output)")
                targets = [x["upgrade_to"] for x in affected if x.get("upgrade_to")]
                if targets:
                    best = max(targets, key=version_key)
                    unfixed = sum(1 for x in affected if not x.get("upgrade_to"))
                    out.append(f"    => updating to {best} fixes {len(targets)} of {len(affected)}"
                               + (f"; {unfixed} have no newer fix listed" if unfixed else ""))
            if counts.get("unknown_version"):
                any_listed = True
                out.append(f"  {label}: {counts['unknown_version']} known vulnerabilities - version unknown, "
                           "cannot tell which apply")
            if counts.get("no_version_data"):
                out.append(f"    ({counts['no_version_data']} more without version data in VulLink)")
        if not any_listed:
            out.append("  none found for the detected versions")
        out.append("")

    out.append("Configuration findings")
    if not result.findings:
        out.append("  none" + ("" if result.mode in ("aggressive", "server-inventory") else " (most checks need --aggressive)"))
    for f in sorted(result.findings, key=lambda f: SEV_ORDER.get(f.severity, 9)):
        out.append(f"  [{f.severity.upper()}] {f.title} - {f.url}")
        if f.detail:
            out.append(f"         {f.detail}")

    extra = result.extra or {}
    if extra:
        integrity = extra.get("integrity", {})
        out += ["", "Integrity (checksums against wordpress.org)"]
        if integrity.get("skipped"):
            out.append("  skipped")
        else:
            core = integrity.get("core", {})
            plugins = integrity.get("plugins", {})
            out.append(f"  core:    {'OK' if core.get('ok') else 'MODIFIED - see findings'}"
                       + (f" ({len(core.get('messages', []))} message(s))" if core.get("messages") else ""))
            out.append(f"  plugins: {'OK' if plugins.get('ok') else 'see findings'}"
                       " (only plugins from wordpress.org can be verified)")
            out.append(f"  PHP files in uploads: {len(integrity.get('phpInUploads', []))}")
        libs = extra.get("libraries", [])
        if libs:
            owners = sorted({lib["in"] for lib in libs})
            out += ["", f"Bundled libraries: {len(libs)} Composer packages in {len(owners)} plugin(s)/theme(s)",
                    "  not checked: VulLink has no source for PHP library advisories yet (see JSON 'extra.libraries')"]
        pkgs = extra.get("packages", [])
        if pkgs:
            out += ["", "OS packages (versions incl. distro patch level):"]
            out += [f"  {p['name']} {p['version']}" for p in pkgs[:15]]

    if result.rest_namespaces:
        out += ["", "REST API namespaces: " + ", ".join(result.rest_namespaces)]
    if result.errors:
        out += ["", "Notes/errors:"] + [f"  - {e}" for e in result.errors[:20]]
    return "\n".join(out)
