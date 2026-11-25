"""Command line interface.

    wpcrawler scan https://example.com                      # default (light) scan + VulLink matching
    wpcrawler scan https://example.com --json out.json
    wpcrawler scan https://example.com --aggressive --authorized --plugin-list slugs.txt
    wpcrawler export-slugs --top 500 -o slugs.txt           # plugin list for enumeration, from VulLink
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from . import report
from .matching import vullink
from .scanner import ScanOptions, scan

AUTH_TEXT = ("--aggressive probes many paths and counts as a security scan. Only use it on sites you own or "
             "have written permission to test, and confirm with --authorized.")


def cmd_scan(args: argparse.Namespace) -> int:
    if args.aggressive and not args.authorized:
        print(AUTH_TEXT, file=sys.stderr)
        return 2
    slugs = []
    if args.plugin_list:
        if not args.aggressive:
            print("--plugin-list requires --aggressive", file=sys.stderr)
            return 2
        slugs = [ln.strip() for ln in Path(args.plugin_list).read_text().splitlines()
                 if ln.strip() and not ln.startswith("#")]

    opts = ScanOptions(max_pages=args.max_pages, delay=args.delay, timeout=args.timeout,
                       verify_tls=not args.insecure, max_requests=args.max_requests,
                       aggressive=args.aggressive, plugin_slugs=slugs)
    if args.user_agent:
        opts.user_agent = args.user_agent
    result = scan(args.url, opts)

    matched = False
    if not args.no_match and result.components:
        try:
            vullink.match(result, args.api)
            matched = True
        except Exception as exc:  # API down etc.: still report the fingerprint
            result.errors.append(f"VulLink matching failed: {exc}")

    if args.json:
        Path(args.json).write_text(json.dumps(result.to_dict(), indent=2, default=str))
    if args.json != "-":
        print(report.render(result, matched))
        if args.json:
            print(f"\nJSON written to {args.json}")
    else:
        print(json.dumps(result.to_dict(), indent=2, default=str))
    return 0 if not result.errors or result.is_wordpress else 1


def cmd_export_slugs(args: argparse.Namespace) -> int:
    client = vullink.VulLinkClient(args.api)
    rows = client.query(
        "MATCH (vuln:Vulnerability)-[:AFFECTS]->(p:Product) WHERE p.productType = 'wordpress-plugin' "
        f"RETURN p.slug AS slug, count(vuln) AS vulns ORDER BY vulns DESC LIMIT {int(args.top)}")
    lines = [r["slug"] for r in rows if r.get("slug")]
    text = "# top vulnerable plugins from VulLink\n" + "\n".join(lines) + "\n"
    if args.output:
        Path(args.output).write_text(text)
        print(f"{len(lines)} slugs written to {args.output}")
    else:
        sys.stdout.write(text)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="wpcrawler", description="WordPress fingerprinting + VulLink matching")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="fingerprint a site and match it against VulLink")
    s.add_argument("url")
    s.add_argument("--json", metavar="FILE", help="write the full result as JSON ('-' = stdout only)")
    s.add_argument("--aggressive", action="store_true", help="probe paths: plugin enumeration, config checks")
    s.add_argument("--authorized", action="store_true", help="confirm you may run aggressive checks on this site")
    s.add_argument("--plugin-list", metavar="FILE", help="slugs to probe in aggressive mode (see export-slugs)")
    s.add_argument("--max-pages", type=int, default=5, help="pages to crawl for assets (default 5)")
    s.add_argument("--delay", type=float, default=1.0, help="seconds between requests (default 1.0)")
    s.add_argument("--timeout", type=float, default=15.0)
    s.add_argument("--max-requests", type=int, default=300, help="hard request budget (default 300)")
    s.add_argument("--user-agent")
    s.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    s.add_argument("--no-match", action="store_true", help="fingerprint only, skip VulLink lookup")
    s.add_argument("--api", default=vullink.DEFAULT_API_URL, help=f"VulLink API (default {vullink.DEFAULT_API_URL})")
    s.set_defaults(func=cmd_scan)

    e = sub.add_parser("export-slugs", help="export the most vulnerable plugin slugs from VulLink")
    e.add_argument("--top", type=int, default=500)
    e.add_argument("-o", "--output")
    e.add_argument("--api", default=vullink.DEFAULT_API_URL)
    e.set_defaults(func=cmd_export_slugs)

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
