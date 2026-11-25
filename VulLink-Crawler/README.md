# VulLink-Crawler

Standalone component that fingerprints a WordPress site from the outside (core, plugins, themes,
server software), and matches what it finds against the VulLink vulnerability graph.

It is independent of the rest of the stack: it has its own package and dependencies, and talks to VulLink only
through the public read-only REST API (`/api/v1/cypher_query`), never to Neo4j directly.

> **Only scan sites you own or have written permission to test.** The default mode behaves like a normal
> visitor. `--aggressive` probes many paths and counts as a security scan (in Germany see §202c StGB). It
> refuses to run without `--authorized`.

## Install

```bash
cd VulLink-Crawler
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Usage

```bash
# default scan + vulnerability matching (VulLink API at http://localhost:8001/api/v1)
.venv/bin/wpcrawler scan https://example.com

# full result as JSON (components, evidence, vulnerabilities, findings)
.venv/bin/wpcrawler scan https://example.com --json result.json

# aggressive: plugin enumeration + configuration checks (own sites only)
.venv/bin/wpcrawler export-slugs --top 500 -o slugs.txt
.venv/bin/wpcrawler scan https://example.com --aggressive --authorized --plugin-list slugs.txt

# fingerprint only, no VulLink needed
.venv/bin/wpcrawler scan https://example.com --no-match

# match a server-side inventory from VulLink-Collector (wp eval-file collect.php > inventory.json)
.venv/bin/wpcrawler match inventory.json
```

Politeness defaults: 1 s between requests (`--delay`), max 300 requests per scan (`--max-requests`),
5 crawled pages (`--max-pages`), only the target host is ever requested.

## What it collects

| Mode | Requests | Detects |
|---|---|---|
| default | start page + up to 4 internal pages, `/feed/`, REST index (`/wp-json/`), `readme.txt` / `style.css` of components already seen | core version (generator meta, feed, `wp-includes` asset versions), plugins and themes (asset paths, generator tags, HTML comments, REST namespaces), plugin/theme versions, parent themes, server software from headers |
| `--aggressive` | + `readme.txt` probe per slug in `--plugin-list`, `readme.html`, `xmlrpc.php`, user enumeration, `uploads/` listing, `debug.log`, `wp-config.php` backups | admin-only plugins invisible on the front end, configuration findings |

Every detected version carries its evidence and a confidence (`high` = readme/style.css/generator,
`medium` = asset `?ver=`, `low` = indirect). The strongest evidence wins; disagreeing versions are reported as
conflicts. Contents of sensitive files (`debug.log`, `wp-config` backups) are never stored, only the fact
that they are reachable.

## Matching

Components map to VulLink products: plugins to `wp-plugin:<slug>`, themes to `wp-theme:<slug>`, core to
`wordpress`, and server software to NVD CPE products filtered by vendor (`apache` to `http_server`, ...).
NVD data linked via `SAME_AS` is used as well. Each vulnerability gets a status:

- `affected`: the detected version is inside an affected range, reported with `upgrade_to` (the
  smallest fixed version above the installed one)
- `unknown_version`: the component was found but its version wasn't, so all its known vulnerabilities are listed
- `no_version_data`: VulLink has no version information for that vulnerability
- versions that are not affected are dropped

Caveats:
- **Distribution packages**: Debian/Ubuntu/RHEL backport security fixes without changing the upstream
  version (`Apache/2.4.57 (Ubuntu)`). Version-based server matches can be false positives; the report adds a
  note in that case.
- **Hidden versions**: hardened sites, caching/minification plugins and CDNs remove the signals this relies on.
- Values read from websites are untrusted. They are validated and encoded as Cypher `\uXXXX` escapes before
  they go into a query (see `matching/vullink.py`).

## Layout

```
src/wpcrawler/
  cli.py              command line (scan, match, export-slugs)
  inventory.py        loads VulLink-Collector inventories as scan results
  scanner.py          orchestration of one scan
  http.py             polite single-host fetcher (delay, budget, size cap)
  models.py           Component / Evidence / Finding / ScanResult
  report.py           console report
  fingerprint/
    parsers.py        pure parsing of HTML, headers, readme.txt, style.css, feeds
    passive.py        default-mode detectors
    active.py         aggressive detectors (enumeration, config checks)
  matching/
    version.py        tolerant version comparison for VulLink's range notation
    vullink.py        VulLink API client and matching
tests/                unit tests + end-to-end tests against a local fake WordPress site
```

Run the tests with `.venv/bin/python -m pytest`.
