"""CLI for the API-based connectors.

    python -m sources.run nvd              # incremental since last run (full load on first run)
    python -m sources.run nvd --full       # force a full reload
    python -m sources.run nvd --max-pages 1  # smoke test
    python -m sources.run wordfence        # sync the Wordfence Intelligence snapshot (only changed records)
    python -m sources.run all              # Wordfence first, then NVD (WordPress scope)
    python -m sources.run nvd --scope all  # load all of NVD instead of only WordPress-related CVEs
"""
from __future__ import annotations

import argparse
import gzip
import json
import logging
from datetime import datetime, timedelta, timezone

from . import graph, nvd, wordfence
from .common import env, load_state, neo4j_driver, save_state

log = logging.getLogger("sources.run")


BACKFILL_LIMIT = 500          # max single-CVE lookups per run
BACKFILL_RECHECK_DAYS = 7     # how long to wait before asking NVD again for a CVE it didn't have


def wordfence_cves(driver) -> set:
    with driver.session() as session:
        return {r["id"] for r in session.run(
            "MATCH (v:Vulnerability) WHERE 'wordfence' IN coalesce(v.sources, []) AND v.cveID IS NOT NULL "
            "RETURN v.cveID AS id")}


def run_nvd(driver, full: bool, max_pages: int | None, scope: str) -> None:
    state = load_state()
    nvd_state = state.get(nvd.SOURCE, {})
    started = datetime.now(timezone.utc)
    last = nvd_state.get("lastModified")
    client = nvd.make_client()

    signature = nvd.scope_signature(scope)
    if last and nvd_state.get("scope", "all") != signature:
        log.info("NVD: scope changed (%s -> %s), doing a full scan", nvd_state.get("scope", "all"), signature)
        full = True
    is_full = full or not last

    known = wordfence_cves(driver) if scope == "wordpress" else None
    if known is not None:
        log.info("NVD scope 'wordpress': %d CVEs known from Wordfence + WordPress CPEs/descriptions + stack %s",
                 len(known), sorted(f"{v}:{p}" for v, p in nvd.stack_products()))
        if not known:
            log.warning("No Wordfence data in the graph yet - run the wordfence source first for best coverage")

    if is_full:
        log.info("NVD: full scan")
        batches = [("full", {})]
    else:
        since = datetime.fromisoformat(last)
        log.info("NVD: incremental load of changes since %s", since.isoformat())
        batches = [
            (f"incr_{a:%Y%m%dT%H%M%S}", {"lastModStartDate": nvd._iso(a), "lastModEndDate": nvd._iso(b)})
            for a, b in nvd.windows(since, started)
        ]

    tag_prefix = started.strftime("%Y%m%dT%H%M%S")
    loaded = removed = skipped = 0
    seen_in_scope: set = set()
    for tag, params in batches:
        for page in nvd.fetch_pages(client, params, f"{tag_prefix}/{tag}", max_pages):
            records, rejected, n_skipped = nvd.split_page(page, known)
            seen_in_scope.update(r["vulnID"] for r in records)
            loaded += graph.load_records(driver, nvd.SOURCE, records)
            graph.remove_records(driver, nvd.SOURCE, rejected)
            removed += len(rejected)
            skipped += n_skipped
    log.info("NVD scan done: %d upserted, %d rejected/removed, %d skipped (out of scope)", loaded, removed, skipped)

    if max_pages:
        log.info("Partial run (--max-pages): not advancing the checkpoint, no cleanup/backfill")
        return

    missing_checked = nvd_state.get("missingChecked", {})
    if is_full:
        # A full scan saw every CVE: drop NVD data that is now out of scope.
        stale = sorted(set(graph.source_vuln_ids(driver, nvd.SOURCE)) - seen_in_scope)
        if stale:
            log.info("NVD: removing %d previously loaded CVEs that are out of scope", len(stale))
            graph.remove_records(driver, nvd.SOURCE, stale)
        # Wordfence CVEs the scan didn't find are not in NVD yet; remember when we last looked.
        if known is not None:
            missing_checked = {c: started.isoformat() for c in known - seen_in_scope}
    elif known is not None:
        # Wordfence may add CVEs that NVD published (and we skipped) long ago: fetch them directly.
        have_nvd = set(graph.source_vuln_ids(driver, nvd.SOURCE))
        cutoff = started - timedelta(days=BACKFILL_RECHECK_DAYS)
        todo = sorted(
            c for c in known - have_nvd
            if c not in missing_checked or datetime.fromisoformat(missing_checked[c]) < cutoff
        )[:BACKFILL_LIMIT]
        found = 0
        for cve_id in todo:
            for page in nvd.fetch_pages(client, {"cveId": cve_id}, f"{tag_prefix}/backfill/{cve_id}"):
                records, rejected, _ = nvd.split_page(page)
                found += graph.load_records(driver, nvd.SOURCE, records)
                graph.remove_records(driver, nvd.SOURCE, rejected)
                if records:
                    missing_checked.pop(cve_id, None)
                else:
                    missing_checked[cve_id] = started.isoformat()
        if todo:
            log.info("NVD backfill: looked up %d Wordfence CVEs, %d found in NVD", len(todo), found)
    missing_checked = {c: t for c, t in missing_checked.items() if known is None or c in known}

    state[nvd.SOURCE] = {
        "lastModified": started.isoformat(),
        "lastRunMode": "full" if is_full else "incremental",
        "scope": signature,
        "missingChecked": missing_checked,
    }
    save_state(state)


def run_wordfence(driver, full: bool, feed_file: str | None) -> None:
    started = datetime.now(timezone.utc)
    if feed_file:
        log.info("Wordfence: loading snapshot from %s", feed_file)
        opener = gzip.open if feed_file.endswith(".gz") else open
        with opener(feed_file, "rt", encoding="utf-8") as fh:
            feed = json.load(fh)
    else:
        feed = wordfence.fetch(wordfence.make_client(), started.strftime("%Y%m%dT%H%M%S"))

    if len(feed) < wordfence.MIN_EXPECTED_RECORDS:
        raise SystemExit(f"Wordfence feed has only {len(feed)} records - refusing to sync a possibly truncated feed")

    graph.upsert_data_source(driver, wordfence.SOURCE, {**wordfence.licence_info(feed), "lastSync": started.isoformat()})

    groups = wordfence.group_by_vuln(feed)
    existing = graph.source_vuln_ids(driver, wordfence.SOURCE, "wfHash")

    # Withdrawn records and WORDFENCE-<uuid> placeholders whose record now carries a CVE.
    gone = sorted(set(existing) - set(groups))
    if gone:
        graph.remove_records(driver, wordfence.SOURCE, gone)
        with driver.session() as session:  # strip Wordfence-specific properties from nodes other sources keep
            session.run(
                "UNWIND $ids AS id MATCH (v:Vulnerability {vulnID: id}) "
                "SET v = apoc.map.removeKeys(properties(v), "
                "[k IN keys(v) WHERE k STARTS WITH 'wf' OR k IN ['wordfenceIDs', 'isWordPress']])",
                ids=gone,
            ).consume()

    changed = [
        vid for vid, recs in groups.items()
        if full or existing.get(vid) != wordfence.content_hash(recs)
    ]
    log.info("Wordfence: %d vulnerabilities in feed, %d new/changed, %d withdrawn",
             len(groups), len(changed), len(gone))
    loaded = graph.load_records(driver, wordfence.SOURCE, (wordfence.transform(v, groups[v]) for v in changed))
    log.info("Wordfence done: %d upserted, %d removed", loaded, len(gone))

    state = load_state()
    state[wordfence.SOURCE] = {"lastSync": started.isoformat(), "records": len(feed), "vulnerabilities": len(groups)}
    save_state(state)


def main() -> None:
    parser = argparse.ArgumentParser(description="VulLink API source connectors")
    parser.add_argument("source", choices=["nvd", "wordfence", "all"])
    parser.add_argument("--full", action="store_true", help="ignore checkpoint/hashes and reload everything")
    parser.add_argument("--max-pages", type=int, default=None, help="NVD: stop after N pages (testing)")
    parser.add_argument("--feed-file", default=None, help="Wordfence: load a saved snapshot instead of downloading")
    parser.add_argument("--scope", choices=["wordpress", "all"], default=env("NVD_SCOPE", "wordpress"),
                        help="NVD: load only WordPress-related CVEs (default) or all of NVD")
    args = parser.parse_args()

    driver = neo4j_driver()
    try:
        graph.ensure_schema(driver)
        # Wordfence first: its CVE list defines the NVD WordPress scope.
        if args.source in ("wordfence", "all"):
            try:
                run_wordfence(driver, args.full, args.feed_file)
            except Exception as exc:  # e.g. rate limit; NVD can still run on the Wordfence data already loaded
                if args.source != "all":
                    raise
                log.error("Wordfence sync failed (%s) - continuing with NVD", exc)
        if args.source in ("nvd", "all"):
            run_nvd(driver, args.full, args.max_pages, args.scope)
        log.info("Linked %d NVD products to WordPress slugs (SAME_AS)", graph.link_wordpress_products(driver))
    finally:
        driver.close()


if __name__ == "__main__":
    main()
