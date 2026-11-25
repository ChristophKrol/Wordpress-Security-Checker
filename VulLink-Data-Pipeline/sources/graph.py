"""Source-agnostic loader: every connector transforms its data into VulnRecord dicts and hands them here.

Graph model (extends the original VulKG schema, all names kept compatible):
  (:Vulnerability {vulnID, cveID?, ...})       vulnID = CVE id, or "<SOURCE>-<id>" when no CVE exists yet
  (:Vulnerability)-[:EXAMPLE_OF]->(:Weakness {cweID})          cweID is the bare number, e.g. "79"
  (:Vulnerability)-[:REFERS_TO]->(:Domain {domainName})
  (:Vulnerability)-[:AFFECTS {affectedVersion, versionRanges, patchedVersions, ...}]->(:Product {productName})
        NVD edges also carry vendorRanges / vendorVersions ("vendor|<2.4.58"): productName is not
        vendor-scoped, so use these when several vendors share a product name (e.g. http_server)
  (:Product)-[:BELONGS_TO]->(:Vendor {vendorName})
  (:Researcher {researcherName})-[:DISCOVERED]->(:Vulnerability)          new
  (:DataSource {name, license, ...})                                       new: provenance/licence per source
  (:Product)-[:SAME_AS {evidence}]->(:Product {productType: "wordpress-plugin"|"wordpress-theme"})
        new: NVD CPE product <-> WordPress slug, inferred from shared CVEs (evidence = number of shared CVEs)

Every node and relationship written here carries a `sources` list (e.g. ["nvd", "wordfence"]).
Reloading a vulnerability from a source first detaches that source's previous relationships,
so updates (changed CPEs, new references, ...) replace stale data instead of piling up.

VulnRecord = {
  "vulnID": str,
  "props": {...},                 # Vulnerability properties, always written (use source-prefixed names
                                  #   for anything another source also provides)
  "fallback": {...},              # shared properties (description, publishedDate) only set if still missing
  "weaknesses": [cweID, ...],
  "domains": [domainName, ...],
  "researchers": [name, ...],
  "affects": [{"productName", "productType", "vendorName"?, "slug"?, "targetSoftware"?: [...],
               "productProps"?: {...},  "edgeProps"?: {...},
               "affectedVersion": [...], "versionRanges": [...], "patchedVersions": [...]}],
}
Version ranges use one notation for all sources: ">=1.0 <2.3", "<=4.1", "*" (all versions).
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Dict, Iterable, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database_schema import CONSTRAINTS, INDEXES  # noqa: E402

log = logging.getLogger("sources.graph")

EXTRA_SCHEMA = [
    "CREATE CONSTRAINT UniqueVulnID IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.vulnID IS UNIQUE",
    "CREATE CONSTRAINT UniqueResearcherName IF NOT EXISTS FOR (r:Researcher) REQUIRE r.researcherName IS UNIQUE",
    "CREATE CONSTRAINT UniqueDataSourceName IF NOT EXISTS FOR (s:DataSource) REQUIRE s.name IS UNIQUE",
    "CREATE INDEX ProductSlug IF NOT EXISTS FOR (p:Product) ON (p.slug)",
    "CREATE INDEX ProductType IF NOT EXISTS FOR (p:Product) ON (p.productType)",
    "CREATE INDEX VulnerabilityLastModified IF NOT EXISTS FOR (v:Vulnerability) ON (v.lastModifiedDate)",
]

_ADD_SOURCE = "apoc.coll.toSet(coalesce({var}.sources, []) + $source)"


def ensure_schema(driver) -> None:
    with driver.session() as session:
        for stmt in list(CONSTRAINTS.values()) + list(INDEXES.values()) + EXTRA_SCHEMA:
            session.run(stmt.strip().rstrip(";")).consume()
        # Nodes created by the original pipelines only have cveID: give them the new key.
        session.run(
            "MATCH (v:Vulnerability) WHERE v.vulnID IS NULL AND v.cveID IS NOT NULL SET v.vulnID = v.cveID"
        ).consume()


def upsert_data_source(driver, name: str, props: Dict) -> None:
    with driver.session() as session:
        session.run("MERGE (s:DataSource {name: $name}) SET s += $props", name=name, props=props).consume()


def _upsert_batch(tx, source: str, rows: List[Dict]) -> None:
    ids = [r["vulnID"] for r in rows]

    tx.run(
        f"""
        UNWIND $rows AS row
        MERGE (v:Vulnerability {{vulnID: row.vulnID}})
        SET v += row.props, v.sources = {_ADD_SOURCE.format(var='v')}
        SET v += apoc.map.removeKeys(row.fallback, keys(v))
        """,
        rows=[{"vulnID": r["vulnID"], "props": r["props"], "fallback": r.get("fallback", {})} for r in rows],
        source=source,
    ).consume()

    # Detach this source's previous relationships for these vulnerabilities.
    tx.run(
        """
        UNWIND $ids AS id
        MATCH (:Vulnerability {vulnID: id})-[r:AFFECTS|EXAMPLE_OF|REFERS_TO|DISCOVERED]-()
        WHERE $source IN coalesce(r.sources, [])
        WITH DISTINCT r, [s IN r.sources WHERE s <> $source] AS rest
        FOREACH (_ IN CASE WHEN size(rest) = 0 THEN [1] ELSE [] END | DELETE r)
        FOREACH (_ IN CASE WHEN size(rest) > 0 THEN [1] ELSE [] END | SET r.sources = rest)
        """,
        ids=ids, source=source,
    ).consume()

    tx.run(
        f"""
        UNWIND $rows AS row
        MATCH (v:Vulnerability {{vulnID: row.vulnID}})
        UNWIND row.weaknesses AS cweID
        MERGE (w:Weakness {{cweID: cweID}})
        MERGE (v)-[r:EXAMPLE_OF]->(w)
        SET r.sources = {_ADD_SOURCE.format(var='r')}
        """,
        rows=[{"vulnID": r["vulnID"], "weaknesses": r.get("weaknesses", [])} for r in rows], source=source,
    ).consume()

    tx.run(
        f"""
        UNWIND $rows AS row
        MATCH (v:Vulnerability {{vulnID: row.vulnID}})
        UNWIND row.domains AS domainName
        MERGE (d:Domain {{domainName: domainName}})
        MERGE (v)-[r:REFERS_TO]->(d)
        SET r.sources = {_ADD_SOURCE.format(var='r')}
        """,
        rows=[{"vulnID": r["vulnID"], "domains": r.get("domains", [])} for r in rows], source=source,
    ).consume()

    tx.run(
        f"""
        UNWIND $rows AS row
        MATCH (v:Vulnerability {{vulnID: row.vulnID}})
        UNWIND row.researchers AS name
        MERGE (res:Researcher {{researcherName: name}})
        MERGE (res)-[r:DISCOVERED]->(v)
        SET r.sources = {_ADD_SOURCE.format(var='r')}
        """,
        rows=[{"vulnID": r["vulnID"], "researchers": r.get("researchers", [])} for r in rows], source=source,
    ).consume()

    tx.run(
        f"""
        UNWIND $rows AS row
        MATCH (v:Vulnerability {{vulnID: row.vulnID}})
        UNWIND row.affects AS a
        MERGE (p:Product {{productName: a.productName}})
          ON CREATE SET p.productType = a.productType
        SET p.sources = {_ADD_SOURCE.format(var='p')},
            p.slug = coalesce(a.slug, p.slug),
            p.targetSoftware = apoc.coll.toSet(coalesce(p.targetSoftware, []) + coalesce(a.targetSoftware, []))
        SET p += coalesce(a.productProps, {{}})
        FOREACH (_ IN CASE WHEN a.vendorName IS NULL THEN [] ELSE [1] END |
            MERGE (vd:Vendor {{vendorName: a.vendorName}})
            MERGE (p)-[:BELONGS_TO]->(vd)
        )
        MERGE (v)-[r:AFFECTS]->(p)
        SET r.sources = {_ADD_SOURCE.format(var='r')},
            r.affectedVersion = apoc.coll.toSet(coalesce(r.affectedVersion, []) + a.affectedVersion),
            r.versionRanges = apoc.coll.toSet(coalesce(r.versionRanges, []) + a.versionRanges),
            r.patchedVersions = apoc.coll.toSet(coalesce(r.patchedVersions, []) + a.patchedVersions),
            r.vendorRanges = apoc.coll.toSet(coalesce(r.vendorRanges, []) + coalesce(a.vendorRanges, [])),
            r.vendorVersions = apoc.coll.toSet(coalesce(r.vendorVersions, []) + coalesce(a.vendorVersions, []))
        SET r += coalesce(a.edgeProps, {{}}),
            r.numOfVersion = size(r.affectedVersion)
        """,
        rows=[{"vulnID": r["vulnID"], "affects": r.get("affects", [])} for r in rows], source=source,
    ).consume()


def load_records(driver, source: str, records: Iterable[Dict], batch_size: int = 500) -> int:
    total = 0
    batch: List[Dict] = []
    with driver.session() as session:
        for rec in records:
            batch.append(rec)
            if len(batch) >= batch_size:
                session.execute_write(_upsert_batch, source, batch)
                total += len(batch)
                batch = []
        if batch:
            session.execute_write(_upsert_batch, source, batch)
            total += len(batch)
    return total


def source_vuln_ids(driver, source: str, prop: str = None) -> Dict[str, object]:
    """vulnID -> value of `prop` (or None) for every vulnerability the source currently backs."""
    with driver.session() as session:
        result = session.run(
            "MATCH (v:Vulnerability) WHERE $source IN coalesce(v.sources, []) "
            "RETURN v.vulnID AS id, CASE WHEN $prop IS NULL THEN null ELSE v[$prop] END AS val",
            source=source, prop=prop,
        )
        return {rec["id"]: rec["val"] for rec in result}


def remove_records(driver, source: str, vuln_ids: List[str], batch_size: int = 1000) -> None:
    """A source withdrew/rejected these entries: drop its claim, delete nodes no other source backs."""
    for i in range(0, len(vuln_ids), batch_size):
        with driver.session() as session:
            session.run(
                """
                UNWIND $ids AS id
                MATCH (v:Vulnerability {vulnID: id})
                OPTIONAL MATCH (v)-[r:AFFECTS|EXAMPLE_OF|REFERS_TO|DISCOVERED]-()
                WHERE $source IN coalesce(r.sources, [])
                WITH v, r, [s IN coalesce(r.sources, []) WHERE s <> $source] AS rest
                FOREACH (_ IN CASE WHEN r IS NOT NULL AND size(rest) = 0 THEN [1] ELSE [] END | DELETE r)
                FOREACH (_ IN CASE WHEN r IS NOT NULL AND size(rest) > 0 THEN [1] ELSE [] END | SET r.sources = rest)
                WITH DISTINCT v
                SET v.sources = [s IN coalesce(v.sources, []) WHERE s <> $source]
                WITH v WHERE size(v.sources) = 0
                DETACH DELETE v
                """,
                ids=vuln_ids[i:i + batch_size], source=source,
            ).consume()


def link_wordpress_products(driver) -> int:
    """Link NVD CPE products (target_sw=wordpress) to Wordfence slug products when a CVE affects exactly
    one of each - that CVE is evidence both nodes describe the same plugin/theme."""
    with driver.session() as session:
        session.run("MATCH ()-[r:SAME_AS]->() DELETE r").consume()
        rec = session.run(
            """
            MATCH (v:Vulnerability)-[:AFFECTS]->(wp:Product)
            WHERE wp.productType IN ['wordpress-plugin', 'wordpress-theme']
            WITH v, collect(wp) AS wps WHERE size(wps) = 1
            MATCH (v)-[:AFFECTS]->(np:Product)
            WHERE 'wordpress' IN coalesce(np.targetSoftware, [])
            WITH v, wps[0] AS wp, collect(np) AS nps WHERE size(nps) = 1
            WITH wp, nps[0] AS np, count(v) AS evidence
            MERGE (np)-[r:SAME_AS]->(wp)
            SET r.evidence = evidence
            RETURN count(r) AS links
            """
        ).single()
        return rec["links"]
