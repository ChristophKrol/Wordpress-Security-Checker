// Example queries for the VulLink graph (NVD + Wordfence).
// Run in Neo4j Browser (http://localhost:7474) or via the API: GET /api/v1/cypher_query/?query=...
// Note: the API only allows read queries.

// 1. Overview: what is in the graph
MATCH (n) RETURN labels(n)[0] AS type, count(*) AS count ORDER BY count DESC;

// 2. Is my plugin version affected? (change slug + installed version)
//    Compares dotted numeric versions; suffixes like "-beta" are compared as text.
WITH 'elementor' AS slug, '4.3.5' AS installed
WITH slug, installed,
     apoc.text.join([x IN (split(installed, '.') + ['0','0','0','0'])[..4] | apoc.text.lpad(x, 8, '0')], '.') AS iv
MATCH (v:Vulnerability)-[r:AFFECTS]->(p:Product {slug: slug})
UNWIND r.versionRanges + [x IN r.affectedVersion | '=' + x] AS range
WITH v, r, iv, range,
     [c IN split(range, ' ') WHERE c <> '*' |
        {op: CASE WHEN c =~ '^[<>]=.*' THEN left(c, 2) ELSE left(c, 1) END,
         ver: apoc.text.join([x IN (split(CASE WHEN c =~ '^[<>]=.*' THEN substring(c, 2) ELSE substring(c, 1) END, '.') + ['0','0','0','0'])[..4] | apoc.text.lpad(x, 8, '0')], '.')}] AS conds
WHERE all(c IN conds WHERE CASE c.op
        WHEN '>=' THEN iv >= c.ver WHEN '>' THEN iv > c.ver
        WHEN '<=' THEN iv <= c.ver WHEN '<' THEN iv < c.ver
        WHEN '=' THEN iv = c.ver END)
RETURN DISTINCT v.vulnID AS id, v.wfCvssScore AS cvss, v.wfTitle AS title, r.patchedVersions AS fixedIn, v.wfURLs AS links
ORDER BY cvss DESC;

// 3. All vulnerabilities of one plugin
MATCH (v:Vulnerability)-[r:AFFECTS]->(p:Product {slug: 'elementor'})
RETURN v.vulnID AS id, v.wfTitle AS title, v.wfCvssScore AS cvss, r.versionRanges AS affected, r.patchedVersions AS fixedIn
ORDER BY v.wfPublished DESC LIMIT 25;

// 4. Plugins with the most vulnerabilities
MATCH (v:Vulnerability)-[:AFFECTS]->(p:Product {productType: 'wordpress-plugin'})
RETURN p.slug AS plugin, p.displayName AS name, count(v) AS vulns ORDER BY vulns DESC LIMIT 20;

// 5. Critical vulnerabilities with NO patch available
MATCH (v:Vulnerability)-[r:AFFECTS {patched: false}]->(p:Product)
WHERE v.wfCvssScore >= 9.0
RETURN p.slug AS software, v.vulnID AS id, v.wfCvssScore AS cvss, v.wfTitle AS title
ORDER BY v.wfPublished DESC LIMIT 25;

// 6. Published in the last 30 days
MATCH (v:Vulnerability)-[:AFFECTS]->(p:Product)
WHERE v.wfPublished >= date() - duration('P30D')
RETURN v.wfPublished AS published, p.slug AS software, v.wfCvssRating AS rating, v.wfTitle AS title
ORDER BY published DESC LIMIT 50;

// 7. WordPress core vulnerabilities
MATCH (v:Vulnerability)-[r:AFFECTS]->(:Product {productName: 'wordpress'})
RETURN v.vulnID AS id, v.wfCvssScore AS cvss, v.wfTitle AS title, r.versionRanges AS affected
ORDER BY v.wfPublished DESC LIMIT 25;

// 8. Most common weakness types in WordPress vulnerabilities
MATCH (v:Vulnerability)-[:EXAMPLE_OF]->(w:Weakness)
WHERE 'wordfence' IN v.sources
RETURN 'CWE-' + w.cweID AS cwe, w.cweName AS name, count(v) AS vulns ORDER BY vulns DESC LIMIT 15;

// 9. Most active researchers
MATCH (res:Researcher)-[:DISCOVERED]->(v:Vulnerability)
RETURN res.researcherName AS researcher, count(v) AS found, round(avg(v.wfCvssScore) * 10) / 10 AS avgCvss
ORDER BY found DESC LIMIT 15;

// 10. Vulnerabilities without a CVE (Wordfence only)
MATCH (v:Vulnerability)-[:AFFECTS]->(p)
WHERE v.vulnID STARTS WITH 'WORDFENCE-'
RETURN v.wfTitle AS title, p.slug AS software, v.wfCvssScore AS cvss, v.wfURLs[0] AS link
ORDER BY cvss DESC LIMIT 25;

// 11. Full-text search in descriptions
CALL db.index.fulltext.queryNodes('VulnerabilityDescriptionFullTextSchema', 'woocommerce AND "sql injection"')
YIELD node, score
RETURN node.vulnID AS id, node.wfTitle AS title, score LIMIT 20;

// 12. Same CVE in NVD and Wordfence: compare scores (fills up after the full NVD load)
MATCH (v:Vulnerability)
WHERE 'nvd' IN v.sources AND 'wordfence' IN v.sources
RETURN v.vulnID AS id, v.v3baseScore AS nvdCvss, v.wfCvssScore AS wordfenceCvss, v.cisaKEV AS actively_exploited
LIMIT 25;

// 13. WordPress vulns on the CISA "known exploited" list (needs the full NVD load)
MATCH (v:Vulnerability {cisaKEV: true})-[:AFFECTS]->(p:Product)
WHERE p.productType STARTS WITH 'wordpress' OR p.productName = 'wordpress'
RETURN v.vulnID AS id, p.slug AS software, v.cisaExploitAdd AS addedToKEV, v.wfTitle AS title;

// 14. NVD product <-> WordPress slug links
MATCH (n:Product)-[s:SAME_AS]->(w:Product)
RETURN n.productName AS nvdProduct, w.slug AS wpSlug, s.evidence AS sharedCVEs ORDER BY sharedCVEs DESC LIMIT 25;

// 15. Visual: one plugin with its vulnerabilities, weaknesses and researchers (use the graph view)
MATCH (p:Product {slug: 'backup-backup'})<-[a:AFFECTS]-(v:Vulnerability)
OPTIONAL MATCH (v)-[e:EXAMPLE_OF]->(w:Weakness)
OPTIONAL MATCH (res:Researcher)-[d:DISCOVERED]->(v)
RETURN p, a, v, e, w, res, d;

// 16. Licence / attribution info for the Wordfence data
MATCH (s:DataSource) RETURN s.name, s.copyrightNotice, s.license, s.licenseUrl, s.lastSync;
