# VulLink Data Pipeline

A comprehensive data pipeline for collecting, processing, validating, and storing vulnerability data from multiple sources.

## Overview

The VulLink data pipeline collects vulnerability data from sources such as:
- National Vulnerability Database (NVD)
- Common Vulnerabilities and Exposures (CVE)
- Common Weakness Enumeration (CWE)
- Exploit Database (ExploitDB)

The pipeline follows a four-stage process:
1. **Crawling**: Data collection from sources
2. **Preprocessing**: Data cleaning and transformation
3. **Validation**: Data quality and schema validation
4. **Migration**: Loading data into a Neo4j database

## Architecture

The pipeline is organized into modular components:

```
VulLink-Data-Pipeline/
├── pipeline/               # Core pipeline implementation
├── crawling/               # Data collection modules
├── preprocessing/          # Data transformation modules
├── validation/             # Data validation modules
├── migration/              # Database migration modules
├── drivers/                # Web drivers for crawling
├── config.py               # Configuration settings
├── logger.py               # Logging functionality
├── run_pipeline.py         # CLI entry point
└── utils.py                # Utility functions
```

## Running the Pipeline

Run the pipeline using the command line interface:

```bash
# Run the full NVD pipeline
python run_pipeline.py nvd

# Run the full CVE pipeline
python run_pipeline.py cve

# Run specific stages of the NVD pipeline
python run_pipeline.py nvd --stages crawl preprocess

# Run specific stages of the CVE pipeline
python run_pipeline.py cve --stages validate migrate
```

## Data Flow

The data flows through the pipeline as follows:

1. **Crawling**: Raw data is collected and saved to the `raw` directory for each source.
2. **Preprocessing**: Raw data is transformed and saved to the `processed` directory.
3. **Validation**: Processed data is validated and saved to the `validated` directory.
4. **Migration**: Validated data is loaded into the Neo4j database.

## Configuration

Configure the pipeline in `config.py`:
- Data source URLs and output directories
- Database connection details
- Processing settings (batch size, timeout, etc.)

## Requirements

- Python 3.6+
- Selenium WebDriver (for dynamic crawling)
- Neo4j database
- Packages: pandas, requests, beautifulsoup4, neo4j, etc.
## API source connectors (`sources/`)

API-based connectors that load directly into the VulLink graph. They extend the original schema
(all original names unchanged), can run repeatedly without duplicating data, and are incremental.

| Source | Command | Key (`.env` in repo root) | Notes |
|---|---|---|---|
| NVD CVE API 2.0 | `python -m sources.run nvd` | `NVD_API_KEY` | First run = full scan, afterwards only CVEs modified since the last run. Default scope `wordpress` (see below) |
| Wordfence Intelligence v3 | `python -m sources.run wordfence` | `WORDFENCE_API_KEY` | Full snapshot each run, only changed records are written; downloads are rate-limited, so run at most a few times a day |

```bash
cd VulLink-Data-Pipeline
python3 -m venv .venv && .venv/bin/pip install -r sources/requirements.txt
.venv/bin/python -m sources.run all          # Wordfence, then NVD
```

**NVD scope.** By default (`--scope wordpress`, or `NVD_SCOPE` in `.env`) the NVD connector downloads all
pages but only stores CVEs that are WordPress-related: the CVE appears in Wordfence, has a CPE with
`target_sw=wordpress` (or vendor `wordpress`), mentions WordPress in its description, or affects the
hosting stack (`NVD_STACK_PRODUCTS`, CPE `vendor:product` pairs; default
`php:php,oracle:mysql,mariadb:mariadb,apache:http_server,f5:nginx,nginx:nginx,litespeedtech:openlitespeed,litespeedtech:litespeed_web_server,litespeed_technologies:litespeed_web_server`). The match reasons are stored
in `Vulnerability.wpRelevance` (e.g. `["wordfence", "wordpress-cpe"]`, `["stack:php"]`) and stack products get
`Product.hostingStack = true`. Changing the stack list triggers a full rescan. A full scan also
removes NVD data that is out of scope. On incremental runs, Wordfence CVEs that NVD has but the pipeline
skipped earlier are fetched one by one (up to 500 per run; CVEs NVD doesn't have yet are rechecked weekly).
Use `--scope all` to load the whole NVD (changing scope triggers a full scan).

Useful flags: `--full` (ignore checkpoints/hashes), `--max-pages N` (NVD smoke test),
`--feed-file path.json[.gz]` (Wordfence: load a saved snapshot instead of downloading).
Raw responses are kept under `data/raw/<source>/`, checkpoints in `data/source_state.json`.

Schema additions:
- `Vulnerability.vulnID`: unique key (CVE id, or `WORDFENCE-<uuid>` until Wordfence assigns a CVE)
- `sources` list on nodes and relationships (`nvd`, `wordfence`): provenance; reloading a source replaces only its own relationships
- WordPress software as `Product {productName: "wp-plugin:<slug>" | "wp-theme:<slug>", productType: "wordpress-plugin" | "wordpress-theme", slug}`;
  core maps to NVD's `wordpress` / `wordpress_mu` products
- `AFFECTS {versionRanges: [">=1.0 <2.3", ...], affectedVersion, patchedVersions, patched, remediation}`
- `(:Researcher)-[:DISCOVERED]->(:Vulnerability)`, `(:Product)-[:SAME_AS {evidence}]->(:Product)` (NVD CPE product to WordPress slug)
- Wordfence-specific vulnerability fields are prefixed `wf` (`wfCvssScore`, `wfTitle`, `wfURLs`, ...); NVD fields keep the original names
- `(:DataSource {name: "wordfence"})` holds the copyright notice and licence. **Wordfence's licence requires a link
  to the record (`wfURLs`) and the copyright notice in any copy you publish.**
