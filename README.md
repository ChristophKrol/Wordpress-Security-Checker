# VulLink: A Dynamic Open-Access Vulnerability Graph Database for Cybersecurity Data Mining

![VulLink System Framework](figures/framework.png)

**VulLink** is a **live, publicly accessible, dynamic, and open-access vulnerability graph database** designed for cybersecurity data mining. It integrates fragmented vulnerability records from multiple public repositories—including NVD, CVE, CWE, ExploitDB, and CVE Details—into a continuously updated Neo4j property graph with explicit cross-source relationships.

The project provides both a publicly deployed web platform and the complete source code required to reproduce the system locally.

VulLink provides:

- Automated multi-source ETL pipelines
- A continuously updated vulnerability graph database
- Interactive graph visualization and exploration
- Public RESTful API for graph querying and data retrieval
- Pre-computed semantic embeddings of vulnerability descriptions
- Reproducible resources for downstream cybersecurity data mining

The repository contains the complete source code for the VulLink platform, including the ETL pipeline, API backend, visualization interface, deployment resources, and downstream cybersecurity analytics demonstrations.

---

# Repository Architecture

The project is organized into four primary components.

| Component | Description |
|----------|-------------|
| **VulLink/** | Core configuration files, Neo4j deployment resources, utilities, and analysis notebooks. |
| **VulLink-API/** | FastAPI backend exposing graph query, subgraph retrieval, embedding access, and analytics endpoints. |
| **VulLink-Visualizer/** | React-based frontend for graph exploration, Cypher querying, and data export. |
| **VulLink-Data-Pipeline/** | ETL pipeline responsible for vulnerability ingestion, normalization, graph construction, and database updates. |
| **VulLink-Crawler/** | Standalone WordPress fingerprinting crawler; matches detected core/plugin/theme/server versions against VulLink via the API. See its README. |
| **VulLink-Collector/** | Server-side inventory (single PHP file run with WP-CLI): exact versions incl. inactive plugins, database server, packages, integrity and configuration checks. Matched with `wpcrawler match`. |

## Directory Layout

```text
VulLink/
├── data/
├── figures/
├── VulLink/
├── VulLink-API/
├── VulLink-Data-Pipeline/
├── VulLink-Crawler/
├── VulLink-Collector/
├── VulLink-Visualizer/
├── .env.example
└── docker-compose.yml
```

---

# Public Deployment

A live instance of VulLink is publicly available:

## 🌐 Web Platform

**http://34.129.106.249/**

The deployment provides:

- Interactive knowledge graph visualization
- Cypher query interface
- Vulnerability search
- Subgraph extraction
- Embedding download
- Public REST API

> **Server Migration Notice**
>
> VulLink has been migrated to a new cloud infrastructure provider. The latest public deployment is now hosted at:
>
> **http://34.129.106.249/**

---

# Prerequisites

To deploy VulLink locally, install:

- Docker and Docker Compose
- Python 3.12+
- Node.js 14+
- Neo4j Community Edition 4.4.11 (for native deployment)

---

# Quick Start

## 1. Configure Environment Variables

Copy the templates and set your own Neo4j password in each (`.env` files are git-ignored):

```bash
cp .env.example .env
cp VulLink-API/.env.example VulLink-API/.env
cp VulLink-Visualizer/.env.example VulLink-Visualizer/.env
```

Use the same Neo4j password in all three files. The root `.env` also holds the API keys for the data
sources (`NVD_API_KEY`, `WORDFENCE_API_KEY`); see the comments in `.env.example`.

## 2. Launch the Full Stack

```bash
docker compose up --build -d
```

This starts Neo4j, the API and the frontend. After a reboot, `docker compose up -d` starts them again.

### Access Points

| Service | URL |
|---------|-----|
| Local Frontend | http://localhost |
| API Documentation | http://localhost:8001/docs |
| Neo4j Browser (user `neo4j`, password from `.env`) | http://localhost:7474 |
| Public Deployment (original authors) | http://34.129.106.249/ |

## 3. Load Vulnerability Data

The database starts empty. Load Wordfence and the WordPress-relevant part of NVD (first run takes
about 10 minutes; later runs only fetch changes):

```bash
cd VulLink-Data-Pipeline
python3 -m venv .venv && .venv/bin/pip install -r sources/requirements.txt
.venv/bin/python -m sources.run all
```

Details, options and the schema additions: `VulLink-Data-Pipeline/README.md` (section "API source connectors").
Example queries: `VulLink-Data-Pipeline/sources/example_queries.cypher`.

## 4. Scan a WordPress Site with the Crawler

```bash
cd VulLink-Crawler
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"     # once
.venv/bin/wpcrawler scan https://your-site.com                  # detect + match against VulLink
.venv/bin/wpcrawler scan https://your-site.com --json result.json
```

Only scan sites you own or have permission to test. `--aggressive --authorized` adds plugin enumeration
and configuration checks. All options: `.venv/bin/wpcrawler scan --help` and `VulLink-Crawler/README.md`.

## 5. Check a Server from the Inside (Collector)

With SSH access, the collector gives exact versions (including inactive plugins and the database server)
plus integrity and configuration checks:

```bash
# on your machine: runs over SSH, nothing is stored on the server (WP-CLI required there)
cd VulLink-Collector
ssh user@server 'wp --path=/var/www/html eval-file -' < collect.php > inventory.json
cd ../VulLink-Crawler && .venv/bin/wpcrawler match ../VulLink-Collector/inventory.json
```

Never put `collect.php` or an inventory inside the website folder; they would be downloadable.

Details and alternatives: `VulLink-Collector/README.md`. The inventory contains sensitive data; don't commit or share it.

---

# Local Development

## Graph Integration Pipeline

```bash
cd VulLink-Data-Pipeline
```

Configure:

```text
pipeline_config.json
config.py
```

Run:

```bash
python main.py
```

or

```bash
python nvd_pipeline_new.py
```

---

## API Backend

```bash
cd VulLink-API

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

Start the API:

```bash
npx dotenv-cli -e ../.env -- uvicorn app.main:app --reload
```

Run endpoint tests:

```bash
npx dotenv-cli -e ../.env -- python tests/test_endpoints.py
```

---

## Frontend Visualizer

```bash
cd VulLink-Visualizer

npm install

npx dotenv-cli -e ../.env -- npm start
```

---

# Database Construction Pipeline

VulLink continuously integrates vulnerability intelligence from multiple public repositories:

- National Vulnerability Database (NVD)
- Common Vulnerabilities and Exposures (CVE)
- Common Weakness Enumeration (CWE)
- Exploit Database (ExploitDB)
- CVE Details

The ETL framework performs:

1. Data ingestion
2. Data cleaning and normalization
3. Entity construction
4. Relationship construction
5. Graph validation
6. Incremental graph loading

The graph currently models the following entity types:

- Vulnerability
- Exploit
- Weakness
- Product
- Vendor
- Author
- Domain

Relationship types include:

- AFFECTS
- EXPLOITS
- EXAMPLE_OF
- BELONGS_TO
- WRITES
- REFERS_TO

The resulting graph database currently contains over **545,000 nodes** and **1.6 million relationships**, supporting large-scale cybersecurity analytics and graph mining.

---

# Deploying the Base VulKG Graph

VulLink builds upon the **VulKG** graph schema proposed in previous research. The original VulKG schema and graph construction methodology are not contributions of this repository.

VulLink extends this foundation through:

- Dynamic multi-source ETL integration
- Automated incremental updates
- Open-access web services
- Interactive graph visualization
- Public REST API
- Pre-computed semantic embeddings
- Cybersecurity data mining utilities

## Requirements

- Neo4j Desktop 1.4.15 or newer
- Neo4j Community Edition 4.4.11
- APOC Plugin
- Graph Data Science (GDS) Plugin

## Deployment Steps

### 1. Create a Neo4j Project

```text
VulKG Project
```

### 2. Create a Local DBMS

```text
Graph DBMS
```

Configuration:

```text
Neo4j Version: 4.4.11
Password: Neo4j
```

### 3. Install Plugins

Install:

- APOC
- Graph Data Science Library

### 4. Enable APOC File Import

Add the following line to the Neo4j configuration file:

```text
apoc.import.file.enabled=true
```

This resolves the error:

```text
Failed to invoke procedure `apoc.periodic.iterate`
Import from files not enabled
```

### 5. Import Data

Copy all required import files into the Neo4j import directory.

### 6. Open Neo4j Browser

Enable:

```text
Enable multi statement query editor
```

### 7. Deploy the Graph

Execute:

```text
VulLink/src/neo4j/VulKG_Deployment_Cypher.cypher
```

This creates the original VulKG graph structure used as the foundation of VulLink.

---

# Open Access and Data Retrieval

VulLink provides both a publicly accessible web platform and a REST API for retrieving cybersecurity knowledge graph data.

Available functionality includes:

- Interactive graph visualization
- Cypher query execution
- Custom subgraph extraction
- Node export
- Relationship export
- Semantic embedding download
- RESTful API access

Researchers can retrieve task-specific vulnerability subgraphs without rebuilding the underlying database.

Example downstream applications include:

- Vulnerability prioritization
- Threat intelligence analysis
- Vulnerability clustering
- Link prediction
- Graph representation learning
- Graph neural network benchmarking

---

# Pre-computed Semantic Features

VulLink provides downloadable embeddings generated from vulnerability descriptions using multiple language models, including:

- SecBERT
- MPNet
- FastText

Embeddings can be downloaded through both the web interface and the REST API with configurable embedding dimensions, enabling direct integration into downstream machine learning workflows.

---

# Demonstration: Exploitability Prediction using Graph Neural Networks

To demonstrate the utility of VulLink for downstream cybersecurity data mining, this repository includes an exploitability prediction benchmark built directly from the VulLink knowledge graph.

Starting from the integrated graph database, we automatically extract the relevant **nodes**, **relationships**, and **vulnerability attributes** to construct graph datasets suitable for graph representation learning.

The prediction task aims to determine whether a vulnerability is associated with a known public exploit.

The benchmark compares multiple approaches, including:

- Traditional machine learning using vulnerability attributes
- Semantic embedding-based models
- Graph neural networks operating directly on the extracted VulLink graph

Unlike tabular approaches, graph neural networks leverage the rich relational information encoded within VulLink, including relationships among vulnerabilities, weaknesses, products, vendors, exploits, and authors.

The resulting benchmark demonstrates that graph-based learning consistently outperforms feature-only baselines, highlighting the importance of relational vulnerability intelligence for cybersecurity analytics.

<p align="center">
<img src="figures/exploitability_prediction_comparison.png" width="900">
</p>

This example serves as a complete reference workflow for:

- Exploitability prediction
- Vulnerability prioritization
- Knowledge graph mining
- Graph representation learning
- Graph neural network research
- Security risk assessment

The preprocessing pipeline illustrates how VulLink can be transformed into graph datasets compatible with popular graph learning frameworks such as **PyTorch Geometric** and **Deep Graph Library (DGL)**.

---

# Cybersecurity Data Mining Applications

VulLink is designed as reusable graph infrastructure for cybersecurity research.

Potential downstream applications include:

- Exploitability prediction
- Vulnerability prioritization
- Vulnerability clustering
- Threat intelligence analysis
- Knowledge graph mining
- Link prediction
- Graph representation learning
- Multi-hop vulnerability reasoning
- Security recommendation systems
- Graph neural network benchmarking

---

# Citation

If you use VulLink in your research, please cite:

```bibtex
@article{do2026vullink,
  title={VulLink: A Dynamic Open-Access Vulnerability Graph Database for Cybersecurity Data Mining},
  author={Do, Luat and Cao, Jinli and Yin, Jiao and Wang, Hua},
  journal={arXiv preprint arXiv:2604.06967},
  year={2026}
}
```

---


# License

This project is released under the MIT License.

See the `LICENSE` files within the repository and component subprojects for additional licensing information.