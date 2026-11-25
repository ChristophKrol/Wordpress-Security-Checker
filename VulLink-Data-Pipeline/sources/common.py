"""Shared plumbing for the API-based source connectors: config, HTTP, Neo4j, run state."""
from __future__ import annotations

import gzip
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from dotenv import load_dotenv
from neo4j import GraphDatabase

REPO_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(REPO_ROOT / ".env")

DATA_DIR = Path(os.getenv("VULLINK_DATA_DIR", REPO_ROOT / "data"))
RAW_DIR = DATA_DIR / "raw"
STATE_FILE = DATA_DIR / "source_state.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("sources")


def env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.getenv(name, default)
    return value.strip() if isinstance(value, str) and value.strip() else default


def neo4j_driver():
    uri = env("NEO4J_URI", "bolt://localhost:7687")
    user = env("NEO4J_USER", "neo4j")
    password = env("NEO4J_PASSWORD")
    if not password:
        raise SystemExit("NEO4J_PASSWORD is not set (expected in the repo-root .env)")
    driver = GraphDatabase.driver(uri, auth=(user, password))
    driver.verify_connectivity()
    return driver


class HttpClient:
    """requests wrapper with a minimum delay between calls and retry/backoff on 403/429/5xx."""

    def __init__(self, headers: Dict[str, str], min_interval: float, max_retries: int = 6, timeout: int = 120,
                 retry_on_429: bool = True):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "VulLink-ETL/1.0", **headers})
        self.min_interval = min_interval
        self.max_retries = max_retries
        self.timeout = timeout
        self.retry_on_429 = retry_on_429
        self._last_call = 0.0

    def get_json(self, url: str, params: Optional[Dict[str, Any]] = None) -> Any:
        for attempt in range(1, self.max_retries + 1):
            wait = self.min_interval - (time.monotonic() - self._last_call)
            if wait > 0:
                time.sleep(wait)
            self._last_call = time.monotonic()
            try:
                resp = self.session.get(url, params=params, timeout=self.timeout)
            except requests.RequestException as exc:
                err = str(exc)
            else:
                if resp.status_code == 200:
                    return resp.json()
                if resp.status_code in (401,):
                    raise RuntimeError(f"Unauthorized (401) for {url} - check the API key")
                if resp.status_code == 429:
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after and retry_after.isdigit() and int(retry_after) <= 300:
                        log.warning("Rate limited, waiting %ss (Retry-After)", retry_after)
                        time.sleep(int(retry_after))
                        continue
                    if not self.retry_on_429:
                        raise RuntimeError(f"Rate limited (429) by {url} - try again later")
                if resp.status_code not in (403, 429, 500, 502, 503, 504):
                    raise RuntimeError(f"HTTP {resp.status_code} for {resp.url}: {resp.text[:300]}")
                err = f"HTTP {resp.status_code}"
            backoff = min(60, 2 ** attempt)
            log.warning("Request failed (%s), retry %d/%d in %ds", err, attempt, self.max_retries, backoff)
            time.sleep(backoff)
        raise RuntimeError(f"Giving up on {url} after {self.max_retries} attempts")


def save_raw(source: str, name: str, payload: Any) -> Path:
    """Keep a gzipped copy of every raw API response so transforms can be re-run offline."""
    path = RAW_DIR / source / f"{name}.json.gz"
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        json.dump(payload, fh)
    return path


def load_state() -> Dict[str, Any]:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


def save_state(state: Dict[str, Any]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True))
