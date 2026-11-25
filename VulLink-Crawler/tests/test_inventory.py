import json
from pathlib import Path

import pytest

from wpcrawler import inventory, report
from wpcrawler.matching import vullink

FIXTURE = Path(__file__).parent / "fixtures" / "inventory.json"


def test_load_inventory_components_and_findings():
    result = inventory.load(FIXTURE)
    assert result.mode == "server-inventory" and result.is_wordpress
    assert result.components["core:wordpress"].version == "6.9.1"
    cf7 = result.components["plugin:contact-form-7"]
    assert cf7.version == "5.8.4" and cf7.details["status"] == "inactive"
    assert cf7.version_evidence.confidence == "high"
    assert result.components["server:mariadb"].version == "10.11.6"
    assert [f.id for f in result.findings] == ["default-salts"]
    assert result.extra["libraries"][0]["name"] == "phpmailer/phpmailer"


def test_hostile_or_invalid_entries_are_dropped():
    result = inventory.load(FIXTURE)
    assert not any("passwd" in k for k in result.components)
    assert "unknown:x" not in result.components
    assert result.components["plugin:weird-version"].version is None   # invalid version discarded
    assert any("skipped invalid component" in e for e in result.errors)


def test_wrong_schema_is_rejected(tmp_path):
    bad = tmp_path / "x.json"
    bad.write_text(json.dumps({"schema": "something-else"}))
    with pytest.raises(ValueError):
        inventory.load(bad)


def test_report_shows_status_update_and_inventory_sections():
    text = report.render(inventory.load(FIXTURE), matched=False)
    assert "(inactive)" in text and "update available: 6.2.5" in text
    assert "Integrity (checksums against wordpress.org)" in text
    assert "Bundled libraries: 1 Composer packages" in text
    assert "mariadb-server 1:10.11.6-0+deb12u1" in text


def test_database_servers_map_to_vullink_products():
    assert vullink.SERVER_PRODUCTS["mariadb"] == [("mariadb", ["mariadb"])]
    assert vullink.SERVER_PRODUCTS["mysql"] == [("mysql", ["oracle"])]
