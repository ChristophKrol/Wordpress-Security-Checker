import pytest

from wpcrawler.matching import version as v
from wpcrawler.matching import vullink
from wpcrawler.models import Component, Evidence


@pytest.mark.parametrize("a,b,expected", [
    ("1.2", "1.2.0", 0), ("1.10", "1.9", 1), ("2.0-beta", "2.0", -1), ("6.9.1", "6.9.12", -1),
    ("4.3.6", "4.3.5", 1), ("1.0.0.1", "1.0", 1),
])
def test_compare(a, b, expected):
    assert v.compare(a, b) == expected


@pytest.mark.parametrize("ver,rng,expected", [
    ("4.3.5", "<=4.3.5", True), ("4.3.6", "<=4.3.5", False), ("4.3.5", "<4.3.6", True),
    ("2.4.66", ">=2.4.0 <2.4.67", True), ("2.4.67", ">=2.4.0 <2.4.67", False), ("1.0", "*", True),
    ("3.9", ">4.0", False),
])
def test_in_range(ver, rng, expected):
    assert v.in_range(ver, rng) is expected


def test_is_affected():
    assert v.is_affected("1.2.3", [], ["1.2.3"]) is True
    assert v.is_affected("1.2.4", ["<1.2.4"], []) is False
    assert v.is_affected("1.2.4", [], []) is None


def test_cypher_str_encodes_everything_and_rejects_hostile_input():
    enc = vullink.cypher_str("wp-plugin:call-now-button")
    assert "call" not in enc.lower()                           # keyword filter of the API can't trigger
    assert enc.startswith("'") and "\\u0063\\u0061\\u006c\\u006c" in enc
    for bad in ("x' OR 1=1 //", "a}) DETACH DELETE n //", "UPPER", ""):
        with pytest.raises(ValueError):
            vullink.cypher_str(bad)


def test_vendor_scoping_drops_other_vendors_ranges():
    row = {"ranges": ["<10.5.3", "<2.4.58"], "exact": [],
           "vendorRanges": ["akka|<10.5.3", "apache|<2.4.58"], "vendorVersions": []}
    assert vullink._scope_to_vendors(row, ["apache"]) and row["ranges"] == ["<2.4.58"]
    other = {"ranges": ["<10.5.3"], "exact": [], "vendorRanges": ["akka|<10.5.3"], "vendorVersions": []}
    assert vullink._scope_to_vendors(other, ["apache"]) is False
    untagged = {"ranges": ["<1.0"], "exact": [], "vendorRanges": None, "vendorVersions": None}
    assert vullink._scope_to_vendors(untagged, ["apache"]) is True


class FakeClient:
    def __init__(self, rows):
        self.rows = rows

    def query(self, cypher):
        return self.rows


def _row(id_, ranges, patched=(), **kw):
    base = {"id": id_, "cve": id_, "title": f"vuln {id_}\nline2", "wfCvss": 7.5, "nvdCvss": None, "severity": "High",
            "kev": False, "links": [], "ranges": list(ranges), "exact": [], "patched": list(patched),
            "hasPatch": bool(patched), "product": "wp-plugin:x", "vendorRanges": None, "vendorVersions": None}
    base.update(kw)
    return base


def test_match_component_statuses_and_upgrade_target():
    comp = Component("plugin", "x", evidence=[Evidence("readme.txt", "u", "1.5", "high")])
    rows = [
        _row("A", ["<1.6"], ["1.6"]),            # affected, fix 1.6
        _row("B", ["<=1.4"], ["1.4.1"]),         # not affected -> dropped
        _row("C", [">=1.0 <2.0"], [], kev=True),  # affected, no patch list -> derive 2.0 from range
        _row("D", [], []),                       # no version data
    ]
    out = {e["id"]: e for e in vullink.match_component(FakeClient(rows), comp)}
    assert set(out) == {"A", "C", "D"}
    assert out["A"]["status"] == "affected" and out["A"]["upgrade_to"] == "1.6"
    assert out["C"]["upgrade_to"] == "2.0" and out["C"]["actively_exploited"]
    assert out["D"]["status"] == "no_version_data"
    assert out["A"]["title"] == "vuln A line2"


def test_match_component_without_version_lists_all_as_unknown():
    comp = Component("plugin", "x")
    out = vullink.match_component(FakeClient([_row("A", ["<1.6"], ["1.6"])]), comp)
    assert [e["status"] for e in out] == ["unknown_version"]


def test_wildcard_is_ignored_when_specific_ranges_exist():
    # CVE-2007-2627: Wordfence "<=2.2" + NVD "*" (no bounds) must not flag WordPress 7.1.5
    assert v.is_affected("7.1.5", ["<=2.2", "*"], [], ["2.2.1"]) is False
    assert v.is_affected("2.1", ["<=2.2", "*"], [], ["2.2.1"]) is True


def test_wildcard_only():
    assert v.is_affected("1.0", ["*"], [], []) is True               # unpatched, all versions
    assert v.is_affected("7.1.5", ["*"], [], ["2.2.1"]) is False     # fix is older than installed version
    assert v.is_affected("2.0", ["*"], [], ["2.2.1"]) is True


def test_vendor_scoping_keeps_untagged_wordfence_ranges():
    row = {"ranges": ["<=2.2", "*"], "exact": [], "vendorRanges": ["wordpress|*"], "vendorVersions": []}
    assert vullink._scope_to_vendors(row, ["wordpress"])
    assert sorted(row["ranges"]) == ["*", "<=2.2"]
