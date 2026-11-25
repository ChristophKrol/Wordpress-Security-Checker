from wpcrawler.cli import main
from wpcrawler.scanner import ScanOptions, normalise_target, scan


def _versions(result):
    return {k: c.version for k, c in result.components.items()}


def test_default_scan_fingerprints_fake_site(fake_site):
    result = scan(fake_site, ScanOptions(delay=0, max_pages=3))
    assert result.is_wordpress
    v = _versions(result)
    assert v["core:wordpress"] == "6.4.2"
    assert v["plugin:contact-form-7"] == "5.8.4"
    assert v["plugin:elementor"] == "3.18.0"
    # asset ?ver=6.4.2 equals the core version -> downgraded; readme/generator win
    assert v["plugin:woocommerce"] == "8.2.1"
    assert v["plugin:wordpress-seo"] == "21.7"
    assert v["theme:astra-child"] == "1.0.0"
    assert v["theme:astra"] == "4.5.2"                   # parent found via child's Template:
    assert v["server:apache"] == "2.4.57"
    assert result.components["server:apache"].notes      # Ubuntu backport warning
    assert "contact-form-7/v1" in result.rest_namespaces
    assert result.findings == [] and result.mode == "default"
    # default mode never touches aggressive paths
    assert result.requests_made < 20


def test_aggressive_scan_finds_config_issues(fake_site):
    result = scan(fake_site, ScanOptions(delay=0, aggressive=True, plugin_slugs=["akismet", "contact-form-7"]))
    ids = {f.id for f in result.findings}
    assert {"xmlrpc-enabled", "user-enumeration-rest", "user-enumeration-author"} <= ids
    assert "plugin:akismet" not in result.components     # 404 -> not reported


def test_request_budget_is_enforced(fake_site):
    result = scan(fake_site, ScanOptions(delay=0, max_requests=3))
    assert result.requests_made <= 3
    assert any("budget" in e for e in result.errors)


def test_aggressive_requires_authorized_flag(fake_site, capsys):
    assert main(["scan", fake_site, "--aggressive", "--no-match"]) == 2
    assert "--authorized" in capsys.readouterr().err


def test_normalise_target():
    assert normalise_target("example.com/some/page") == "https://example.com/"
    assert normalise_target("http://localhost:8000") == "http://localhost:8000/"
