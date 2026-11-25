from pathlib import Path

from wpcrawler.fingerprint import parsers as p

SITE = Path(__file__).parent / "fixtures" / "site"
INDEX = (SITE / "index.html").read_text()
BASE = "https://example.com/"


def test_component_refs_from_attributes_and_inline_json():
    refs = p.wp_component_refs(p.extract_urls(INDEX, BASE))
    found = {(t, s, v) for t, s, v, _ in refs}
    assert ("plugin", "contact-form-7", "5.8.4") in found
    assert ("plugin", "elementor", "3.18.0") in found
    assert ("plugin", "woocommerce", "6.4.2") in found        # from JSON-escaped inline script
    assert ("theme", "astra-child", "1.0.0") in found


def test_core_asset_versions_skip_bundled_libraries():
    versions = {v for v, _ in p.core_asset_versions(p.extract_urls(INDEX, BASE))}
    assert versions == {"6.4.2"}                              # jquery 3.7.1 ignored


def test_generators():
    parsed = [p.parse_generator(g) for g in p.meta_generators(INDEX)]
    assert ("wordpress", "6.4.2") in parsed
    assert ("woocommerce", "8.2.1") in parsed
    assert ("elementor", "3.18.0") in parsed
    assert p.parse_generator("WPML ver:4.6.9 stt:1;") == ("wpml", "4.6.9")


def test_comment_signature_yoast():
    assert ("wordpress-seo", "21.7") in [(s, v) for s, v, _ in p.comment_signatures(INDEX)]


def test_readme_parsing():
    name, stable, changelog = p.parse_readme((SITE / "wp-content/plugins/woocommerce/readme.txt").read_text())
    assert (name, stable, changelog) == ("WooCommerce", "8.2.1", "8.2.1")
    assert p.parse_readme("<html>404</html>") == (None, None, None)
    assert p.parse_readme("=== X ===\nStable tag: trunk\n")[1] is None


def test_style_css():
    assert p.parse_style_css((SITE / "wp-content/themes/astra-child/style.css").read_text()) == \
        ("Astra Child", "1.0.0", "astra")


def test_server_headers_and_distro():
    sw = p.server_software({"server": "Apache/2.4.57 (Ubuntu)", "x-powered-by": "PHP/8.1.2-1ubuntu2.14"})
    assert ("apache", "Apache HTTP Server", "2.4.57") == sw[0][:3]
    assert sw[1][0] == "php" and sw[1][2].startswith("8.1.2")
    assert p.distro_package("Apache/2.4.57 (Ubuntu)") == "Ubuntu"
    assert p.server_software({"server": "LiteSpeed"})[0][:3] == ("litespeed", "LiteSpeed Web Server", None)
    assert p.cdn_in_front({"server": "cloudflare"}) == "Cloudflare"


def test_rest_link_and_feed():
    assert p.rest_root_from_link_header('<https://x.org/?rest_route=/>; rel="https://api.w.org/"') == \
        "https://x.org/?rest_route=/"
    assert p.feed_generator_version((SITE / "feed.xml").read_text()) == "6.4.2"


def test_hostile_values_are_rejected():
    assert p.clean_slug("../../etc") is None
    assert p.clean_slug("x' OR 1=1") is None
    assert p.clean_version("1.0'; DROP") is None
    refs = p.wp_component_refs(["https://e.com/wp-content/plugins/ok-slug/x.js?ver=1.2%27%3B"])
    assert refs[0][1:3] == ("ok-slug", None)
