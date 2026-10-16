"""The website only shows real output: its demo data must match what the engine returns now."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location("site_demo_data", ROOT / "scripts" / "site_demo_data.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_site_demo_data_is_current():
    mod = _load()
    committed = (ROOT / "site" / "assets" / "demo-data.js").read_text("utf-8")
    assert committed == mod.render(mod.build()), (
        "site/assets/demo-data.js is stale: run `uv run python scripts/site_demo_data.py`")


def test_site_pages_exist_and_link_assets():
    for page in ("index.html", "docs.html"):
        html = (ROOT / "site" / page).read_text("utf-8")
        assert 'href="assets/style.css"' in html
        assert "<title>" in html and 'lang="en"' in html
    assert (ROOT / "site" / ".nojekyll").exists()


def test_site_announces_accepted_hermes_catalog_entry():
    catalog = "https://github.com/NousResearch/hermes-agent/blob/main/plugin-catalog/scamgate.yaml"
    home = (ROOT / "site" / "index.html").read_text("utf-8")
    docs = (ROOT / "site" / "docs.html").read_text("utf-8")
    assert "Now in the Hermes Plugin Catalog" in home
    assert 'href="docs.html#hermes-plugin"' in home
    for html in (home, docs):
        assert catalog in html
        assert "community plugin" in html
    assert 'id="hermes-plugin"' in docs
    assert "hermes plugins install scamgate" in docs
    assert "Preferred once it is in the catalog" not in docs
    assert "when the entry lands" not in docs
