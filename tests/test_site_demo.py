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
