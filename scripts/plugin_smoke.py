"""Smoke test for a plain Hermes plugin install: only the plugin folder, pydantic and pyyaml.

CI copies `src/scamgate` into an empty `plugins/` folder, makes a venv with nothing but the
plugin's `python_dependencies`, and runs this. It proves `hermes scamgate update-feeds`,
`/scamgate update` and the `scamgate_update_feeds` tool work without typer, rich, mcp or a
`scamgate` command on PATH. Downloads are served from tests/fixtures/feeds (no network).

    python scripts/plugin_smoke.py <plugins-dir> <fixtures-dir>
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def main() -> int:
    plugins_dir, fixtures = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    for extra in ("typer", "rich", "mcp"):
        if importlib.util.find_spec(extra) is not None:
            fail(f"{extra} is installed; this check needs a venv with only the plugin's dependencies")

    tmp = Path(tempfile.mkdtemp(prefix="scamgate-smoke-"))
    os.environ["SCAMGATE_CACHE_DIR"] = str(tmp / "cache")
    os.environ["SCAMGATE_STATE_DIR"] = str(tmp / "state")
    os.environ["SCAMGATE_AUTO_UPDATE"] = "0"
    os.environ.pop("SCAMGATE_URLHAUS_AUTH_KEY", None)
    sys.path.insert(0, str(plugins_dir))  # how Hermes imports a plugin folder

    from scamgate import feeds, plugin

    served = []

    def fixture_fetch(url: str) -> str:
        served.append(url)
        name = "openphish.txt" if "openphish" in url else "phishing-domains.txt"
        return (fixtures / name).read_text("utf-8")

    feeds._download = fixture_fetch

    class Ctx:
        tools, commands, cli = {}, {}, {}

        def register_hook(self, *a, **k): pass
        def register_tool(self, **kw): self.tools[kw["name"]] = kw
        def register_command(self, name, handler, **kw): self.commands[name] = handler
        def register_cli_command(self, name, help, setup_fn, handler_fn=None, description=""):
            self.cli[name] = (setup_fn, handler_fn)
        def get_config(self, key, default=None): return default

    ctx = Ctx()
    plugin.register(ctx)
    for need in ("scamgate_check_url", "scamgate_update_feeds"):
        if need not in ctx.tools:
            fail(f"tool {need} not registered")

    setup, handler = ctx.cli["scamgate"]

    def hermes_scamgate(*argv: str) -> int:
        parser = argparse.ArgumentParser(prog="hermes scamgate")
        setup(parser)
        return handler(parser.parse_args(list(argv)))

    print("$ hermes scamgate update-feeds")
    if hermes_scamgate("update-feeds") != 0:
        fail("update-feeds returned non-zero")
    print("$ hermes scamgate feeds-status")
    if hermes_scamgate("feeds-status") != 0:
        fail("feeds-status returned non-zero")
    if not served or not all(u.startswith("https://") for u in served):
        fail(f"unexpected download URLs: {served}")

    tool = json.loads(ctx.tools["scamgate_update_feeds"]["handler"]({"url": "https://evil.example/x"}))
    print("tool:", tool["summary"])
    if tool["skipped"] != "fresh":
        fail("the tool downloaded again right after a refresh")

    verdict = json.loads(ctx.tools["scamgate_check_url"]["handler"]({"url": "https://bad-shop.test/login"}))
    print("check_url bad-shop.test:", verdict["decision"])
    if verdict["decision"] != "deny":
        fail("a host from the sample feed was not denied")
    status = ctx.commands["scamgate"]("status")
    print(status)
    if "loaded" not in status:
        fail("/scamgate status doesn't see the refreshed lists")
    print("OK: plugin feed refresh works on a bare plugin install")
    return 0


if __name__ == "__main__":
    sys.exit(main())
