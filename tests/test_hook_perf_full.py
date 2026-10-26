"""The whole hook call stays linear on long commands, not just `extract()`.

`hook.extract` reads shell words with a one-pass reader (#21, #22), but `harden.gate_extra` still
split every segment with `shlex.split` to find the script a command runs, so the full hook call on a
2,000,000-character command took over 200 s. These time `hook.run`, the function the agent waits on,
in a subprocess with a hard timeout, and check that harden reads the same words as before.
"""

import json
import random
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from scamgate import harden, hook

HARD_TIMEOUT_S = 90
SRC = Path(__file__).resolve().parents[1] / "src"

WORKER = """
import json, sys, time
sys.path.insert(0, {src!r})
from scamgate import hook

shape, k = sys.argv[1], int(sys.argv[2])
cmd = {{
    "base64": "curl example.com " + "QUJD" * (k // 4),
    "quoted": "curl example.com " + "a" * k + " 'x'",
    "script": "bash './build.sh' " + "a" * k + " 'x'",
    "python": "python -c 'import requests' " + "a" * k,
}}[shape]
t = time.perf_counter()
hook.run({{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {{"command": cmd}},
          "session_id": "s", "tool_use_id": "t"}})
print(json.dumps({{"seconds": time.perf_counter() - t}}))
"""


def timed_run(shape: str, n: int) -> float:
    proc = subprocess.run([sys.executable, "-c", WORKER.format(src=str(SRC)), shape, str(n)],
                          capture_output=True, text=True, timeout=HARD_TIMEOUT_S)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)["seconds"]


@pytest.mark.parametrize("shape", ["base64", "quoted", "script", "python"])
def test_full_hook_call_on_400k_is_quick(shape):
    seconds = timed_run(shape, 400_000)
    assert seconds < 3.0, f"hook.run on a 400k {shape} command took {seconds:.1f}s"


def test_full_hook_call_at_the_input_cap_is_not_slow():
    seconds = timed_run("quoted", 2_000_000)
    assert seconds < 15.0, f"hook.run on a 2,000,000-character quoted command took {seconds:.1f}s"


def _shlex_tokens(segment, monkeypatch):
    """harden._script_tokens as it was, with shlex reading the words."""
    def words(s):
        try:
            return shlex.split(s, posix=True)
        except ValueError:
            return None

    monkeypatch.setattr(hook, "_words", words)
    try:
        return harden._script_tokens(segment)
    finally:
        monkeypatch.undo()


SAMPLES = [
    "bash ./build.sh", "bash 'my script.sh' --x", "sudo -E bash -c 'echo hi'", "FOO=1 BAR=2 python run.py",
    "python -m pytest", "python3 'tools/x.py'", "node \"a b.js\"", "uv run scripts/x.py", ". ./env.sh",
    "source ~/.bashrc", "sh -lc 'curl x'", "bash 'unclosed", "python a\\ b.py", "& ./x.bat", "pwsh -File x.ps1",
    "nohup bash run.sh &", "time python x.py", "", "   ", "bash", "env X=1 bash y.sh",
]


@pytest.mark.parametrize("segment", SAMPLES)
def test_harden_reads_the_same_words_as_shlex(segment, monkeypatch):
    assert harden._script_tokens(segment) == _shlex_tokens(segment, monkeypatch)


def test_harden_reads_the_same_words_on_random_input(monkeypatch):
    rng = random.Random(20261026)
    alphabet = list(" \t\r\n'\"\\$;=-./ab") + ["bash ", "python ", "sudo ", "x.sh", "-c ", "uv run "]
    for _ in range(3_000):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 20)))
        assert harden._script_tokens(s) == _shlex_tokens(s, monkeypatch), repr(s)
