"""The hook has to stay usable on large tool inputs.

A 100k-character command used to keep the hook busy for about 40 s, and the hook accepts inputs up
to 2 MiB. Two different things cost that time. The call-looking pattern `[A-Za-z_][\\w.]*\\(`
backtracks from every start position to the end of the string, which is quadratic in the length of
the segment. `shlex.split` also grows faster than the input on a single long token, because it
assembles the token one character at a time. Calling it twice per segment doubled a number that
was already too large.

The timing runs in a subprocess with a hard timeout: a regex stuck in the C engine cannot be
interrupted from inside the same process, so an in-process deadline would never fire.
"""

import json
import random
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from scamgate import hook

HARD_TIMEOUT_S = 60
MAX_SECONDS = 2.0
MAX_SECONDS_400K = 5.0
# A quoted local install of 400k characters measures 0.53 s here; reading the words first makes it
# 3.3 s, so the line sits between the two with room on both sides.
MAX_SECONDS_LOCAL_INSTALL = 2.0
MAX_RATIO = 8.0
SRC = Path(__file__).resolve().parents[1] / "src"

WORKER = """
import json, sys, time
sys.path.insert(0, {src!r})
from scamgate import hook

shape = sys.argv[1]
sizes = [int(x) for x in sys.argv[2:]]
body = {{
    "identifier": lambda k: "curl example.com " + "a" * k,
    "dotted": lambda k: "curl example.com " + "a." * (k // 2),
    "base64": lambda k: "curl example.com " + "QUJD" * (k // 4),
    "local_quoted": lambda k: "cargo fetch " + "a" * k + " 'x'",
}}[shape]
out = []
for k in sizes:
    t = time.perf_counter()
    gate = hook.extract("Bash", {{"command": body(k)}})
    out.append({{"n": k, "seconds": time.perf_counter() - t, "opaque": gate.opaque_network}})
print(json.dumps(out))
"""


def timed_hook(shape: str, sizes: list[int]) -> list[dict]:
    code = WORKER.format(src=str(SRC))
    proc = subprocess.run([sys.executable, "-c", code, shape, *map(str, sizes)],
                          capture_output=True, text=True, timeout=HARD_TIMEOUT_S)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


@pytest.mark.parametrize("shape", ["identifier", "dotted", "base64"])
def test_long_run_does_not_stall_the_hook(shape):
    seconds = timed_hook(shape, [100_000])[0]["seconds"]
    assert seconds < MAX_SECONDS, f"{shape} run of 100k chars took {seconds:.1f}s"


@pytest.mark.parametrize("shape", ["identifier", "dotted", "base64"])
def test_cost_grows_less_than_the_input(shape):
    """Four times the input must not cost eight times the time, measured in one process."""
    small, big = timed_hook(shape, [100_000, 400_000])
    ratio = big["seconds"] / small["seconds"]
    assert big["seconds"] < MAX_SECONDS_400K, f"{shape} run of 400k took {big['seconds']:.1f}s"
    assert ratio < MAX_RATIO, f"{shape} grew {ratio:.1f}x for 4x the input"


def test_local_install_is_answered_without_reading_the_words():
    """`_LOCAL_ONLY` short-circuits before the split, so a quoted local install stays instant even
    when it is long. Reading the words first would hand a 400k-character segment to shlex."""
    result = timed_hook("local_quoted", [400_000])[0]
    assert result["opaque"] is False
    assert result["seconds"] < MAX_SECONDS_LOCAL_INSTALL, (
        f"a 400k quoted local install took {result['seconds']:.1f}s")


OLD_CALL = re.compile(r"[A-Za-z_][\w.]*\(")

SAMPLES = [
    "foo.bar(1)",
    "a" * 5_000,
    "a." * 2_000,
    "QUJD" * 500,
    "",
    "(",
    "()",
    "1a(",
    "_x(",
    ".a(",
    "中文字段(a)",
    "한글(",
    "curl example.com",
    "a.b.c(",
    "x(1) (2)",
    "abc)\n(def)",
    "npm ci && node script.js",
    "grep -r 'foo(' src",
]


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda s: repr(s[:18]))
def test_call_detection_is_unchanged(sample):
    """The linear scan must answer exactly what the pattern did, including on odd input."""
    assert hook._code_like(sample) == bool(OLD_CALL.search(sample))


def test_call_detection_matches_the_pattern_on_repo_text():
    texts = [p.read_text(encoding="utf-8", errors="replace")
             for p in [SRC / "scamgate" / "hook.py", SRC / "scamgate" / "engine.py",
                       Path(__file__).resolve().parents[1] / "README.md"]]
    for text in texts:
        for line in text.splitlines():
            assert hook._code_like(line) == bool(OLD_CALL.search(line)), line[:80]


WORD_ALPHABET = list("abcXYZ019_-./=:@%+") + [
    " ", "\t", "\r", "\n", "\x0b", "\x0c", "\u3000", "#", "中", "文", "|", ";", "$", "'", '"', "\\",
]

WORD_SAMPLES = [
    "",
    " ",
    "\t\r\n",
    "a  b",
    "a\u3000b",
    "a\x0bb",
    "# x",
    "echo '# x'",
    "a\\ b",
    "curl 'http://x'",
    "a'",
    "a\\",
    "curl example.com",
    "pip install -r requirements.txt",
]


def _shlex_words(s: str):
    try:
        return shlex.split(s, posix=True)
    except ValueError:
        return None


@pytest.mark.parametrize("sample", WORD_SAMPLES, ids=lambda s: repr(s[:18]))
def test_word_split_is_unchanged(sample):
    """Without quotes or escapes the fast path must give the words shlex would have given."""
    assert hook._words(sample) == _shlex_words(sample)


def test_word_split_is_unchanged_on_random_input():
    """Same check over a seeded batch of random strings drawn from shell-relevant characters."""
    rng = random.Random(20261025)
    for _ in range(5_000):
        s = "".join(rng.choice(WORD_ALPHABET) for _ in range(rng.randint(0, 24)))
        assert hook._words(s) == _shlex_words(s), repr(s)
