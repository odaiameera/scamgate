"""`_shell_words` must answer exactly what `shlex.split(seg, posix=True)` answers.

A word difference here is a behaviour difference in what the hook decides, so the samples cover
the places the two implementations could drift apart: whitespace sets, empty quotes, adjacent
pieces, escapes inside and outside double quotes, unicode, and the inputs shlex refuses.
"""

import random
import shlex

import pytest

from scamgate import hook

BS = chr(92)
SQ = chr(39)
DQ = chr(34)
TAB = chr(9)
CR = chr(13)

SAMPLES = [
    "",
    " ",
    "   ",
    TAB,
    chr(10),
    CR + chr(10),
    "a",
    "a b",
    "  a  b  ",
    "a" + TAB + "b",
    "a" + CR + "b",
    "a" + chr(10) + "b",
    chr(11),
    chr(12),
    chr(0x3000),
    "a" + chr(11) + "b",
    SQ + SQ,
    DQ + DQ,
    SQ + SQ + " " + SQ + SQ,
    DQ + DQ + " " + DQ + DQ,
    SQ + SQ + DQ + DQ,
    "a" + SQ + SQ + "b",
    "a" + DQ + DQ + "b",
    SQ + "a" + SQ,
    DQ + "a" + DQ,
    SQ + "a b" + SQ,
    DQ + "a b" + DQ,
    SQ + "a" + DQ + "b" + SQ,
    DQ + "a" + SQ + "b" + DQ,
    BS + SQ,
    BS + DQ,
    BS + BS,
    BS + " ",
    "a" + BS + " b",
    "a" + BS + "b",
    "a" + BS + BS + "b",
    DQ + "a" + BS + DQ + "b" + DQ,
    DQ + "a" + BS + "n" + DQ,
    DQ + "a" + BS + "t" + DQ,
    DQ + "a" + BS + chr(10) + DQ,
    "#",
    "# a",
    "a#b",
    "|",
    ";",
    "$HOME",
    "a|b",
    "curl example.com",
    "curl " + SQ + "example.com" + SQ,
    "curl " + DQ + "example.com" + DQ,
    "a" + SQ * 4 + "b",
    "a" + DQ * 4 + "b",
    chr(0x4e2d) + chr(0x6587) + " " + chr(0x5b57),
    SQ + chr(0x4e2d) + " " + chr(0x6587) + SQ,
]

REFUSED = [SQ, DQ, BS, "cargo fetch " + BS, SQ + "unclosed", DQ + "unclosed", "a b" + BS,
           DQ + "a" + BS, SQ + "a" + BS]


@pytest.mark.parametrize("seg", SAMPLES)
def test_same_words_as_shlex(seg: str) -> None:
    assert hook._shell_words(seg) == shlex.split(seg, posix=True)


@pytest.mark.parametrize("seg", REFUSED)
def test_same_refusal_as_shlex(seg: str) -> None:
    with pytest.raises(ValueError, match="No closing quotation|No escaped character") as want:
        shlex.split(seg, posix=True)
    with pytest.raises(ValueError, match="No closing quotation|No escaped character") as got:
        hook._shell_words(seg)
    assert str(got.value) == str(want.value)


def test_same_words_on_random_strings() -> None:
    rng = random.Random(20261025)
    pool = [" ", TAB, CR, chr(10), chr(11), chr(12), chr(0x3000), SQ, DQ, BS,
            "a", "b", "Z", "#", "$", "|", ";", "-", "/", ".", "=", ":", chr(0x4e2d)]
    weights = [6, 2, 2, 3, 1, 1, 1, 10, 10, 10, 6, 4, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2]
    for _ in range(5_000):
        seg = "".join(rng.choices(pool, weights=weights, k=rng.randrange(0, 13)))
        try:
            want = shlex.split(seg, posix=True)
        except ValueError as exc:
            with pytest.raises(ValueError) as got:
                hook._shell_words(seg)
            assert str(got.value) == str(exc), seg
            continue
        assert hook._shell_words(seg) == want, seg


def test_flat_time_on_a_long_token() -> None:
    """One long word used to be the expensive case for shlex, which builds tokens char by char."""
    import time

    seg = "a" * 400_000
    start = time.perf_counter()
    words = hook._shell_words(seg)
    elapsed = time.perf_counter() - start
    assert words == [seg]
    assert elapsed < 0.5, elapsed
