import base64
import hashlib

from scamgate import integrity


def _digest(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def test_verify_detects_modified_and_missing_files(tmp_path):
    good = tmp_path / "a.py"
    good.write_bytes(b"print('ok')")
    bad = tmp_path / "b.py"
    bad.write_bytes(b"print('changed')")
    entries = [(good, "sha256", _digest(b"print('ok')")),
               (bad, "sha256", _digest(b"print('original')")),
               (tmp_path / "gone.py", "sha256", _digest(b"x"))]
    ok, msg = integrity.verify(entries)
    assert not ok and "b.py" in msg and "gone.py" in msg and "a.py" not in msg


def test_verify_all_good(tmp_path):
    f = tmp_path / "a.py"
    f.write_bytes(b"x")
    assert integrity.verify([(f, "sha256", _digest(b"x"))]) == (True, "1 files verified")


def test_dev_install_is_reported_not_failed():
    ok, msg = integrity.check()  # tests run from an editable checkout
    assert ok
