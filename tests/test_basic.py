import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from folder_hasher import sniff_type, hash_all, _ext_match


def test_sniff_png():
    res = sniff_type(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
    assert res is not None and res[0] == "png"


def test_sniff_jpeg():
    res = sniff_type(b"\xff\xd8\xff\xe0" + b"\x00" * 16)
    assert res is not None and res[0] == "jpeg"


def test_sniff_pdf():
    res = sniff_type(b"%PDF-1.4\n...")
    assert res is not None and res[0] == "pdf"


def test_sniff_unknown():
    assert sniff_type(b"random nonsense xyz") is None


def test_ext_match_ok(tmp_path):
    p = tmp_path / "image.png"
    p.write_bytes(b"x")
    assert _ext_match(p, ("png", {".png"})) == "ok"


def test_ext_match_mismatch(tmp_path):
    p = tmp_path / "image.jpg"
    p.write_bytes(b"x")
    assert _ext_match(p, ("png", {".png"})) == "mismatch"


def test_hash_all_matches_hashlib(tmp_path):
    p = tmp_path / "f.bin"
    payload = b"hello world"
    p.write_bytes(payload)
    res = hash_all(p)
    assert res["md5"]    == hashlib.md5(payload).hexdigest()
    assert res["sha1"]   == hashlib.sha1(payload).hexdigest()
    assert res["sha256"] == hashlib.sha256(payload).hexdigest()
