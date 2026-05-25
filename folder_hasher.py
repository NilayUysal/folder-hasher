#!/usr/bin/env python3
"""
folder-hasher

Walk a folder, hash every file with SHA256, and write a CSV manifest.
Useful for snapshotting the contents of an evidence directory so you can
later verify that nothing changed.

Pure Python standard library — no external dependencies.
Tested on Python 3.8+.
"""

import argparse
import csv
import hashlib
import os
import sys
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


CHUNK = 1024 * 1024  # 1 MiB read buffer


# File signature table: (magic prefix, label, valid extensions)
MAGIC_TABLE: List[Tuple[bytes, str, set]] = [
    (b"\x89PNG\r\n\x1a\n",    "png",      {".png"}),
    (b"\xff\xd8\xff",         "jpeg",     {".jpg", ".jpeg"}),
    (b"GIF87a",               "gif",      {".gif"}),
    (b"GIF89a",               "gif",      {".gif"}),
    (b"%PDF-",                "pdf",      {".pdf"}),
    (b"PK\x03\x04",           "zip",      {".zip", ".jar", ".docx", ".xlsx", ".pptx", ".odt"}),
    (b"\x1f\x8b\x08",         "gzip",     {".gz", ".tgz"}),
    (b"7z\xbc\xaf\x27\x1c",   "7z",       {".7z"}),
    (b"MZ",                   "pe",       {".exe", ".dll", ".sys", ".scr"}),
    (b"\x7fELF",              "elf",      {".bin", ".o", ".so", ""}),
    (b"SQLite format 3\x00",  "sqlite",   {".db", ".sqlite", ".sqlite3"}),
]


def sniff_type(head: bytes):
    for sig, label, exts in MAGIC_TABLE:
        if head.startswith(sig):
            return label, exts
    return None


def _ext_match(path: Path, sniff) -> str:
    if not sniff:
        return "unknown"
    _, ok_exts = sniff
    return "ok" if path.suffix.lower() in ok_exts else "mismatch"


def hash_all(path: Path) -> dict:
    """Stream the file once: compute MD5/SHA1/SHA256 and sniff the file signature."""
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    head = b""
    with path.open("rb") as f:
        first = True
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            if first:
                head = chunk[:32]
                first = False
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    sniff = sniff_type(head)
    return {
        "md5":           md5.hexdigest(),
        "sha1":          sha1.hexdigest(),
        "sha256":        sha256.hexdigest(),
        "detected_type": sniff[0] if sniff else "unknown",
        "ext_match":     _ext_match(path, sniff),
    }


def _ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def walk_files(root: Path,
               includes: Optional[List[str]] = None,
               excludes: Optional[List[str]] = None) -> Iterable[Path]:
    for dirpath, _dirs, filenames in os.walk(root):
        for name in filenames:
            p = Path(dirpath) / name
            rel = str(p.relative_to(root))
            if includes and not any(fnmatch(rel, pat) for pat in includes):
                continue
            if excludes and any(fnmatch(rel, pat) for pat in excludes):
                continue
            yield p


def inventory_one(path: Path, root: Path) -> dict:
    try:
        st = path.stat()
    except OSError as e:
        return {"path": str(path), "error": f"stat failed: {e}"}

    row = {
        "relative_path": str(path.relative_to(root)),
        "name":          path.name,
        "size_bytes":    st.st_size,
        "modified_utc":  _ts(st.st_mtime),
        "path":          str(path),
    }
    try:
        row.update(hash_all(path))
    except (OSError, PermissionError) as e:
        row["error"] = f"hash failed: {e}"
    return row


CSV_FIELDS = [
    "relative_path", "name", "size_bytes", "modified_utc",
    "sha256", "md5", "sha1",
    "detected_type", "ext_match",
    "path", "error",
]


def write_csv(rows: List[dict], out_path: Path) -> None:
    with out_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def verify(manifest_path: Path, root: Path) -> int:
    """Re-hash the folder and diff against an existing manifest CSV."""
    expected = {}
    with manifest_path.open() as f:
        for r in csv.DictReader(f):
            expected[r["relative_path"]] = r

    changed = []
    added = []
    seen = set()

    for p in walk_files(root):
        rel = str(p.relative_to(root))
        seen.add(rel)
        exp = expected.get(rel)
        if exp is None:
            added.append(rel)
            continue
        try:
            digests = hash_all(p)
        except OSError as e:
            changed.append((rel, f"hash failed: {e}"))
            continue
        if digests["sha256"] != exp.get("sha256"):
            changed.append((rel, "sha256 differs"))

    removed = sorted(rel for rel in expected if rel not in seen)

    print("== verification report ==")
    print(f"manifest: {manifest_path}")
    print(f"root:     {root}")
    print(f"changed:  {len(changed)}   added: {len(added)}   removed: {len(removed)}")
    for rel, why in changed:
        print(f"  [CHANGED] {rel}   ({why})")
    for rel in sorted(added):
        print(f"  [ADDED]   {rel}")
    for rel in removed:
        print(f"  [REMOVED] {rel}")

    return 0 if not (changed or added or removed) else 1


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="folder-hasher",
        description="Build a forensic file manifest, or verify a folder against one.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    hp = sub.add_parser("hash", help="Build a manifest of the given folder.")
    hp.add_argument("path", type=Path, help="Folder to inventory")
    hp.add_argument("-o", "--output", type=Path, default=Path("manifest.csv"),
                    help="Output CSV file (default: manifest.csv)")
    hp.add_argument("--quiet", action="store_true",
                    help="Don't print per-file progress on stderr")
    hp.add_argument("--include", action="append", default=[], metavar="GLOB",
                    help="Only include files matching this glob (can be passed multiple times)")
    hp.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="Exclude files matching this glob (can be passed multiple times)")

    vp = sub.add_parser("verify", help="Verify a folder against an existing manifest.")
    vp.add_argument("path", type=Path, help="Folder to verify")
    vp.add_argument("manifest", type=Path, help="Existing manifest CSV")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.cmd == "verify":
        if not args.path.is_dir():
            print(f"error: {args.path} is not a directory", file=sys.stderr)
            return 2
        return verify(args.manifest, args.path)

    # default: hash
    root: Path = args.path
    if not root.exists() or not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    rows: List[dict] = []
    for i, p in enumerate(walk_files(root, includes=args.include, excludes=args.exclude), 1):
        rows.append(inventory_one(p, root))
        if not args.quiet:
            print(f"[{i:>5}] {p.relative_to(root)}", file=sys.stderr)

    write_csv(rows, args.output)
    mismatches = sum(1 for r in rows if r.get("ext_match") == "mismatch")
    print(f"done — {len(rows)} files inventoried, manifest written to {args.output}")
    if mismatches:
        print(f"!! {mismatches} files with extension/content mismatches — worth investigating")
    return 0


if __name__ == "__main__":
    sys.exit(main())
