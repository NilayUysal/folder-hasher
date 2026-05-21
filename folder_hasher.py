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
from pathlib import Path
from typing import Iterable, List, Optional


CHUNK = 1024 * 1024  # 1 MiB read buffer


def hash_all(path: Path) -> dict:
    """Stream the file once and return md5, sha1, sha256 digests as a dict."""
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5":    md5.hexdigest(),
        "sha1":   sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def _ts(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def walk_files(root: Path) -> Iterable[Path]:
    for dirpath, _dirs, filenames in os.walk(root):
        for name in filenames:
            yield Path(dirpath) / name


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
    "sha256", "md5", "sha1", "path", "error",
]


def write_csv(rows: List[dict], out_path: Path) -> None:
    with out_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="folder-hasher",
        description="Walk a folder and write a SHA256 manifest as CSV.",
    )
    p.add_argument("path", type=Path, help="Folder to inventory")
    p.add_argument("-o", "--output", type=Path, default=Path("manifest.csv"),
                   help="Output CSV file (default: manifest.csv)")
    p.add_argument("--quiet", action="store_true",
                   help="Don't print per-file progress on stderr")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    root: Path = args.path
    if not root.exists() or not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2

    rows: List[dict] = []
    for i, p in enumerate(walk_files(root), 1):
        rows.append(inventory_one(p, root))
        if not args.quiet:
            print(f"[{i:>5}] {p.relative_to(root)}", file=sys.stderr)

    write_csv(rows, args.output)
    print(f"done — {len(rows)} files inventoried, manifest written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
