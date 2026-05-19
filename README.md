# folder-hasher

A small CLI tool that walks a folder, computes a SHA256 for every file, and
writes a CSV manifest. Useful for snapshotting the contents of a directory so
you can verify later that nothing changed.

Pure Python standard library — no external dependencies.
Tested on Python 3.8+.

## Usage

```bash
python3 folder_hasher.py ./my_evidence -o manifest.csv
```

The tool walks the folder recursively, computes the SHA256 of every file, and
writes a CSV with one row per file (path, size, modified time, hash).

## License

MIT — see `LICENSE`.
