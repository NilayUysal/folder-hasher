# folder-hasher

![tests](https://github.com/NilayUysal/folder-hasher/actions/workflows/test.yml/badge.svg)

A small CLI tool that walks a folder, computes a SHA256 for every file, and
writes a CSV manifest. Useful for snapshotting the contents of a directory so
you can verify later that nothing changed.
Also flags files whose extension doesn't match their actual content (e.g. a `.jpg` that's really a Windows binary).

Pure Python standard library — no external dependencies.
Tested on Python 3.8+.

## Background

I wrote about why I built this and what I learned along the way (in Turkish):
[Mührün altında ne var?](https://medium.com/@uysalnil94.nu/m%C3%BChr%C3%BCn-alt%C4%B1nda-ne-var-4c1645ba4ef2)

## Usage

Build a manifest of a folder:

```bash
python3 folder_hasher.py hash ./my_evidence -o manifest.csv
```

Verify a folder against an earlier manifest:

```bash
python3 folder_hasher.py verify ./my_evidence manifest.csv
```

The verify command exits `0` if everything matches and `1` if anything changed,
was added, or was removed — useful in CI or shell pipelines.

## Running tests

```bash
python3 -m pytest tests/
```

Changes between versions are tracked in [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see `LICENSE`.
