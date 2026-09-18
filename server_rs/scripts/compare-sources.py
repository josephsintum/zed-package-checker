#!/usr/bin/env python3
"""Diff what one server publishes from each of its two advisory sources.

The archive holds every advisory for every package; the API path fetches only
the ones this project's dependencies need. They are meant to be
indistinguishable from the outside, and this is what says so: same binary, same
fixtures, one run against a populated archive and one against an empty cache
that forces the network path.

Requires the real archive to be present — run `dbcheck --fetch` first.
"""

import importlib.util
import pathlib
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]

spec = importlib.util.spec_from_file_location("harness", HERE / "compare-servers.py")
harness = importlib.util.module_from_spec(spec)
sys.modules["harness"] = harness
spec.loader.exec_module(harness)

RUST = ROOT / "server_rs" / "target" / "release" / "package-checker-lsp"
FIXTURES = ROOT / "server" / "testdata" / "fixtures"
ARCHIVE_DB = pathlib.Path.home() / "Library" / "Caches" / "zed-package-checker" / "db"


def main() -> int:
    if not ARCHIVE_DB.is_dir():
        print(f"no advisory archive at {ARCHIVE_DB}; run dbcheck --fetch first")
        return 2

    failures = 0
    for fixture in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        archive = harness.publish(RUST, fixture, ARCHIVE_DB)
        # A fresh directory every time: a warm API cache would prove nothing.
        with tempfile.TemporaryDirectory() as empty:
            api = harness.publish(RUST, fixture, empty)

        print(f"== {fixture.name}")
        for path in sorted(set(archive) | set(api)):
            if archive.get(path) == api.get(path):
                print(f"   {path}: identical ({len(archive.get(path, []))} diagnostics)")
                continue
            failures += 1
            print(f"   {path}: DIFFERS")
            print("     archive:")
            print(harness.show(archive.get(path)))
            print("     api:")
            print(harness.show(api.get(path)))

    print("\nFAIL" if failures else "\nAGREE — both sources produce identical diagnostics")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
