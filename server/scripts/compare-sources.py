#!/usr/bin/env python3
"""Diff what the server publishes from each of its two advisory sources.

The archive holds every advisory for every package; the API path fetches only
the ones this project's dependencies need. They are meant to be
indistinguishable from the outside, and this is what says so: same binary, same
fixtures, one run against a populated archive and one against an empty cache
that forces the network path.

Drives the binary over stdio itself rather than reusing `scripts/lsp-smoke.py`,
which prints only the start of a range. Compared per diagnostic: the full range,
the severity, the code, and the message.

Requires the real archive to be present — run `dbcheck --fetch` first.
"""

import json
import pathlib
import subprocess
import sys
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parents[2]
SERVER = ROOT / "target" / "release" / "package-checker-lsp"
FIXTURES = ROOT / "server" / "testdata" / "fixtures"
ARCHIVE_DB = pathlib.Path.home() / "Library" / "Caches" / "zed-package-checker" / "db"
TIMEOUT = 180


def drain(stream, sink):
    for line in iter(stream.readline, b""):
        sink.append(line.decode("utf-8", "replace").rstrip())


def send(proc, payload):
    body = json.dumps(payload).encode()
    proc.stdin.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
    proc.stdin.flush()


def read_message(proc):
    length = None
    while True:
        line = proc.stdout.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            break
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":")[1])
    if length is None:
        return None
    return json.loads(proc.stdout.read(length))


def publish(binary, root, db_root=None):
    """Every diagnostic the server publishes for one fixture, keyed by file.

    `db_root` points the server at a specific advisory cache — an empty one
    exercises the cold path, which is how the archive and the API are told
    apart.
    """
    proc = subprocess.Popen(
        [str(binary), "--stdio"] + (["--db-root", str(db_root)] if db_root else []),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    errors = []
    threading.Thread(target=drain, args=(proc.stderr, errors), daemon=True).start()

    uri = root.as_uri()
    send(proc, {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "processId": None,
            "rootUri": uri,
            "workspaceFolders": [{"uri": uri, "name": root.name}],
            # Ask for utf-8 so the server emits byte columns and the comparison
            # is not measuring an encoding conversion.
            "capabilities": {"general": {"positionEncodings": ["utf-8", "utf-16"]}},
        },
    })

    out = {}
    timer = threading.Timer(TIMEOUT, proc.kill)
    timer.start()
    try:
        while True:
            message = read_message(proc)
            if message is None:
                break
            if message.get("id") == 1:
                send(proc, {"jsonrpc": "2.0", "method": "initialized", "params": {}})
                continue
            # Server-to-client requests must be answered, or progress and
            # watcher registration stall the server forever.
            if "id" in message and "method" in message:
                send(proc, {"jsonrpc": "2.0", "id": message["id"], "result": None})
                continue
            if message.get("method") == "textDocument/publishDiagnostics":
                params = message["params"]
                name = params["uri"].rsplit("/", 1)[-1]
                out[name] = sorted(
                    (
                        d["range"]["start"]["line"], d["range"]["start"]["character"],
                        d["range"]["end"]["line"], d["range"]["end"]["character"],
                        d.get("severity"), str(d.get("code")), d.get("message"),
                    )
                    for d in params["diagnostics"]
                )
                # One publish per file is enough; stop once the scan has landed.
                if len(out) >= 1:
                    break
    finally:
        timer.cancel()
        try:
            send(proc, {"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": None})
            send(proc, {"jsonrpc": "2.0", "method": "exit", "params": None})
        except (BrokenPipeError, OSError):
            pass
        proc.kill()
        proc.wait()
    return out


def show(entries):
    if entries is None:
        return "    (nothing published)"
    return "\n".join(
        f"    [{a}:{b}-{c}:{d}] severity={s} code={code}\n      {msg}"
        for a, b, c, d, s, code, msg in entries
    )


def main() -> int:
    if not ARCHIVE_DB.is_dir():
        print(f"no advisory archive at {ARCHIVE_DB}; run dbcheck --fetch first")
        return 2
    if not SERVER.is_file():
        print(f"no server binary at {SERVER}; run `make server` first")
        return 2

    failures = 0
    for fixture in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        archive = publish(SERVER, fixture, ARCHIVE_DB)
        # A fresh directory every time: a warm API cache would prove nothing.
        with tempfile.TemporaryDirectory() as empty:
            api = publish(SERVER, fixture, empty)

        print(f"== {fixture.name}")
        for path in sorted(set(archive) | set(api)):
            if archive.get(path) == api.get(path):
                print(f"   {path}: identical ({len(archive.get(path, []))} diagnostics)")
                continue
            failures += 1
            print(f"   {path}: DIFFERS")
            print("     archive:")
            print(show(archive.get(path)))
            print("     api:")
            print(show(api.get(path)))

    print("\nFAIL" if failures else "\nAGREE — both sources produce identical diagnostics")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
