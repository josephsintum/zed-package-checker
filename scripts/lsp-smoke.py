#!/usr/bin/env python3
"""Drive the language server over stdio and report what it publishes.

This is the cheap version of the Zed gate: it speaks enough LSP to prove the
server initializes, negotiates an encoding and pushes diagnostics, without
needing the editor in the loop. Zed is still the real test — this just catches
protocol mistakes in a second rather than a rebuild-reinstall cycle.

    scripts/lsp-smoke.py [--binary PATH] [--root DIR]

Exits non-zero if the handshake fails or no diagnostics arrive.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import select
import subprocess
import sys
import threading
import time

DEFAULT_BINARY = "server/dist/package-checker-lsp"


def frame(payload: dict) -> bytes:
    """Encode one JSON-RPC message with LSP's Content-Length framing."""
    body = json.dumps(payload).encode()
    return b"Content-Length: %d\r\n\r\n%s" % (len(body), body)


def readable(stream, timeout: float) -> bool:
    """Report whether stream has data, so a quiet server does not hang us."""
    return bool(select.select([stream], [], [], timeout)[0])


def read_message(stream) -> dict | None:
    """Read one Content-Length framed message, or None at clean EOF."""
    length = None
    while True:
        line = stream.readline()
        if not line:
            return None
        line = line.strip()
        if not line:
            break  # blank line ends the header block
        name, _, value = line.decode().partition(":")
        if name.strip().lower() == "content-length":
            length = int(value.strip())
    if length is None:
        return None
    return json.loads(stream.read(length))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=DEFAULT_BINARY)
    ap.add_argument("--root", default="server/testdata/fixtures/npm-direct")
    ap.add_argument("--timeout", type=float, default=120.0,
                    help="seconds to wait for diagnostics")
    ap.add_argument("--expect", type=int, default=1,
                    help="stop after this many publishes")
    args = ap.parse_args()

    root = pathlib.Path(args.root).resolve()
    if not root.is_dir():
        print(f"root does not exist: {root}", file=sys.stderr)
        return 2

    proc = subprocess.Popen(
        [args.binary, "--stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Drain stderr concurrently so the server's logs are visible and a full
    # pipe buffer can never deadlock the handshake.
    def drain_stderr() -> None:
        for line in proc.stderr:
            sys.stderr.write("  [server] " + line.decode(errors="replace"))

    threading.Thread(target=drain_stderr, daemon=True).start()

    proc.stdin.write(frame({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": None,
            "rootUri": root.as_uri(),
            "workspaceFolders": [{"uri": root.as_uri(), "name": root.name}],
            # Claim UTF-8 support so the encoding negotiation is exercised.
            "capabilities": {"general": {"positionEncodings": ["utf-8", "utf-16"]}},
        },
    }))
    proc.stdin.flush()

    init_result = read_message(proc.stdout)
    if not init_result or "result" not in init_result:
        print(f"initialize failed: {init_result}", file=sys.stderr)
        proc.kill()
        return 1

    caps = init_result["result"]["capabilities"]
    print(f"  positionEncoding : {caps.get('positionEncoding')}")
    print(f"  serverInfo       : {init_result['result'].get('serverInfo')}")

    proc.stdin.write(frame({"jsonrpc": "2.0", "method": "initialized", "params": {}}))
    proc.stdin.flush()

    # Collect notifications until diagnostics arrive or the server goes quiet.
    #
    # Server-to-client requests must be answered: the server registers file
    # watchers this way, and a real client always replies. Ignoring them wedges
    # anything the server does afterwards.
    published = []
    deadline = time.time() + args.timeout
    while time.time() < deadline:
        if not readable(proc.stdout, 0.5):
            if published:
                break  # the server has gone quiet and we have what we came for
            continue
        msg = read_message(proc.stdout)
        if msg is None:
            break
        if "id" in msg and "method" in msg:
            proc.stdin.write(frame({"jsonrpc": "2.0", "id": msg["id"], "result": None}))
            proc.stdin.flush()
            continue
        if msg.get("method") == "textDocument/publishDiagnostics":
            published.append(msg["params"])
            if len(published) >= args.expect:
                break

    proc.stdin.write(frame({"jsonrpc": "2.0", "id": 2, "method": "shutdown"}))
    proc.stdin.flush()
    read_message(proc.stdout)
    proc.stdin.write(frame({"jsonrpc": "2.0", "method": "exit", "params": {}}))
    proc.stdin.flush()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    if not published:
        print("\nFAIL: no diagnostics published", file=sys.stderr)
        return 1

    for params in published:
        print(f"\n  published for {params['uri']}")
        for d in params["diagnostics"]:
            start = d["range"]["start"]
            print(f"    [{start['line']}:{start['character']}] "
                  f"severity={d.get('severity')} code={d.get('code')} "
                  f"source={d.get('source')}")
            print(f"    {d['message']}")
    print("\nPASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
