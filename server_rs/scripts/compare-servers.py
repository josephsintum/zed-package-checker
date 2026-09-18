#!/usr/bin/env python3
"""Diff what the two servers publish, over the fixtures they share.

Both are language servers, so the honest comparison is the wire output. This
drives each binary over stdio itself rather than reusing `scripts/lsp-smoke.py`,
which prints only the start of a range — and the end is exactly where the two
implementations were expected to differ.

Compared per diagnostic: the full range, the severity, the code, and the message.
"""

import json
import pathlib
import subprocess
import sys
import threading

ROOT = pathlib.Path(__file__).resolve().parents[2]
GO = ROOT / "server" / "dist" / "package-checker-lsp"
RUST = ROOT / "server_rs" / "target" / "release" / "package-checker-lsp"
FIXTURES = ROOT / "server" / "testdata" / "fixtures"
TIMEOUT = 180

# Known and intended differences in diagnostic *wording*, with the reason.
# Anything not listed fails.
#
# Scoped to the message on purpose. Range, severity and code are compared with
# no exceptions available, because every fixture below carries exactly one
# findings-bearing file: a whitelist that covered the whole file would cover
# every file the harness compares, and the gate could never fail again.
#
# Every entry is the Rust server ahead of the Go one, not a divergence the two
# disagree about; each is recorded in docs/CARRY-BACK.md for the Go server to
# take. The exact new wording is pinned by tests in src/diagnostics.rs, not here,
# because these strings carry version numbers that move with the archive.
VERIFIED_FIX = (
    "Rust names the lowest version clearing every advisory, checked back against "
    "the index; Go names the worst advisory's fix, which can leave the others "
    "unresolved. CARRY-BACK item 3."
)
LOCKFILE_CLAUSE = (
    "Rust says when a finding was resolved in a lockfile, so editing the manifest "
    "alone will not clear it. CARRY-BACK item 4."
)

EXPECTED: dict[tuple[str, str], str] = {
    # Both changes at once: a verified fix, and a lockfile-resolved version.
    ("npm-direct", "package.json"): f"{VERIFIED_FIX} {LOCKFILE_CLAUSE}",
    ("npm-range-vs-lock", "package.json"): LOCKFILE_CLAUSE,
    ("rust-cargo", "Cargo.toml"): LOCKFILE_CLAUSE,
    ("npm-nolock", "package.json"): VERIFIED_FIX,
    ("py-requirements", "requirements.txt"): VERIFIED_FIX,
    # Go suppresses "Fixed in" for a multi-advisory toolchain finding, because
    # the worst advisory's fix clears almost none of the other 75. A verified
    # fix does not have that problem, so Rust names one.
    ("go-mod", "go.mod"): VERIFIED_FIX,
}


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


def publish(binary, root):
    """Every diagnostic the server publishes for one fixture, keyed by file."""
    proc = subprocess.Popen(
        [str(binary), "--stdio"],
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
            # Ask for utf-8 so both servers emit byte columns and the comparison
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


def structure(entries):
    """Everything but the message: range, severity, code."""
    return None if entries is None else [e[:6] for e in entries]


def wording(entries):
    return None if entries is None else [e[6] for e in entries]


def show(entries):
    if entries is None:
        return "    (nothing published)"
    return "\n".join(
        f"    [{a}:{b}-{c}:{d}] severity={s} code={code}\n      {msg}"
        for a, b, c, d, s, code, msg in entries
    )


def main():
    failures = 0
    for fixture in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        go = publish(GO, fixture)
        rust = publish(RUST, fixture)
        print(f"== {fixture.name}")

        for path in sorted(set(go) | set(rust)):
            expected = EXPECTED.get((fixture.name, path))
            if go.get(path) == rust.get(path):
                print(f"   {path}: identical ({len(go.get(path, []))} diagnostics)")
                continue

            # Position, severity and code are not whitelistable. A difference
            # here is a real divergence however the messages read.
            if structure(go.get(path)) != structure(rust.get(path)):
                failures += 1
                label = "DIFFERS (range/severity/code)"
            elif expected:
                label = f"wording differs as expected — {expected}"
            else:
                failures += 1
                label = "DIFFERS (wording)"
            print(f"   {path}: {label}")
            print("     go:")
            print(show(go.get(path)))
            print("     rust:")
            print(show(rust.get(path)))

    if failures:
        print("\nFAIL")
    elif EXPECTED:
        print("\nAGREE on range, severity and code; wording differs only as listed")
    else:
        print("\nAGREE — every diagnostic identical")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
