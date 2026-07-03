#!/usr/bin/env python3
"""Extract one JSON-RPC message by id from a framed LSP response stream (the LS's stdout).

The stream is a concatenation of `Content-Length: N\r\n\r\n<body>` frames. We parse frames by their
declared byte length (bodies contain braces, so a brace-matching regex is not safe), then print the
message whose top-level "id" equals the requested id. Prints nothing if not found.
"""
import json
import sys


def frames(data: bytes):
    i = 0
    marker = b"Content-Length:"
    while True:
        j = data.find(marker, i)
        if j < 0:
            return
        hdr_end = data.find(b"\r\n\r\n", j)
        sep = b"\r\n\r\n"
        if hdr_end < 0:
            hdr_end = data.find(b"\n\n", j)
            sep = b"\n\n"
            if hdr_end < 0:
                return
        try:
            n = int(data[j + len(marker):hdr_end].split(b"\r\n")[0].strip())
        except ValueError:
            i = hdr_end + len(sep)
            continue
        body_start = hdr_end + len(sep)
        body = data[body_start:body_start + n]
        i = body_start + n
        yield body


def main():
    path, want = sys.argv[1], sys.argv[2]
    try:
        want_id = int(want)
    except ValueError:
        want_id = want
    with open(path, "rb") as f:
        data = f.read()
    for body in frames(data):
        try:
            msg = json.loads(body.decode("utf-8", "replace"))
        except Exception:
            continue
        if isinstance(msg, dict) and msg.get("id") == want_id:
            print(json.dumps(msg))
            return


if __name__ == "__main__":
    main()
