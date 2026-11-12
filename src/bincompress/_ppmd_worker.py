"""Subprocess worker that encodes and verifies one PPMd order candidate.

Reads the framed input from stdin, encodes it with the order given on the
command line, verifies the payload by a full decode, and writes the payload
to stdout only when it round-trips exactly. Exit status is zero on success
and non-zero otherwise; a native crash in pyppmd kills only this worker.
"""

from __future__ import annotations

import sys

import pyppmd

MEMORY_SIZE = 256 << 20
_CHUNK = 1 << 20


def main() -> int:
    order = int(sys.argv[1])
    framed = sys.stdin.buffer.read()
    encoder = pyppmd.Ppmd7Encoder(order, MEMORY_SIZE)
    parts = [
        encoder.encode(framed[offset : offset + _CHUNK])
        for offset in range(0, len(framed), _CHUNK)
    ]
    parts.append(encoder.flush())
    payload = b"".join(parts)
    decoder = pyppmd.Ppmd7Decoder(order, MEMORY_SIZE)
    decoded = decoder.decode(payload, len(framed))
    if decoded != framed or not decoder.eof or decoder.unused_data:
        return 1
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
