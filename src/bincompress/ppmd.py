"""Bounded PPMd Variant H adapter for instruction-skeleton streams."""

from __future__ import annotations

import subprocess
import sys

import pyppmd

from bincompress.exceptions import FormatError, IntegrityError

MEMORY_SIZE = 256 << 20
_TERMINATOR = b"\xf0BLC1PPM"
_ORDERS = (8, 16, 20, 24, 32)


def _encode_candidate(order: int, framed: bytes) -> bytes | None:
    """Encode and verify one order candidate in an isolated subprocess.

    pyppmd is not safe to exercise exhaustively in-process: single-shot
    ``encode()`` mis-encodes inputs above roughly 4 MiB, repeated creation
    of large-model coders can crash the interpreter outright, and some
    order/data combinations silently produce undecodable streams (observed
    at order 16 and order 32 on real instruction skeletons). The worker
    therefore feeds the encoder in bounded chunks, verifies the payload by
    a full decode, and reports the payload only when it round-trips; a
    crash or corruption kills or fails only the worker, never the encoder.

    Args:
        order: PPMd model order to evaluate.
        framed: Input bytes including the stream terminator.

    Returns:
        The verified payload, or None when the candidate fails or crashes.
    """

    completed = subprocess.run(  # noqa: S603 - fixed interpreter and module
        [sys.executable, "-m", "bincompress._ppmd_worker", str(order)],
        input=framed,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout


def compress(data: bytes) -> bytes:
    """Compress one byte stream with the fixed BLC1 PPMd model.

    Args:
        data: Bytes to encode.

    Raises:
        FormatError: If no PPMd order produced a verifiable stream.

    Returns:
        Raw PPMd Variant H payload with an end marker.
    """

    framed = data + _TERMINATOR
    candidates: list[tuple[int, bytes]] = []
    for order in _ORDERS:
        payload = _encode_candidate(order, framed)
        if payload is not None:
            candidates.append((order, payload))
    if not candidates:
        raise FormatError("no PPMd order produced a verifiable stream")
    order, payload = min(candidates, key=lambda candidate: len(candidate[1]))
    return bytes((order,)) + payload


def decompress(payload: bytes, expected_size: int) -> bytes:
    """Decode a PPMd payload with an exact output bound.

    Args:
        payload: Raw PPMd Variant H payload.
        expected_size: Required uncompressed byte count.

    Raises:
        FormatError: If the stream is malformed, truncated, or has trailing data.
        IntegrityError: If the decoded size differs from ``expected_size``.

    Returns:
        Exact reconstructed bytes.
    """

    if expected_size < 0:
        raise FormatError("negative PPMd output size")
    if not payload:
        raise FormatError("PPMd header is truncated")
    order = payload[0]
    if order not in _ORDERS:
        raise FormatError("unsupported PPMd order")
    decoder = pyppmd.Ppmd7Decoder(order, MEMORY_SIZE)
    framed_size = expected_size + len(_TERMINATOR)
    # Single-shot decode with an exact output bound: chunked decode() calls
    # corrupt state when max_length truncates output mid-symbol (pyppmd
    # false-eof after ~2-3 MiB), so the payload is decoded in one call.
    try:
        result = decoder.decode(payload[1:], framed_size)
    except (RuntimeError, ValueError) as error:
        raise FormatError("invalid PPMd stream") from error
    if len(result) != framed_size:
        raise IntegrityError("decoded PPMd size does not match")
    if not decoder.eof:
        raise FormatError("PPMd stream exceeds the declared size or is truncated")
    if decoder.unused_data:
        raise FormatError("PPMd stream has trailing data")
    if not result.endswith(_TERMINATOR):
        raise FormatError("PPMd stream terminator does not match")
    return result[:expected_size]
