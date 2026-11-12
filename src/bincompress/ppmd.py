"""Bounded PPMd Variant H adapter for instruction-skeleton streams."""

from __future__ import annotations

import pyppmd

from bincompress.exceptions import FormatError, IntegrityError

MEMORY_SIZE = 256 << 20
_TERMINATOR = b"\xf0BLC1PPM"
_ORDERS = (8, 16, 20, 24, 32)


def compress(data: bytes) -> bytes:
    """Compress one byte stream with the fixed BLC1 PPMd model.

    Args:
        data: Bytes to encode.

    Returns:
        Raw PPMd Variant H payload with an end marker.
    """

    framed = data + _TERMINATOR
    candidates: list[tuple[int, bytes]] = []
    for order in _ORDERS:
        encoder = pyppmd.Ppmd7Encoder(order, MEMORY_SIZE)
        payload = encoder.encode(framed) + encoder.flush()
        candidates.append((order, payload))
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
    try:
        decoder = pyppmd.Ppmd7Decoder(order, MEMORY_SIZE)
        framed_size = expected_size + len(_TERMINATOR)
        result = decoder.decode(payload[1:], framed_size)
        if len(result) < framed_size and decoder.needs_input:
            result += decoder.decode(b"\0", framed_size - len(result))
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
