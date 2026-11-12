"""Tests for the pinned native preflate-rs adapter."""

from __future__ import annotations

import zlib

import pytest

from bincompress.exceptions import FormatError
from bincompress.preflate import compress, decompress, is_available

pytestmark = pytest.mark.skipif(
    not is_available(), reason="pinned preflate-rs native library is unavailable"
)


def test_preflate_round_trips_embedded_zlib_stream() -> None:
    """A detected embedded stream recreates its complete surrounding bytes exactly."""

    plain = (b"structured resource pixels\0" * 16384) + bytes(range(256))
    source = b"resource-prefix" + zlib.compress(plain, level=9) + b"resource-suffix"
    payload = compress(source)
    assert decompress(payload, len(source)) == source


def test_preflate_round_trips_data_without_deflate() -> None:
    """The container remains lossless when no transformable stream is present."""

    source = bytes(range(256)) * 32
    assert decompress(compress(source), len(source)) == source


def test_preflate_rejects_malformed_payload() -> None:
    """Invalid native container bytes surface as a safe format error."""

    with pytest.raises(FormatError):
        decompress(b"not a preflate container", 1024)


def test_preflate_enforces_output_size() -> None:
    """The native decoder cannot expand beyond the declared segment size."""

    source = zlib.compress(b"bounded output" * 8192)
    payload = compress(source)
    with pytest.raises(FormatError):
        decompress(payload, len(source) - 1)
