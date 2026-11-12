"""Tests for exact BLC1 archive composition accounting."""

from __future__ import annotations

import struct

import pytest

from bincompress.codec import Method, _compress_x86_multiplexed
from bincompress.exceptions import FormatError
from bincompress.profiler import _profile_streams, profile_archive


def test_profile_accounts_for_every_archive_byte() -> None:
    """Global framing and segment contributions sum to the complete archive."""

    source = bytes(range(256)) * 64 + b"profile-data" * 1024
    profile = profile_archive(source)
    assert profile.original_size == len(source)
    assert (
        profile.global_header_size
        + sum(segment.stored_size for segment in profile.segments)
        == profile.archive_size
    )
    assert sum(segment.original_size for segment in profile.segments) == len(source)


def test_multiplex_profile_accounts_for_internal_streams() -> None:
    """Multiplexer metadata, skeleton, and constants cover its entire payload."""

    source = b"".join(
        b"\x48\x8b\x05" + value.to_bytes(4, "little") for value in range(1024)
    )
    payload = _compress_x86_multiplexed(source, 64, 9)
    streams = _profile_streams(Method.X86_MULTIPLEX_LZMA2, payload, len(source))
    assert [stream.name for stream in streams] == [
        "method-metadata",
        "instruction-skeleton",
        "typed-constants",
    ]
    assert sum(stream.stored_size for stream in streams) == len(payload)
    assert streams[1].original_size == len(source)
    assert streams[2].original_size > 0


def test_multiplex_profile_rejects_impossible_boundaries() -> None:
    """A hostile skeleton length cannot produce negative stream accounting."""

    source = b"\xe8\x01\x00\x00\x00" * 128
    payload = bytearray(_compress_x86_multiplexed(source, 64, 9))
    struct.pack_into(">Q", payload, 1, len(payload))
    with pytest.raises(FormatError, match="exceed"):
        _profile_streams(Method.X86_MULTIPLEX_LZMA2, bytes(payload), len(source))
