"""Tests for defensive PE segmentation."""

from __future__ import annotations

import struct

import pytest

from bincompress.codec import compress, decompress
from bincompress.exceptions import FormatError
from bincompress.pe import parse_pe_segments


def _synthetic_pe() -> bytes:
    """Build a small PE-like fixture with two raw sections.

    Returns:
        Synthetic PE bytes.
    """

    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<H", data, coff, 0x8664)
    struct.pack_into("<H", data, coff + 2, 2)
    struct.pack_into("<H", data, coff + 16, 0xF0)
    struct.pack_into("<H", data, coff + 20, 0x20B)
    struct.pack_into("<Q", data, coff + 20 + 24, 0x140000000)
    table = coff + 20 + 0xF0

    data[table : table + 8] = b".text\0\0\0"
    struct.pack_into("<I", data, table + 12, 0x1000)
    struct.pack_into("<II", data, table + 16, 0x200, 0x200)
    struct.pack_into("<I", data, table + 36, 0x60000020)

    second = table + 40
    data[second : second + 8] = b".data\0\0\0"
    struct.pack_into("<I", data, second + 12, 0x2000)
    struct.pack_into("<II", data, second + 16, 0x100, 0x400)
    struct.pack_into("<I", data, second + 36, 0xC0000040)

    data[0x200:0x400] = (b"\xe8\x10\x00\x00\x00" * 103)[:0x200]
    data[0x400:0x500] = b"data" * 64
    data[0x500:0x600] = b"overlay".ljust(0x100, b"\0")
    return bytes(data)


def test_segments_cover_pe_without_gaps_or_overlap() -> None:
    """Parsed segments concatenate to the original byte stream."""

    source = _synthetic_pe()
    segments = parse_pe_segments(source)
    restored = b"".join(
        source[segment.offset : segment.offset + segment.size] for segment in segments
    )
    assert restored == source
    assert any(segment.name == ".text" and segment.executable for segment in segments)
    assert any(
        segment.name == ".text" and segment.x86_bitness == 64 for segment in segments
    )
    assert any(
        segment.name == ".data" and not segment.executable for segment in segments
    )
    assert any(
        segment.name == ".text"
        and segment.virtual_address == 0x1000
        and segment.image_base == 0x140000000
        for segment in segments
    )


def test_non_pe_is_rejected_by_parser() -> None:
    """The specialized parser does not guess on arbitrary bytes."""

    with pytest.raises(FormatError, match="not a PE"):
        parse_pe_segments(b"not a pe")


def test_out_of_bounds_section_is_rejected() -> None:
    """A section that extends beyond the file is invalid."""

    source = bytearray(_synthetic_pe())
    table = 0x84 + 20 + 0xF0
    struct.pack_into("<II", source, table + 16, 0x1000, 0x200)
    with pytest.raises(FormatError, match="outside"):
        parse_pe_segments(bytes(source))


def test_overlapping_sections_are_rejected() -> None:
    """Overlapping raw sections do not produce ambiguous reconstruction."""

    source = bytearray(_synthetic_pe())
    second = 0x84 + 20 + 0xF0 + 40
    struct.pack_into("<II", source, second + 16, 0x100, 0x300)
    with pytest.raises(FormatError, match="overlap"):
        parse_pe_segments(bytes(source))


def test_codec_round_trips_synthetic_pe() -> None:
    """The complete codec round-trips segmented PE data."""

    source = _synthetic_pe()
    assert decompress(compress(source)) == source
