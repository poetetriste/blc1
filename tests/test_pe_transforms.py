"""Tests for reversible PE metadata transforms."""

from __future__ import annotations

import struct

import pytest

from bincompress.pe_transforms import (
    decode_pdata,
    decode_relocations,
    encode_pdata,
    encode_relocations,
    relocation_pointer_offsets,
)


def test_pdata_round_trip_with_padding() -> None:
    """Runtime-function columns and non-record tail bytes round-trip exactly."""

    records = b"".join(
        struct.pack("<III", start, start + 0x20, 0x8000 + index * 8)
        for index, start in enumerate(range(0x1000, 0x1400, 0x20))
    )
    source = records + b"PAD"
    transformed = encode_pdata(source)
    assert len(transformed) == len(source)
    assert decode_pdata(transformed) == source


def test_relocations_round_trip_with_zero_padding() -> None:
    """Relocation pages, offsets, types, and section padding round-trip exactly."""

    first_entries = (0xA010, 0xA018, 0xA120, 0x0000)
    second_entries = (0xA004, 0xA204)
    source = bytearray(struct.pack("<II", 0x1000, 8 + len(first_entries) * 2))
    source.extend(struct.pack("<" + "H" * len(first_entries), *first_entries))
    source.extend(struct.pack("<II", 0x3000, 8 + len(second_entries) * 2))
    source.extend(struct.pack("<" + "H" * len(second_entries), *second_entries))
    source.extend(b"\0" * 32)

    transformed = encode_relocations(bytes(source))
    assert transformed is not None
    assert len(transformed) == len(source) + 4
    assert decode_relocations(transformed, len(source)) == bytes(source)


def test_malformed_relocation_block_is_not_transformed() -> None:
    """Out-of-bounds block sizes reject the specialized encoder path."""

    source = struct.pack("<II", 0x1000, 0x1000)
    assert encode_relocations(source) is None


def test_relocation_decoder_rejects_invalid_block_size() -> None:
    """Hostile transformed block metadata cannot overrun the stream."""

    source = struct.pack("<I", 1) + struct.pack("<I", 0x1000)
    source += struct.pack("<I", 7) + b"\0" * 8
    with pytest.raises(ValueError, match="block size"):
        decode_relocations(source, len(source) - 4)


def test_relocations_locate_pointers_inside_target_section() -> None:
    """Only matching relocation types and target-section RVAs become offsets."""

    entries = (0xA010, 0xA120, 0x3018, 0x0000)
    source = struct.pack("<II", 0x2000, 8 + len(entries) * 2)
    source += struct.pack("<" + "H" * len(entries), *entries)
    source += b"\0" * 16
    assert relocation_pointer_offsets(source, 0x2000, 0x100, 8) == (0x10,)
    assert relocation_pointer_offsets(source, 0x2000, 0x100, 4) == (0x18,)


def test_relocation_pointer_scan_rejects_malformed_blocks() -> None:
    """Pointer extraction does not trust relocation block lengths."""

    source = struct.pack("<II", 0x2000, 0x1000)
    assert relocation_pointer_offsets(source, 0x2000, 0x100, 8) is None
