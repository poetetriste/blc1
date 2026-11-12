"""Tests for the BLC1 container."""

from __future__ import annotations

import struct

import pytest

from bincompress.codec import (
    Method,
    _compress_pointer_section,
    _compress_tuned_lzma,
    _compress_x86_instructions,
    _compress_x86_multiplexed,
    _ConstantTransform,
    _decompress_pointer_section,
    _decompress_with,
    _decompress_x86_instructions,
    _decompress_x86_multiplexed,
    _inverse_transform_words,
    _transform_words,
    compress,
    decompress,
)
from bincompress.exceptions import FormatError, IntegrityError


def test_round_trip_arbitrary_binary() -> None:
    """Arbitrary bytes round-trip exactly."""

    source = bytes(range(256)) * 32 + b"\0" * 4096
    assert decompress(compress(source)) == source


def test_round_trip_empty_input() -> None:
    """An empty input remains representable."""

    assert decompress(compress(b"")) == b""


def test_round_trip_low_preset() -> None:
    """The archive records the raw-LZMA settings required for decoding."""

    source = b"repeated binary payload" * 1000
    assert decompress(compress(source, preset=0)) == source


def test_invalid_preset_is_rejected() -> None:
    """Invalid compression presets fail before encoding."""

    with pytest.raises(ValueError, match="preset"):
        compress(b"data", preset=10)


def test_truncated_archive_is_rejected() -> None:
    """Every truncation of a non-empty payload is rejected."""

    archive = compress(b"abc" * 1000)
    with pytest.raises(FormatError):
        decompress(archive[:-1])


def test_trailing_bytes_are_rejected() -> None:
    """Unframed bytes after the final segment are rejected."""

    with pytest.raises(FormatError, match="trailing"):
        decompress(compress(b"abc") + b"x")


def test_digest_mismatch_is_rejected() -> None:
    """Tampering with a raw payload is detected by SHA-256."""

    archive = bytearray(compress(b"abc"))
    archive[-1] ^= 1
    with pytest.raises(IntegrityError, match="SHA-256"):
        decompress(bytes(archive))


def test_excessive_segment_count_is_rejected() -> None:
    """A hostile segment count cannot trigger an unbounded loop."""

    archive = bytearray(compress(b""))
    struct.pack_into(">I", archive, 44, 5000)
    with pytest.raises(FormatError, match="too many"):
        decompress(bytes(archive))


def test_declared_segment_size_cannot_exceed_file_size() -> None:
    """Declared sizes bound decompression before a payload is expanded."""

    archive = bytearray(compress(b"abc" * 1000))
    original_size = struct.unpack_from(">Q", archive, 4)[0]
    first_segment_size_offset = 48 + 4
    struct.pack_into(">Q", archive, first_segment_size_offset, original_size + 1)
    with pytest.raises(FormatError, match="exceed"):
        decompress(bytes(archive))


def test_structured_x86_payload_round_trips() -> None:
    """The framed semantic instruction method restores exact section bytes."""

    source = b"".join(
        b"\x48\x8b\x05" + value.to_bytes(4, "little") for value in range(2048)
    )
    payload = _compress_x86_instructions(source, 64, 9)
    assert _decompress_x86_instructions(payload, 9, len(source)) == source


def test_structured_x86_payload_rejects_invalid_settings() -> None:
    """A hostile decoder mode in semantic metadata is rejected before expansion."""

    source = b"\xe8\x01\x00\x00\x00" * 128
    payload = bytearray(_compress_x86_instructions(source, 64, 9))
    payload[0] = 16
    with pytest.raises(FormatError, match="settings"):
        _decompress_x86_instructions(bytes(payload), 9, len(source))


def test_structured_x86_payload_rejects_truncation() -> None:
    """A truncated semantic payload cannot decode partially."""

    source = b"\xe8\x01\x00\x00\x00" * 128
    payload = _compress_x86_instructions(source, 64, 9)
    with pytest.raises(FormatError, match="truncated"):
        _decompress_x86_instructions(payload[:-1], 9, len(source))


def test_multiplexed_x86_payload_round_trips() -> None:
    """Independent skeleton and constant blocks restore exact section bytes."""

    source = b"".join(
        b"\x48\x8b\x05" + (value * 17).to_bytes(4, "little") for value in range(2048)
    )
    payload = _compress_x86_multiplexed(source, 64, 9)
    assert _decompress_x86_multiplexed(payload, 9, len(source)) == source


def test_ppmd_multiplexed_x86_payload_round_trips() -> None:
    """PPMd skeletons and LZMA constants restore exact section bytes."""

    source = b"".join(
        b"\x48\x8b\x05" + (value * 17).to_bytes(4, "little") for value in range(2048)
    )
    payload = _compress_x86_multiplexed(source, 64, 9, ppmd_skeleton=True)

    assert (
        _decompress_x86_multiplexed(payload, 9, len(source), ppmd_skeleton=True)
        == source
    )


def test_multiplexed_x86_payload_rejects_invalid_transform() -> None:
    """Unknown constant transforms are rejected during stream routing."""

    source = b"\xe8\x01\x00\x00\x00" * 128
    payload = bytearray(_compress_x86_multiplexed(source, 64, 9))
    payload[137 + 2] = 255
    with pytest.raises(FormatError, match="multiplex"):
        _decompress_x86_multiplexed(bytes(payload), 9, len(source))


def test_multiplexed_x86_payload_rejects_truncation() -> None:
    """A truncated second multiplexed block cannot decode partially."""

    source = b"\xe8\x01\x00\x00\x00" * 128
    payload = _compress_x86_multiplexed(source, 64, 9)
    with pytest.raises(FormatError, match="truncated"):
        _decompress_x86_multiplexed(payload[:-1], 9, len(source))


@pytest.mark.parametrize("width", [1, 2, 4, 8])
@pytest.mark.parametrize("transform", list(_ConstantTransform))
def test_constant_transforms_are_reversible(
    width: int, transform: _ConstantTransform
) -> None:
    """Every multiplexed constant transform is byte-exact at every width."""

    mask = (1 << (width * 8)) - 1
    source = b"".join(
        (((index * 257) ^ (index << 4)) & mask).to_bytes(width, "little")
        for index in range(257)
    )
    transformed = _transform_words(source, width, transform)
    assert len(transformed) == len(source)
    assert _inverse_transform_words(transformed, width, transform) == source


@pytest.mark.parametrize(
    ("pointer_width", "image_base"), [(4, 0x400000), (8, 0x140000000)]
)
def test_pointer_section_round_trips(pointer_width: int, image_base: int) -> None:
    """Relocation-selected pointers and their surrounding bytes restore exactly."""

    source = bytearray((index * 37) & 0xFF for index in range(4096))
    offsets = tuple(range(0, len(source) - pointer_width, 24))
    mask = (1 << (pointer_width * 8)) - 1
    for index, offset in enumerate(offsets):
        pointer = (image_base + 0x1000 + index * 16) & mask
        source[offset : offset + pointer_width] = pointer.to_bytes(
            pointer_width, "little"
        )
    payload = _compress_pointer_section(
        bytes(source), offsets, pointer_width, image_base, 9
    )
    assert _decompress_pointer_section(payload, 9, len(source)) == bytes(source)


def test_pointer_section_rejects_invalid_count() -> None:
    """Hostile pointer counts are rejected before stream expansion."""

    source = (0x140001000).to_bytes(8, "little") + b"x" * 64
    payload = bytearray(_compress_pointer_section(source, (0,), 8, 0x140000000, 9))
    struct.pack_into(">Q", payload, 9, len(source))
    with pytest.raises(FormatError, match="count"):
        _decompress_pointer_section(bytes(payload), 9, len(source))


def test_transposed_word_section_round_trips() -> None:
    """Two-byte planes restore mixed UTF-16 and binary bytes exactly."""

    source = "Structured UTF-16 resources".encode("utf-16le") + bytes(range(64))
    transformed = _transform_words(source, 2, _ConstantTransform.TRANSPOSE)
    payload = _compress_tuned_lzma(transformed, 9)
    assert _decompress_with(Method.TRANSPOSE2_LZMA2, payload, 9, len(source)) == source


def test_transposed_word_section_rejects_odd_size() -> None:
    """Malformed odd-sized word streams are rejected before decompression."""

    with pytest.raises(FormatError, match="odd"):
        _decompress_with(Method.TRANSPOSE2_LZMA2, b"", 9, 3)
