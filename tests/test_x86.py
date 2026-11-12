"""Tests for reversible x86 stream transforms."""

from __future__ import annotations

import random
import struct
from dataclasses import replace

import pytest

from bincompress.x86 import (
    BranchStreams,
    merge_instruction_constants,
    merge_relative_branches,
    split_instruction_constants,
    split_relative_branches,
)


@pytest.mark.parametrize(
    "source",
    [
        b"",
        b"\xe8\x01\x00\x00\x00",
        b"\xe9\xfb\xff\xff\xff",
        b"\x0f\x84\x10\x00\x00\x00",
        b"prefix\xe8\x10\x20\x30\x40suffix\x0f\x8f\xff\xff\xff\xff",
        b"truncated\xe8\x01\x02\x03",
    ],
)
def test_branch_streams_round_trip(source: bytes) -> None:
    """Supported, mixed, and truncated patterns round-trip exactly."""

    streams = split_relative_branches(source)
    assert merge_relative_branches(streams, len(source)) == source


def test_branch_targets_are_normalized_to_absolute_offsets() -> None:
    """Relative operands become absolute section-local target offsets."""

    source = b"xx\xe8" + struct.pack("<i", -2)
    streams = split_relative_branches(source)
    assert streams.count == 1
    assert streams.skeleton == b"xx\xe8"
    assert struct.unpack("<I", streams.targets)[0] == 5


def test_deterministic_random_data_round_trips() -> None:
    """Random byte streams remain byte-exact despite false opcode matches."""

    random_source = random.Random(20261111)  # noqa: S311 - deterministic test data
    for size in range(512):
        source = random_source.randbytes(size)
        streams = split_relative_branches(source)
        assert merge_relative_branches(streams, size) == source


def test_inconsistent_target_count_is_rejected() -> None:
    """Malformed side-stream metadata cannot produce partial output."""

    with pytest.raises(ValueError, match="target stream size"):
        merge_relative_branches(BranchStreams(b"\xe8", b"", 1), 5)


@pytest.mark.parametrize("bitness", [32, 64])
def test_instruction_streams_round_trip_code_and_random_bytes(bitness: int) -> None:
    """Typed x86 constants round-trip valid code and arbitrary trailing data."""

    random_source = random.Random(20261112 + bitness)  # noqa: S311 - test data
    source = (
        b"\x8b\x45\xfc"
        b"\x83\xc0\x7f"
        b"\xe8\x10\x00\x00\x00"
        b"\x0f\x84\xf0\xff\xff\xff" + random_source.randbytes(4096)
    )
    streams = split_instruction_constants(source, bitness)
    assert merge_instruction_constants(streams) == source


def test_instruction_streams_restore_rip_relative_addresses() -> None:
    """RIP-relative memory operands are normalized and restored exactly."""

    source = b"\x48\x8b\x05\x78\x56\x34\x12"
    streams = split_instruction_constants(source, 64)
    assert any(streams.constants)
    assert merge_instruction_constants(streams) == source


def test_instruction_streams_reject_truncated_values() -> None:
    """A missing typed constant cannot silently corrupt reconstructed code."""

    streams = split_instruction_constants(b"\x83\xc0\x7f", 64)
    damaged_constants = tuple(b"" for _ in streams.constants)
    damaged = replace(streams, constants=damaged_constants)
    with pytest.raises(ValueError, match="truncated"):
        merge_instruction_constants(damaged)
