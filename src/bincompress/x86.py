"""Reversible stream transforms for x86 relative branches."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

from iced_x86 import Decoder, FlowControl, Instruction, OpKind

_DWORD = struct.Struct("<I")
_UINT32_MASK = (1 << 32) - 1


@dataclass(frozen=True, slots=True)
class BranchStreams:
    """Separated x86 code and branch-target streams.

    Args:
        skeleton: Original bytes with four-byte branch operands removed.
        targets: Absolute branch targets stored as little-endian unsigned dwords.
        count: Number of removed branch operands.
    """

    skeleton: bytes
    targets: bytes
    count: int


class _StreamKind(IntEnum):
    """Kinds of instruction constants separated into independent streams."""

    DISPLACEMENT = 0
    IMMEDIATE = 1
    BRANCH = 2
    RIP_ADDRESS = 3


@dataclass(frozen=True, slots=True)
class _ConstantSpan:
    """One encoded displacement or immediate inside an instruction."""

    offset: int
    size: int
    kind: _StreamKind


@dataclass(frozen=True, slots=True)
class InstructionStreams:
    """Zeroed instruction bytes and type-specific constant streams."""

    skeleton: bytes
    constants: tuple[bytes, ...]
    bitness: int


_RELATIVE_FLOW_CONTROLS = frozenset(
    {
        FlowControl.CALL,
        FlowControl.CONDITIONAL_BRANCH,
        FlowControl.UNCONDITIONAL_BRANCH,
    }
)
_NEAR_BRANCH_KINDS = frozenset(
    {OpKind.NEAR_BRANCH16, OpKind.NEAR_BRANCH32, OpKind.NEAR_BRANCH64}
)
_CONSTANT_SIZES = (1, 2, 4, 8)


def _stream_index(kind: _StreamKind, size: int) -> int:
    """Return the size-major typed-stream index for a constant span."""

    try:
        size_index = _CONSTANT_SIZES.index(size)
    except ValueError as error:
        raise ValueError("unsupported x86 constant size") from error
    return size_index * len(_StreamKind) + int(kind)


def _constant_spans(decoder: Decoder, instruction: Instruction) -> list[_ConstantSpan]:
    """Return ordered constant-byte spans for one decoded instruction.

    Args:
        decoder: Decoder that produced ``instruction``.
        instruction: Most recently decoded instruction.

    Returns:
        Non-overlapping displacement and immediate spans.
    """

    offsets = decoder.get_constant_offsets(instruction)
    spans: list[_ConstantSpan] = []
    if offsets.has_displacement:
        kind = (
            _StreamKind.RIP_ADDRESS
            if instruction.is_ip_rel_memory_operand
            else _StreamKind.DISPLACEMENT
        )
        spans.append(
            _ConstantSpan(offsets.displacement_offset, offsets.displacement_size, kind)
        )
    if offsets.has_immediate:
        kind = (
            _StreamKind.BRANCH
            if instruction.flow_control in _RELATIVE_FLOW_CONTROLS
            and instruction.op0_kind in _NEAR_BRANCH_KINDS
            else _StreamKind.IMMEDIATE
        )
        spans.append(
            _ConstantSpan(offsets.immediate_offset, offsets.immediate_size, kind)
        )
    if offsets.has_immediate2:
        spans.append(
            _ConstantSpan(
                offsets.immediate_offset2,
                offsets.immediate_size2,
                _StreamKind.IMMEDIATE,
            )
        )
    return sorted(spans, key=lambda span: span.offset)


def _normalized_value(
    instruction: Instruction, span: _ConstantSpan, raw: bytes
) -> bytes:
    """Normalize relative constants to section-local absolute addresses."""

    mask = (1 << (span.size * 8)) - 1
    if span.kind is _StreamKind.BRANCH:
        value = instruction.near_branch_target & mask
        return value.to_bytes(span.size, "little")
    if span.kind is _StreamKind.RIP_ADDRESS:
        value = instruction.ip_rel_memory_address & mask
        return value.to_bytes(span.size, "little")
    return raw


def split_instruction_constants(data: bytes, bitness: int) -> InstructionStreams:
    """Zero instruction constants and collect their values by semantic kind.

    Args:
        data: Raw x86 code bytes.
        bitness: Decoder mode, either 32 or 64.

    Raises:
        ValueError: If the decoder mode is unsupported.

    Returns:
        Same-length skeleton plus displacement, immediate, branch, and RIP streams.
    """

    if bitness not in (32, 64):
        raise ValueError("x86 bitness must be 32 or 64")
    skeleton = bytearray(data)
    values = [bytearray() for _ in range(len(_CONSTANT_SIZES) * len(_StreamKind))]
    decoder = Decoder(bitness, data, ip=0)
    for instruction in decoder:
        for span in _constant_spans(decoder, instruction):
            start = instruction.ip + span.offset
            end = start + span.size
            raw = data[start:end]
            values[_stream_index(span.kind, span.size)].extend(
                _normalized_value(instruction, span, raw)
            )
            skeleton[start:end] = b"\0" * span.size
    return InstructionStreams(
        skeleton=bytes(skeleton),
        constants=tuple(bytes(value) for value in values),
        bitness=bitness,
    )


def _restore_value(
    instruction: Instruction, span: _ConstantSpan, normalized: bytes
) -> bytes:
    """Convert a stored constant back to its original instruction representation."""

    if span.kind not in (_StreamKind.BRANCH, _StreamKind.RIP_ADDRESS):
        return normalized
    mask = (1 << (span.size * 8)) - 1
    absolute = int.from_bytes(normalized, "little")
    relative = (absolute - instruction.next_ip) & mask
    return relative.to_bytes(span.size, "little")


def merge_instruction_constants(streams: InstructionStreams) -> bytes:
    """Restore exact x86 bytes from a zeroed skeleton and constant streams.

    Args:
        streams: Structured streams produced by :func:`split_instruction_constants`.

    Raises:
        ValueError: If the bitness or any stream length is inconsistent.

    Returns:
        Original x86 bytes.
    """

    if streams.bitness not in (32, 64):
        raise ValueError("x86 bitness must be 32 or 64")
    expected_streams = len(_CONSTANT_SIZES) * len(_StreamKind)
    if len(streams.constants) != expected_streams:
        raise ValueError("x86 constant stream count does not match")
    cursors = [0] * expected_streams
    output = bytearray(streams.skeleton)
    decoder = Decoder(streams.bitness, streams.skeleton, ip=0)
    for instruction in decoder:
        for span in _constant_spans(decoder, instruction):
            index = _stream_index(span.kind, span.size)
            cursor = cursors[index]
            end = cursor + span.size
            source = streams.constants[index]
            if end > len(source):
                raise ValueError("x86 constant stream is truncated")
            normalized = source[cursor:end]
            start = instruction.ip + span.offset
            output[start : start + span.size] = _restore_value(
                instruction, span, normalized
            )
            cursors[index] = end
    if any(
        cursor != len(stream)
        for cursor, stream in zip(cursors, streams.constants, strict=True)
    ):
        raise ValueError("x86 constant stream contains trailing bytes")
    return bytes(output)


def _instruction_size(data: bytes, offset: int) -> int:
    """Return a supported relative-branch size at an input offset.

    Args:
        data: Complete input code stream.
        offset: Candidate instruction offset.

    Returns:
        Five for E8/E9, six for 0F 80..8F, or zero when not recognized.
    """

    remaining = len(data) - offset
    if remaining >= 5 and data[offset] in (0xE8, 0xE9):
        return 5
    if remaining >= 6 and data[offset] == 0x0F and data[offset + 1] & 0xF0 == 0x80:
        return 6
    return 0


def split_relative_branches(data: bytes) -> BranchStreams:
    """Separate relative branch operands from an x86 byte stream.

    Every syntactically matching byte pattern is transformed. False positives are harmless
    because the transform is byte-exact and does not claim to validate instruction boundaries.

    Args:
        data: Raw executable-section bytes.

    Returns:
        The shortened opcode skeleton and normalized target stream.
    """

    skeleton = bytearray()
    targets = bytearray()
    offset = 0
    count = 0
    while offset < len(data):
        size = _instruction_size(data, offset)
        if size == 0:
            skeleton.append(data[offset])
            offset += 1
            continue

        opcode_size = size - 4
        skeleton.extend(data[offset : offset + opcode_size])
        relative = _DWORD.unpack_from(data, offset + opcode_size)[0]
        absolute = (relative + offset + size) & _UINT32_MASK
        targets.extend(_DWORD.pack(absolute))
        count += 1
        offset += size

    return BranchStreams(bytes(skeleton), bytes(targets), count)


def merge_relative_branches(streams: BranchStreams, expected_size: int) -> bytes:
    """Reconstruct an x86 stream from a skeleton and absolute branch targets.

    Args:
        streams: Streams returned by :func:`split_relative_branches`.
        expected_size: Required reconstructed byte length.

    Raises:
        ValueError: If stream sizes or opcode framing are inconsistent.

    Returns:
        Original executable-section bytes.
    """

    if streams.count < 0 or len(streams.targets) != streams.count * _DWORD.size:
        raise ValueError("branch target stream size does not match its count")
    if len(streams.skeleton) + len(streams.targets) != expected_size:
        raise ValueError("branch streams do not match the expected size")

    output = bytearray()
    skeleton_offset = 0
    target_offset = 0
    remaining = streams.count
    while skeleton_offset < len(streams.skeleton):
        byte = streams.skeleton[skeleton_offset]
        opcode_size = 0
        if remaining and byte in (0xE8, 0xE9):
            opcode_size = 1
        elif (
            remaining
            and skeleton_offset + 1 < len(streams.skeleton)
            and byte == 0x0F
            and streams.skeleton[skeleton_offset + 1] & 0xF0 == 0x80
        ):
            opcode_size = 2

        if opcode_size == 0:
            output.append(byte)
            skeleton_offset += 1
            continue

        output.extend(streams.skeleton[skeleton_offset : skeleton_offset + opcode_size])
        absolute = _DWORD.unpack_from(streams.targets, target_offset)[0]
        relative = (absolute - len(output) - _DWORD.size) & _UINT32_MASK
        output.extend(_DWORD.pack(relative))
        skeleton_offset += opcode_size
        target_offset += _DWORD.size
        remaining -= 1

    if remaining or target_offset != len(streams.targets):
        raise ValueError("branch target stream contains unmatched operands")
    if len(output) != expected_size:
        raise ValueError("reconstructed branch stream has the wrong size")
    return bytes(output)
