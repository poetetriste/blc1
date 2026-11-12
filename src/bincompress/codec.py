"""BLC1 research container and adaptive per-segment compression."""

from __future__ import annotations

import hashlib
import lzma
import struct
from dataclasses import dataclass
from enum import IntEnum

from bincompress.exceptions import FormatError, IntegrityError
from bincompress.pe import Segment, generic_segment, parse_pe_segments
from bincompress.pe_transforms import (
    decode_pdata,
    decode_relocations,
    encode_pdata,
    encode_relocations,
    relocation_pointer_offsets,
)
from bincompress.ppmd import compress as compress_ppmd
from bincompress.ppmd import decompress as decompress_ppmd
from bincompress.preflate import compress as compress_preflate
from bincompress.preflate import decompress as decompress_preflate
from bincompress.preflate import is_available as preflate_is_available
from bincompress.x86 import (
    BranchStreams,
    InstructionStreams,
    merge_instruction_constants,
    merge_relative_branches,
    split_instruction_constants,
    split_relative_branches,
)

_MAGIC = b"BLC1"
_HEADER = struct.Struct(">4sQ32sI")
_SEGMENT_HEADER = struct.Struct(">BBHQQ")
_X86_STREAM_HEADER = struct.Struct(">Q")
_X86_INSTRUCTION_HEADER = struct.Struct(">BBB" + "Q" * 16)
_X86_MULTIPLEX_HEADER = struct.Struct(">BQ" + "Q" * 16 + "B" * 16)
_POINTER_SECTION_HEADER = struct.Struct(">BQQQ")
_TUNED_BCJ_HEADER = struct.Struct(">BB")
_MAX_SEGMENTS = 4096
_MAX_NAME_BYTES = 255


class Method(IntEnum):
    """Compression methods supported by BLC1."""

    RAW = 0
    LZMA2 = 1
    X86_LZMA2 = 2
    X86_STREAMS_LZMA2 = 3
    X86_INSTRUCTIONS_LZMA2 = 4
    X86_TUNED_LZMA2 = 5
    PDATA_LZMA2 = 6
    RELOC_LZMA2 = 7
    X86_MULTIPLEX_LZMA2 = 8
    POINTERS_LZMA2 = 9
    TRANSPOSE2_LZMA2 = 10
    PREFLATE = 11
    X86_MULTIPLEX_PPMD = 12


class _ConstantTransform(IntEnum):
    """Reversible transforms evaluated for typed x86 constants."""

    RAW = 0
    DELTA = 1
    XOR = 2
    TRANSPOSE = 3
    DELTA_TRANSPOSE = 4
    XOR_TRANSPOSE = 5


@dataclass(frozen=True, slots=True)
class EncodedSegment:
    """Compressed representation of one original segment."""

    name: str
    method: Method
    preset: int
    original_size: int
    payload: bytes


def _filters(method: Method, preset: int) -> list[dict[str, int]]:
    """Build deterministic raw-LZMA filter settings.

    Args:
        method: Selected compression method.
        preset: LZMA preset from zero through nine.

    Returns:
        Filter chain accepted by the standard-library lzma module.
    """

    lzma2 = {"id": lzma.FILTER_LZMA2, "preset": preset}
    if method is Method.X86_LZMA2:
        return [{"id": lzma.FILTER_X86, "start_offset": 0}, lzma2]
    return [lzma2]


def _compress_with(method: Method, data: bytes, preset: int) -> bytes:
    """Compress a segment with a specific method.

    Args:
        method: Compression method.
        data: Segment bytes.
        preset: LZMA preset.

    Returns:
        Compressed bytes.
    """

    if method is Method.RAW:
        return data
    return lzma.compress(data, format=lzma.FORMAT_RAW, filters=_filters(method, preset))


def _compress_x86_streams(data: bytes, preset: int) -> bytes:
    """Compress separated x86 opcode and branch-target streams.

    Args:
        data: Executable-section bytes.
        preset: LZMA preset.

    Returns:
        Framed compressed streams, or empty bytes when no branches were found.
    """

    streams = split_relative_branches(data)
    if streams.count == 0:
        return b""
    transformed = streams.skeleton + streams.targets
    payload = lzma.compress(
        transformed,
        format=lzma.FORMAT_RAW,
        filters=[
            {
                "id": lzma.FILTER_LZMA2,
                "preset": preset,
                "lc": 4,
                "lp": 0,
                "pb": 2,
            }
        ],
    )
    return _X86_STREAM_HEADER.pack(streams.count) + payload


def _decompress_x86_streams(payload: bytes, preset: int, expected_size: int) -> bytes:
    """Decode and merge framed x86 branch streams.

    Args:
        payload: Framed compressed stream payload.
        preset: Stored LZMA preset.
        expected_size: Required reconstructed size.

    Raises:
        FormatError: If stream framing or branch metadata is invalid.

    Returns:
        Reconstructed executable-section bytes.
    """

    if len(payload) < _X86_STREAM_HEADER.size:
        raise FormatError("x86 stream header is truncated")
    (count,) = _X86_STREAM_HEADER.unpack_from(payload)
    if count > expected_size // 5:
        raise FormatError("x86 branch count exceeds the segment size")
    skeleton_expected = expected_size - count * 4
    targets_expected = count * 4
    decoder = lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW,
        filters=[
            {
                "id": lzma.FILTER_LZMA2,
                "preset": preset,
                "lc": 4,
                "lp": 0,
                "pb": 2,
            }
        ],
    )
    transformed = decoder.decompress(
        payload[_X86_STREAM_HEADER.size :], max_length=expected_size + 1
    )
    if len(transformed) > expected_size:
        raise IntegrityError("decoded x86 streams exceed the declared size")
    if not decoder.eof or decoder.unused_data:
        raise FormatError("compressed x86 streams are truncated or have trailing data")
    if len(transformed) != expected_size:
        raise IntegrityError("decoded x86 stream size does not match")
    skeleton = transformed[:skeleton_expected]
    targets = transformed[skeleton_expected:]
    if len(targets) != targets_expected:
        raise IntegrityError("decoded x86 target stream size does not match")
    try:
        return merge_relative_branches(
            BranchStreams(skeleton, targets, count), expected_size
        )
    except ValueError as error:
        raise FormatError("invalid x86 branch streams") from error


def _instruction_filters(preset: int, lc: int, pb: int) -> list[dict[str, int]]:
    """Build LZMA settings for a structured instruction stream."""

    return [
        {
            "id": lzma.FILTER_LZMA2,
            "preset": preset,
            "lc": lc,
            "lp": 0,
            "pb": pb,
        }
    ]


def _tuned_bcj_filters(preset: int, lc: int, pb: int) -> list[dict[str, int]]:
    """Build a tuned x86 BCJ and LZMA2 filter chain."""

    return [
        {"id": lzma.FILTER_X86, "start_offset": 0},
        {
            "id": lzma.FILTER_LZMA2,
            "preset": preset,
            "lc": lc,
            "lp": 0,
            "pb": pb,
        },
    ]


def _compress_tuned_bcj(data: bytes, preset: int) -> bytes:
    """Choose the smallest literal/position context for BCJ-filtered bytes."""

    candidates = [
        (
            len(
                payload := lzma.compress(
                    data,
                    format=lzma.FORMAT_RAW,
                    filters=_tuned_bcj_filters(preset, lc, pb),
                )
            ),
            lc,
            pb,
            payload,
        )
        for lc in range(5)
        for pb in range(5)
    ]
    _, lc, pb, payload = min(candidates)
    return _TUNED_BCJ_HEADER.pack(lc, pb) + payload


def _decompress_tuned_bcj(payload: bytes, preset: int, expected_size: int) -> bytes:
    """Decode a tuned BCJ-filtered segment with strict size bounds."""

    if len(payload) < _TUNED_BCJ_HEADER.size:
        raise FormatError("tuned BCJ header is truncated")
    lc, pb = _TUNED_BCJ_HEADER.unpack_from(payload)
    if lc > 4 or pb > 4:
        raise FormatError("invalid tuned BCJ settings")
    decoder = lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW,
        filters=_tuned_bcj_filters(preset, lc, pb),
    )
    result = decoder.decompress(
        payload[_TUNED_BCJ_HEADER.size :], max_length=expected_size + 1
    )
    if len(result) > expected_size:
        raise IntegrityError("decoded tuned BCJ segment exceeds its declared size")
    if not decoder.eof or decoder.unused_data:
        raise FormatError("tuned BCJ segment is truncated or has trailing data")
    return result


def _compress_tuned_lzma(data: bytes, preset: int) -> bytes:
    """Compress transformed bytes with the best LZMA context settings."""

    candidates = [
        (
            len(
                payload := lzma.compress(
                    data,
                    format=lzma.FORMAT_RAW,
                    filters=_instruction_filters(preset, lc, pb),
                )
            ),
            lc,
            pb,
            payload,
        )
        for lc in range(5)
        for pb in range(5)
    ]
    _, lc, pb, payload = min(candidates)
    return _TUNED_BCJ_HEADER.pack(lc, pb) + payload


def _decompress_tuned_lzma(payload: bytes, preset: int, transformed_size: int) -> bytes:
    """Decode a tuned LZMA stream with an exact transformed-size bound."""

    if len(payload) < _TUNED_BCJ_HEADER.size:
        raise FormatError("transformed LZMA header is truncated")
    lc, pb = _TUNED_BCJ_HEADER.unpack_from(payload)
    if lc > 4 or pb > 4:
        raise FormatError("invalid transformed LZMA settings")
    decoder = lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW,
        filters=_instruction_filters(preset, lc, pb),
    )
    result = decoder.decompress(
        payload[_TUNED_BCJ_HEADER.size :], max_length=transformed_size + 1
    )
    if len(result) > transformed_size:
        raise IntegrityError("decoded transform exceeds its declared size")
    if not decoder.eof or decoder.unused_data:
        raise FormatError("transformed LZMA stream is truncated or has trailing data")
    if len(result) != transformed_size:
        raise IntegrityError("decoded transform size does not match")
    return result


def _transpose_words(data: bytes, width: int) -> bytes:
    """Group equal byte positions from fixed-width little-endian words."""

    return b"".join(data[offset::width] for offset in range(width))


def _untranspose_words(data: bytes, width: int) -> bytes:
    """Restore interleaved fixed-width words from byte-position planes."""

    count = len(data) // width
    output = bytearray(len(data))
    for offset in range(width):
        plane = data[offset * count : (offset + 1) * count]
        output[offset::width] = plane
    return bytes(output)


def _transform_words(data: bytes, width: int, transform: _ConstantTransform) -> bytes:
    """Apply a size-preserving transform to one typed constant stream."""

    if len(data) % width:
        raise ValueError("constant stream is not word-aligned")
    if transform is _ConstantTransform.RAW or not data:
        return data
    mask = (1 << (width * 8)) - 1
    values = [
        int.from_bytes(data[offset : offset + width], "little")
        for offset in range(0, len(data), width)
    ]
    if transform in (
        _ConstantTransform.DELTA,
        _ConstantTransform.DELTA_TRANSPOSE,
    ):
        previous = values[0]
        transformed = [previous]
        for value in values[1:]:
            transformed.append((value - previous) & mask)
            previous = value
        result = b"".join(value.to_bytes(width, "little") for value in transformed)
    elif transform in (_ConstantTransform.XOR, _ConstantTransform.XOR_TRANSPOSE):
        previous = values[0]
        transformed = [previous]
        for value in values[1:]:
            transformed.append(value ^ previous)
            previous = value
        result = b"".join(value.to_bytes(width, "little") for value in transformed)
    else:
        result = data
    if transform in (
        _ConstantTransform.TRANSPOSE,
        _ConstantTransform.DELTA_TRANSPOSE,
        _ConstantTransform.XOR_TRANSPOSE,
    ):
        return _transpose_words(result, width)
    return result


def _inverse_transform_words(
    data: bytes, width: int, transform: _ConstantTransform
) -> bytes:
    """Invert a typed constant-stream transform."""

    if len(data) % width:
        raise ValueError("constant stream is not word-aligned")
    if transform is _ConstantTransform.RAW or not data:
        return data
    if transform in (
        _ConstantTransform.TRANSPOSE,
        _ConstantTransform.DELTA_TRANSPOSE,
        _ConstantTransform.XOR_TRANSPOSE,
    ):
        data = _untranspose_words(data, width)
    if transform is _ConstantTransform.TRANSPOSE:
        return data
    mask = (1 << (width * 8)) - 1
    values = [
        int.from_bytes(data[offset : offset + width], "little")
        for offset in range(0, len(data), width)
    ]
    output = [values[0]]
    for value in values[1:]:
        if transform in (
            _ConstantTransform.DELTA,
            _ConstantTransform.DELTA_TRANSPOSE,
        ):
            output.append((output[-1] + value) & mask)
        else:
            output.append(output[-1] ^ value)
    return b"".join(value.to_bytes(width, "little") for value in output)


def _compress_x86_multiplexed(
    data: bytes, bitness: int, preset: int, *, ppmd_skeleton: bool = False
) -> bytes:
    """Compress instruction skeleton and transformed constants independently."""

    streams = split_instruction_constants(data, bitness)
    if not any(streams.constants):
        return b""
    transform_ids: list[int] = []
    transformed_values: list[bytes] = []
    proxy_filters = _instruction_filters(preset, 3, 0)
    for index, value in enumerate(streams.constants):
        width = (1, 2, 4, 8)[index // 4]
        candidates = []
        for transform in _ConstantTransform:
            transformed = _transform_words(value, width, transform)
            proxy_size = len(
                lzma.compress(
                    transformed,
                    format=lzma.FORMAT_RAW,
                    filters=proxy_filters,
                )
            )
            candidates.append((proxy_size, int(transform), transformed))
        _, transform_id, transformed = min(candidates)
        transform_ids.append(transform_id)
        transformed_values.append(transformed)

    skeleton_payload = (
        compress_ppmd(streams.skeleton)
        if ppmd_skeleton
        else _compress_tuned_lzma(streams.skeleton, preset)
    )
    constants_payload = _compress_tuned_lzma(b"".join(transformed_values), preset)
    header = _X86_MULTIPLEX_HEADER.pack(
        bitness,
        len(skeleton_payload),
        *(len(value) for value in streams.constants),
        *transform_ids,
    )
    return header + skeleton_payload + constants_payload


def _decompress_x86_multiplexed(
    payload: bytes,
    preset: int,
    expected_size: int,
    *,
    ppmd_skeleton: bool = False,
) -> bytes:
    """Route two independently compressed blocks back into instruction streams."""

    if len(payload) < _X86_MULTIPLEX_HEADER.size:
        raise FormatError("x86 multiplex header is truncated")
    unpacked = _X86_MULTIPLEX_HEADER.unpack_from(payload)
    bitness, skeleton_payload_size = unpacked[:2]
    value_sizes = unpacked[2:18]
    transform_ids = unpacked[18:]
    if bitness not in (32, 64):
        raise FormatError("invalid x86 multiplex bitness")
    constants_size = sum(value_sizes)
    if constants_size > expected_size:
        raise FormatError("x86 multiplex constants exceed the segment size")
    start = _X86_MULTIPLEX_HEADER.size
    boundary = start + skeleton_payload_size
    if boundary > len(payload):
        raise FormatError("x86 multiplex skeleton payload is truncated")
    skeleton_payload = payload[start:boundary]
    skeleton = (
        decompress_ppmd(skeleton_payload, expected_size)
        if ppmd_skeleton
        else _decompress_tuned_lzma(skeleton_payload, preset, expected_size)
    )
    transformed = _decompress_tuned_lzma(payload[boundary:], preset, constants_size)
    values: list[bytes] = []
    cursor = 0
    try:
        for index, (size, transform_id) in enumerate(
            zip(value_sizes, transform_ids, strict=True)
        ):
            end = cursor + size
            transform = _ConstantTransform(transform_id)
            width = (1, 2, 4, 8)[index // 4]
            values.append(
                _inverse_transform_words(transformed[cursor:end], width, transform)
            )
            cursor = end
        return merge_instruction_constants(
            InstructionStreams(skeleton, tuple(values), bitness)
        )
    except ValueError as error:
        raise FormatError("invalid x86 multiplex streams") from error


def _compress_pointer_section(
    data: bytes,
    pointer_offsets: tuple[int, ...],
    pointer_width: int,
    image_base: int,
    preset: int,
) -> bytes:
    """Compress a section skeleton plus relocation-identified pointer streams."""

    if pointer_width not in (4, 8):
        raise ValueError("pointer width must be four or eight")
    if not pointer_offsets:
        return b""
    if image_base >= 1 << (pointer_width * 8):
        raise ValueError("image base does not fit the pointer width")
    skeleton = bytearray(data)
    positions = bytearray()
    values = bytearray()
    previous = 0
    mask = (1 << (pointer_width * 8)) - 1
    for index, offset in enumerate(pointer_offsets):
        if offset < 0 or offset + pointer_width > len(data):
            raise ValueError("pointer offset lies outside the section")
        if index and offset <= pointer_offsets[index - 1]:
            raise ValueError("pointer offsets must be strictly increasing")
        positions.extend((offset - previous).to_bytes(4, "little"))
        previous = offset
        pointer = int.from_bytes(data[offset : offset + pointer_width], "little")
        values.extend(((pointer - image_base) & mask).to_bytes(pointer_width, "little"))
        skeleton[offset : offset + pointer_width] = b"\0" * pointer_width

    transformed_positions = _transpose_words(bytes(positions), 4)
    transformed_values = _transform_words(
        bytes(values), pointer_width, _ConstantTransform.DELTA_TRANSPOSE
    )
    skeleton_payload = _compress_tuned_lzma(bytes(skeleton), preset)
    pointer_payload = _compress_tuned_lzma(
        transformed_positions + transformed_values, preset
    )
    return (
        _POINTER_SECTION_HEADER.pack(
            pointer_width,
            image_base,
            len(pointer_offsets),
            len(skeleton_payload),
        )
        + skeleton_payload
        + pointer_payload
    )


def _decompress_pointer_section(
    payload: bytes, preset: int, expected_size: int
) -> bytes:
    """Restore a section from its skeleton and normalized absolute pointers."""

    if len(payload) < _POINTER_SECTION_HEADER.size:
        raise FormatError("pointer section header is truncated")
    pointer_width, image_base, count, skeleton_payload_size = (
        _POINTER_SECTION_HEADER.unpack_from(payload)
    )
    if pointer_width not in (4, 8):
        raise FormatError("invalid pointer width")
    if image_base >= 1 << (pointer_width * 8):
        raise FormatError("pointer image base does not fit its width")
    if count == 0 or count > expected_size // pointer_width:
        raise FormatError("invalid pointer count")
    start = _POINTER_SECTION_HEADER.size
    boundary = start + skeleton_payload_size
    if boundary > len(payload):
        raise FormatError("pointer section skeleton is truncated")
    skeleton = bytearray(
        _decompress_tuned_lzma(payload[start:boundary], preset, expected_size)
    )
    stream_size = count * (4 + pointer_width)
    transformed = _decompress_tuned_lzma(payload[boundary:], preset, stream_size)
    positions_end = count * 4
    position_deltas = _untranspose_words(transformed[:positions_end], 4)
    values = _inverse_transform_words(
        transformed[positions_end:],
        pointer_width,
        _ConstantTransform.DELTA_TRANSPOSE,
    )
    mask = (1 << (pointer_width * 8)) - 1
    offset = 0
    previous = -1
    for index in range(count):
        delta_start = index * 4
        offset += int.from_bytes(
            position_deltas[delta_start : delta_start + 4], "little"
        )
        if offset <= previous or offset + pointer_width > expected_size:
            raise FormatError("invalid pointer position stream")
        value_start = index * pointer_width
        normalized = int.from_bytes(
            values[value_start : value_start + pointer_width], "little"
        )
        pointer = (normalized + image_base) & mask
        skeleton[offset : offset + pointer_width] = pointer.to_bytes(
            pointer_width, "little"
        )
        previous = offset
    return bytes(skeleton)


def _compress_x86_instructions(data: bytes, bitness: int, preset: int) -> bytes:
    """Compress a zeroed instruction skeleton and typed constant streams.

    Args:
        data: Executable-section bytes.
        bitness: x86 decoding mode.
        preset: LZMA preset.

    Returns:
        Framed structured payload, or empty bytes when no constants were found.
    """

    streams = split_instruction_constants(data, bitness)
    values = streams.constants
    if not any(values):
        return b""
    transformed = streams.skeleton + b"".join(values)
    candidates = [
        (
            len(
                payload := lzma.compress(
                    transformed,
                    format=lzma.FORMAT_RAW,
                    filters=_instruction_filters(preset, lc, pb),
                )
            ),
            lc,
            pb,
            payload,
        )
        for lc in range(5)
        for pb in range(5)
    ]
    _, lc, pb, payload = min(candidates)
    header = _X86_INSTRUCTION_HEADER.pack(
        bitness,
        lc,
        pb,
        *(len(value) for value in values),
    )
    return header + payload


def _decompress_x86_instructions(
    payload: bytes, preset: int, expected_size: int
) -> bytes:
    """Decode a structured x86 instruction payload.

    Args:
        payload: Framed compressed instruction streams.
        preset: Stored LZMA preset.
        expected_size: Required reconstructed section size.

    Raises:
        FormatError: If stream metadata or reconstruction is invalid.
        IntegrityError: If decompressed sizes do not match.

    Returns:
        Original executable-section bytes.
    """

    if len(payload) < _X86_INSTRUCTION_HEADER.size:
        raise FormatError("x86 instruction header is truncated")
    bitness, lc, pb, *value_sizes = _X86_INSTRUCTION_HEADER.unpack_from(payload)
    if bitness not in (32, 64) or lc > 4 or pb > 4:
        raise FormatError("invalid x86 instruction settings")
    constants_size = sum(value_sizes)
    if constants_size > expected_size:
        raise FormatError("x86 constant streams exceed the segment size")
    transformed_size = expected_size + constants_size
    decoder = lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW,
        filters=_instruction_filters(preset, lc, pb),
    )
    transformed = decoder.decompress(
        payload[_X86_INSTRUCTION_HEADER.size :], max_length=transformed_size + 1
    )
    if len(transformed) > transformed_size:
        raise IntegrityError("decoded x86 instructions exceed the declared size")
    if not decoder.eof or decoder.unused_data:
        raise FormatError(
            "compressed x86 instructions are truncated or have trailing data"
        )
    if len(transformed) != transformed_size:
        raise IntegrityError("decoded x86 instruction stream size does not match")

    cursor = expected_size
    values: list[bytes] = []
    for size in value_sizes:
        values.append(transformed[cursor : cursor + size])
        cursor += size
    try:
        return merge_instruction_constants(
            InstructionStreams(
                skeleton=transformed[:expected_size],
                constants=tuple(values),
                bitness=bitness,
            )
        )
    except ValueError as error:
        raise FormatError("invalid x86 instruction streams") from error


def _decompress_with(
    method: Method, payload: bytes, preset: int, expected_size: int
) -> bytes:
    """Decompress one segment.

    Args:
        method: Stored compression method.
        payload: Stored segment payload.
        preset: Stored LZMA preset.
        expected_size: Maximum permitted decoded size.

    Returns:
        Decoded segment bytes.
    """

    if method is Method.RAW:
        return payload
    if method is Method.X86_STREAMS_LZMA2:
        return _decompress_x86_streams(payload, preset, expected_size)
    if method is Method.X86_INSTRUCTIONS_LZMA2:
        return _decompress_x86_instructions(payload, preset, expected_size)
    if method is Method.X86_MULTIPLEX_LZMA2:
        return _decompress_x86_multiplexed(payload, preset, expected_size)
    if method is Method.X86_MULTIPLEX_PPMD:
        return _decompress_x86_multiplexed(
            payload, preset, expected_size, ppmd_skeleton=True
        )
    if method is Method.POINTERS_LZMA2:
        return _decompress_pointer_section(payload, preset, expected_size)
    if method is Method.TRANSPOSE2_LZMA2:
        if expected_size % 2:
            raise FormatError("transposed word section has an odd size")
        transformed = _decompress_tuned_lzma(payload, preset, expected_size)
        return _untranspose_words(transformed, 2)
    if method is Method.PREFLATE:
        return decompress_preflate(payload, expected_size)
    if method is Method.X86_TUNED_LZMA2:
        return _decompress_tuned_bcj(payload, preset, expected_size)
    if method is Method.PDATA_LZMA2:
        return decode_pdata(_decompress_tuned_lzma(payload, preset, expected_size))
    if method is Method.RELOC_LZMA2:
        transformed = _decompress_tuned_lzma(payload, preset, expected_size + 4)
        try:
            return decode_relocations(transformed, expected_size)
        except ValueError as error:
            raise FormatError("invalid relocation transform") from error
    decoder = lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW, filters=_filters(method, preset)
    )
    result = decoder.decompress(payload, max_length=expected_size + 1)
    if len(result) > expected_size:
        raise IntegrityError("decoded segment exceeds its declared size")
    if not decoder.eof or decoder.unused_data:
        raise FormatError("compressed segment is truncated or has trailing data")
    return result


def _choose_encoding(
    data: bytes,
    segment: Segment,
    preset: int,
    pointer_offsets: tuple[int, ...] = (),
) -> EncodedSegment:
    """Choose the smallest available representation for a segment.

    Args:
        data: Complete input bytes.
        segment: Segment metadata.
        preset: LZMA preset.
        pointer_offsets: Relocation-identified pointers within the segment.

    Returns:
        Best encoded representation.
    """

    original = data[segment.offset : segment.offset + segment.size]
    candidates = [
        (Method.RAW, original),
        (Method.LZMA2, _compress_with(Method.LZMA2, original, preset)),
    ]
    if segment.executable and segment.x86_bitness and original:
        candidates.append(
            (Method.X86_LZMA2, _compress_with(Method.X86_LZMA2, original, preset))
        )
        candidates.append(
            (Method.X86_TUNED_LZMA2, _compress_tuned_bcj(original, preset))
        )
        x86_streams = _compress_x86_streams(original, preset)
        if x86_streams:
            candidates.append((Method.X86_STREAMS_LZMA2, x86_streams))
        x86_instructions = _compress_x86_instructions(
            original, segment.x86_bitness, preset
        )
        if x86_instructions:
            candidates.append((Method.X86_INSTRUCTIONS_LZMA2, x86_instructions))
        x86_multiplexed = _compress_x86_multiplexed(
            original, segment.x86_bitness, preset
        )
        if x86_multiplexed:
            candidates.append((Method.X86_MULTIPLEX_LZMA2, x86_multiplexed))
            x86_ppmd = _compress_x86_multiplexed(
                original,
                segment.x86_bitness,
                preset,
                ppmd_skeleton=True,
            )
            candidates.append((Method.X86_MULTIPLEX_PPMD, x86_ppmd))
    elif segment.name == ".pdata" and segment.x86_bitness == 64 and original:
        candidates.append(
            (Method.PDATA_LZMA2, _compress_tuned_lzma(encode_pdata(original), preset))
        )
    elif segment.name == ".reloc" and original:
        relocations = encode_relocations(original)
        if relocations is not None:
            candidates.append(
                (Method.RELOC_LZMA2, _compress_tuned_lzma(relocations, preset))
            )
    if segment.name in (".rdata", ".rsrc") and original and len(original) % 2 == 0:
        candidates.append(
            (
                Method.TRANSPOSE2_LZMA2,
                _compress_tuned_lzma(_transpose_words(original, 2), preset),
            )
        )
    if segment.name == ".rsrc" and original and preflate_is_available():
        candidates.append((Method.PREFLATE, compress_preflate(original)))
    if (
        pointer_offsets
        and segment.x86_bitness in (32, 64)
        and segment.image_base is not None
    ):
        pointer_payload = _compress_pointer_section(
            original,
            pointer_offsets,
            segment.x86_bitness // 8,
            segment.image_base,
            preset,
        )
        candidates.append((Method.POINTERS_LZMA2, pointer_payload))
    method, payload = min(candidates, key=lambda candidate: len(candidate[1]))
    stored_preset = preset if method is not Method.RAW else 0
    return EncodedSegment(segment.name, method, stored_preset, len(original), payload)


def _serialize(data: bytes, encoded: list[EncodedSegment]) -> bytes:
    """Serialize encoded segments into a complete integrity-protected archive."""

    output = bytearray(
        _HEADER.pack(_MAGIC, len(data), hashlib.sha256(data).digest(), len(encoded))
    )
    for segment in encoded:
        name = segment.name.encode("utf-8")
        if len(name) > _MAX_NAME_BYTES:
            raise FormatError("segment name is too long")
        output.extend(
            _SEGMENT_HEADER.pack(
                int(segment.method),
                segment.preset,
                len(name),
                segment.original_size,
                len(segment.payload),
            )
        )
        output.extend(name)
        output.extend(segment.payload)
    return bytes(output)


def _choose_whole_file_encoding(
    data: bytes, bitness: int, preset: int
) -> EncodedSegment:
    """Choose a whole-file fallback without semantic instruction decoding."""

    candidates = [
        (Method.RAW, data),
        (Method.LZMA2, _compress_with(Method.LZMA2, data, preset)),
        (Method.X86_LZMA2, _compress_with(Method.X86_LZMA2, data, preset)),
        (Method.X86_TUNED_LZMA2, _compress_tuned_bcj(data, preset)),
    ]
    method, payload = min(candidates, key=lambda candidate: len(candidate[1]))
    stored_preset = preset if method is not Method.RAW else 0
    return EncodedSegment("file", method, stored_preset, len(data), payload)


def compress(data: bytes, *, preset: int = 9) -> bytes:
    """Compress arbitrary bytes into a self-contained BLC1 archive.

    Args:
        data: Input bytes.
        preset: LZMA preset from zero through nine.

    Raises:
        ValueError: If the preset is outside the supported range.

    Returns:
        Complete BLC1 archive bytes.
    """

    if not 0 <= preset <= 9:
        raise ValueError("preset must be between 0 and 9")
    try:
        segments = parse_pe_segments(data)
    except FormatError:
        encoded = [
            _choose_encoding(data, segment, preset) for segment in generic_segment(data)
        ]
        return _serialize(data, encoded)

    pointer_offsets_by_file_offset: dict[int, tuple[int, ...]] = {}
    relocation_segment = next(
        (segment for segment in segments if segment.name == ".reloc"), None
    )
    bitness = next(
        (segment.x86_bitness for segment in segments if segment.x86_bitness), None
    )
    if relocation_segment is not None and bitness in (32, 64):
        relocation_data = data[
            relocation_segment.offset : relocation_segment.offset
            + relocation_segment.size
        ]
        for segment in segments:
            if segment.name not in (".rdata", ".data"):
                continue
            if segment.virtual_address is None:
                continue
            offsets = relocation_pointer_offsets(
                relocation_data,
                segment.virtual_address,
                segment.size,
                bitness // 8,
            )
            if offsets:
                pointer_offsets_by_file_offset[segment.offset] = offsets

    encoded = [
        _choose_encoding(
            data,
            segment,
            preset,
            pointer_offsets_by_file_offset.get(segment.offset, ()),
        )
        for segment in segments
    ]
    archives = [_serialize(data, encoded)]
    if bitness and data:
        archives.append(
            _serialize(data, [_choose_whole_file_encoding(data, bitness, preset)])
        )
    return min(archives, key=len)


def decompress(archive: bytes) -> bytes:
    """Decode a BLC1 archive and verify its integrity.

    Args:
        archive: Complete BLC1 archive bytes.

    Raises:
        FormatError: If the container is malformed.
        IntegrityError: If decoded size or SHA-256 does not match.

    Returns:
        Original input bytes.
    """

    if len(archive) < _HEADER.size:
        raise FormatError("archive header is truncated")
    magic, original_size, digest, segment_count = _HEADER.unpack_from(archive)
    if magic != _MAGIC:
        raise FormatError("invalid BLC1 magic")
    if segment_count > _MAX_SEGMENTS:
        raise FormatError("archive contains too many segments")

    cursor = _HEADER.size
    decoded = bytearray()
    for _ in range(segment_count):
        if cursor + _SEGMENT_HEADER.size > len(archive):
            raise FormatError("segment header is truncated")
        method_value, preset, name_size, expected_size, payload_size = (
            _SEGMENT_HEADER.unpack_from(archive, cursor)
        )
        cursor += _SEGMENT_HEADER.size
        if preset > 9:
            raise FormatError("invalid segment preset")
        end = cursor + name_size + payload_size
        if end > len(archive):
            raise FormatError("segment payload is truncated")
        if expected_size > original_size - len(decoded):
            raise FormatError("declared segment sizes exceed the original size")
        try:
            Method(method_value)
            archive[cursor : cursor + name_size].decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise FormatError("invalid segment metadata") from error
        cursor += name_size
        payload = archive[cursor : cursor + payload_size]
        cursor += payload_size
        try:
            part = _decompress_with(
                Method(method_value), payload, preset, expected_size
            )
        except lzma.LZMAError as error:
            raise FormatError("invalid compressed segment") from error
        if len(part) != expected_size:
            raise IntegrityError("decoded segment size does not match")
        decoded.extend(part)

    if cursor != len(archive):
        raise FormatError("archive contains trailing bytes")
    result = bytes(decoded)
    if len(result) != original_size:
        raise IntegrityError("decoded file size does not match")
    if hashlib.sha256(result).digest() != digest:
        raise IntegrityError("decoded SHA-256 does not match")
    return result
