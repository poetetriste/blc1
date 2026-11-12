"""Exact size accounting for complete BLC1 archives and internal streams."""

from __future__ import annotations

from dataclasses import dataclass

from bincompress.codec import (
    _HEADER,
    _SEGMENT_HEADER,
    _X86_MULTIPLEX_HEADER,
    Method,
    compress,
)
from bincompress.exceptions import FormatError


@dataclass(frozen=True, slots=True)
class StreamProfile:
    """Size contribution of one independently framed method stream."""

    name: str
    original_size: int
    stored_size: int


@dataclass(frozen=True, slots=True)
class SegmentProfile:
    """Exact archive contribution of one encoded segment."""

    name: str
    method: Method
    original_size: int
    payload_size: int
    framing_size: int
    streams: tuple[StreamProfile, ...]

    @property
    def stored_size(self) -> int:
        """Return payload plus segment framing bytes."""

        return self.payload_size + self.framing_size


@dataclass(frozen=True, slots=True)
class ArchiveProfile:
    """Complete size breakdown for the representation selected by BLC1."""

    original_size: int
    archive_size: int
    global_header_size: int
    segments: tuple[SegmentProfile, ...]


def _profile_streams(
    method: Method, payload: bytes, original_size: int
) -> tuple[StreamProfile, ...]:
    """Account for independently decodable streams inside a method payload.

    Args:
        method: Selected segment method.
        payload: Complete stored method payload.
        original_size: Reconstructed segment size.

    Raises:
        FormatError: If multiplex metadata is inconsistent with the payload.

    Returns:
        Exact internal stream contributions whose stored sizes sum to the payload size.
    """

    if method not in (
        Method.X86_MULTIPLEX_LZMA2,
        Method.X86_MULTIPLEX_PPMD,
    ):
        return (StreamProfile("payload", original_size, len(payload)),)
    if len(payload) < _X86_MULTIPLEX_HEADER.size:
        raise FormatError("x86 multiplex profile header is truncated")
    unpacked = _X86_MULTIPLEX_HEADER.unpack_from(payload)
    skeleton_payload_size = unpacked[1]
    constants_size = sum(unpacked[2:18])
    constants_payload_size = (
        len(payload) - _X86_MULTIPLEX_HEADER.size - skeleton_payload_size
    )
    if constants_payload_size < 0:
        raise FormatError("x86 multiplex profile sizes exceed the payload")
    return (
        StreamProfile("method-metadata", 0, _X86_MULTIPLEX_HEADER.size),
        StreamProfile("instruction-skeleton", original_size, skeleton_payload_size),
        StreamProfile("typed-constants", constants_size, constants_payload_size),
    )


def profile_archive(data: bytes, *, preset: int = 9) -> ArchiveProfile:
    """Compress bytes and return exact accounting for the selected archive.

    Args:
        data: Input bytes.
        preset: LZMA preset from zero through nine.

    Raises:
        FormatError: If the internally produced archive is inconsistent.

    Returns:
        Complete archive, segment, and internal-stream size accounting.
    """

    archive = compress(data, preset=preset)
    if len(archive) < _HEADER.size:
        raise FormatError("profiled archive header is truncated")
    _, original_size, _, segment_count = _HEADER.unpack_from(archive)
    cursor = _HEADER.size
    segments: list[SegmentProfile] = []
    for _ in range(segment_count):
        if cursor + _SEGMENT_HEADER.size > len(archive):
            raise FormatError("profiled segment header is truncated")
        method_value, _, name_size, segment_size, payload_size = (
            _SEGMENT_HEADER.unpack_from(archive, cursor)
        )
        cursor += _SEGMENT_HEADER.size
        end = cursor + name_size + payload_size
        if end > len(archive):
            raise FormatError("profiled segment payload is truncated")
        try:
            method = Method(method_value)
            name = archive[cursor : cursor + name_size].decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise FormatError("invalid profiled segment metadata") from error
        cursor += name_size
        payload = archive[cursor : cursor + payload_size]
        cursor += payload_size
        streams = _profile_streams(method, payload, segment_size)
        if sum(stream.stored_size for stream in streams) != payload_size:
            raise FormatError("profiled stream sizes do not match the payload")
        segments.append(
            SegmentProfile(
                name=name,
                method=method,
                original_size=segment_size,
                payload_size=payload_size,
                framing_size=_SEGMENT_HEADER.size + name_size,
                streams=streams,
            )
        )
    if cursor != len(archive):
        raise FormatError("profiled archive contains trailing bytes")
    if sum(segment.original_size for segment in segments) != original_size:
        raise FormatError("profiled segment sizes do not match the input")
    return ArchiveProfile(
        original_size=original_size,
        archive_size=len(archive),
        global_header_size=_HEADER.size,
        segments=tuple(segments),
    )
