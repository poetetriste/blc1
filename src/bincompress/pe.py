"""Minimal, defensive parser for PE section boundaries."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from bincompress.exceptions import FormatError

_DOS_POINTER_OFFSET = 0x3C
_COFF_HEADER_SIZE = 20
_SECTION_HEADER_SIZE = 40
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_FILE_MACHINE_I386 = 0x014C
_IMAGE_FILE_MACHINE_AMD64 = 0x8664
_PE32_MAGIC = 0x010B
_PE32_PLUS_MAGIC = 0x020B
_MAX_SECTIONS = 96


@dataclass(frozen=True, slots=True)
class Segment:
    """Contiguous byte range with a compression hint.

    Args:
        name: Human-readable segment name stored in the archive.
        offset: Byte offset in the original file.
        size: Segment length in bytes.
        executable: Whether x86 branch conversion is worth trying.
        x86_bitness: x86 decoding mode, or ``None`` for another architecture.
        virtual_address: Section RVA, or ``None`` for non-section ranges.
        image_base: Preferred PE image base, or ``None`` for non-PE ranges.
    """

    name: str
    offset: int
    size: int
    executable: bool
    x86_bitness: int | None = None
    virtual_address: int | None = None
    image_base: int | None = None


def _unpack_from(fmt: str, data: bytes, offset: int) -> tuple[int, ...]:
    """Unpack integers after validating the requested range.

    Args:
        fmt: Little-endian struct format.
        data: Input PE bytes.
        offset: Start offset.

    Raises:
        FormatError: If the field lies outside the input.

    Returns:
        Unpacked integer tuple.
    """

    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise FormatError("PE field extends beyond the input")
    return struct.unpack_from(fmt, data, offset)


def parse_pe_segments(data: bytes) -> list[Segment]:
    """Return segments that cover a PE file exactly once.

    Args:
        data: Complete PE file bytes.

    Raises:
        FormatError: If the PE metadata is malformed or overlapping.

    Returns:
        Ordered, gap-inclusive segments covering every input byte.
    """

    if len(data) < 64 or data[:2] != b"MZ":
        raise FormatError("input is not a PE file")

    (pe_offset,) = _unpack_from("<I", data, _DOS_POINTER_OFFSET)
    if pe_offset + 4 + _COFF_HEADER_SIZE > len(data):
        raise FormatError("PE header lies outside the input")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise FormatError("invalid PE signature")

    coff_offset = pe_offset + 4
    (machine,) = _unpack_from("<H", data, coff_offset)
    number_of_sections, optional_header_size = _unpack_from(
        "<H12xH", data, coff_offset + 2
    )
    if number_of_sections > _MAX_SECTIONS:
        raise FormatError("PE contains too many sections")

    table_offset = coff_offset + _COFF_HEADER_SIZE + optional_header_size
    table_size = number_of_sections * _SECTION_HEADER_SIZE
    if table_offset + table_size > len(data):
        raise FormatError("PE section table lies outside the input")

    x86_bitness: int | None = None
    image_base: int | None = None
    if optional_header_size >= 2:
        optional_offset = coff_offset + _COFF_HEADER_SIZE
        (optional_magic,) = _unpack_from("<H", data, optional_offset)
        if machine == _IMAGE_FILE_MACHINE_I386 and optional_magic == _PE32_MAGIC:
            x86_bitness = 32
            if optional_header_size >= 32:
                (image_base,) = _unpack_from("<I", data, optional_offset + 28)
        elif (
            machine == _IMAGE_FILE_MACHINE_AMD64 and optional_magic == _PE32_PLUS_MAGIC
        ):
            x86_bitness = 64
            if optional_header_size >= 32:
                (image_base,) = _unpack_from("<Q", data, optional_offset + 24)

    sections: list[Segment] = []
    for index in range(number_of_sections):
        offset = table_offset + index * _SECTION_HEADER_SIZE
        raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", errors="replace") or f"section_{index}"
        (virtual_address,) = _unpack_from("<I", data, offset + 12)
        raw_size, raw_offset = _unpack_from("<II", data, offset + 16)
        (characteristics,) = _unpack_from("<I", data, offset + 36)
        if raw_size == 0:
            continue
        if raw_offset < table_offset + table_size:
            raise FormatError("PE section overlaps its headers")
        if raw_offset + raw_size > len(data):
            raise FormatError("PE section lies outside the input")
        sections.append(
            Segment(
                name=name,
                offset=raw_offset,
                size=raw_size,
                executable=bool(characteristics & _IMAGE_SCN_MEM_EXECUTE),
                x86_bitness=x86_bitness,
                virtual_address=virtual_address,
                image_base=image_base,
            )
        )

    sections.sort(key=lambda item: item.offset)
    cursor = 0
    result: list[Segment] = []
    gap_index = 0
    for section in sections:
        if section.offset < cursor:
            raise FormatError("PE sections overlap")
        if section.offset > cursor:
            result.append(
                Segment(
                    name=f"gap_{gap_index}",
                    offset=cursor,
                    size=section.offset - cursor,
                    executable=False,
                )
            )
            gap_index += 1
        result.append(section)
        cursor = section.offset + section.size

    if cursor < len(data):
        result.append(
            Segment(
                name="overlay" if sections else "file",
                offset=cursor,
                size=len(data) - cursor,
                executable=False,
            )
        )
    if not result and data:
        result.append(Segment("file", 0, len(data), False))
    return result


def generic_segment(data: bytes) -> list[Segment]:
    """Return one generic segment for non-PE data.

    Args:
        data: Arbitrary binary data.

    Returns:
        A segment list covering the input.
    """

    return [Segment("file", 0, len(data), False)] if data else []
