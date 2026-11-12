"""Reversible transforms for structured PE metadata sections."""

from __future__ import annotations

import itertools
import struct

_DWORD = struct.Struct("<I")
_WORD = struct.Struct("<H")
_PDATA_RECORD = struct.Struct("<III")
_IMAGE_REL_BASED_HIGHLOW = 3
_IMAGE_REL_BASED_DIR64 = 10


def _delta_encode(values: list[int], mask: int) -> list[int]:
    """Convert unsigned values to modular first differences."""

    if not values:
        return []
    return [
        values[0],
        *[(right - left) & mask for left, right in itertools.pairwise(values)],
    ]


def _delta_decode(values: list[int], mask: int) -> list[int]:
    """Restore unsigned values from modular first differences."""

    restored: list[int] = []
    current = 0
    for value in values:
        current = (current + value) & mask
        restored.append(current)
    return restored


def encode_pdata(data: bytes) -> bytes:
    """Transpose and delta-code 12-byte x64 runtime-function records.

    Args:
        data: Raw ``.pdata`` section bytes.

    Returns:
        Same-length reversible transformed bytes.
    """

    record_count = len(data) // _PDATA_RECORD.size
    body_size = record_count * _PDATA_RECORD.size
    columns: tuple[list[int], list[int], list[int]] = ([], [], [])
    for record in _PDATA_RECORD.iter_unpack(data[:body_size]):
        for column, value in zip(columns, record, strict=True):
            column.append(value)
    transformed = bytearray()
    for column in columns:
        for value in _delta_encode(column, 0xFFFFFFFF):
            transformed.extend(_DWORD.pack(value))
    transformed.extend(data[body_size:])
    return bytes(transformed)


def decode_pdata(data: bytes) -> bytes:
    """Restore interleaved x64 runtime-function records.

    Args:
        data: Transformed bytes produced by :func:`encode_pdata`.

    Returns:
        Original ``.pdata`` bytes.
    """

    record_count = len(data) // _PDATA_RECORD.size
    column_size = record_count * _DWORD.size
    columns: list[list[int]] = []
    for index in range(3):
        start = index * column_size
        values = [
            value[0] for value in _DWORD.iter_unpack(data[start : start + column_size])
        ]
        columns.append(_delta_decode(values, 0xFFFFFFFF))
    restored = bytearray()
    for record in zip(*columns, strict=True):
        restored.extend(_PDATA_RECORD.pack(*record))
    restored.extend(data[record_count * _PDATA_RECORD.size :])
    return bytes(restored)


def encode_relocations(data: bytes) -> bytes | None:
    """Reorder and delta-code PE base-relocation blocks.

    Args:
        data: Raw ``.reloc`` section bytes, including optional zero padding.

    Returns:
        Transformed bytes prefixed by the block count, or ``None`` if malformed.
    """

    cursor = 0
    previous_page = 0
    pages: list[int] = []
    sizes: list[int] = []
    entries: list[int] = []
    while cursor + 8 <= len(data):
        page, block_size = struct.unpack_from("<II", data, cursor)
        if page == 0 and block_size == 0:
            break
        if block_size < 8 or block_size % 2 or cursor + block_size > len(data):
            return None
        pages.append((page - previous_page) & 0xFFFFFFFF)
        previous_page = page
        sizes.append(block_size)
        previous_offset = 0
        for offset in range(cursor + 8, cursor + block_size, _WORD.size):
            entry = _WORD.unpack_from(data, offset)[0]
            entry_type = entry >> 12
            relocation_offset = entry & 0x0FFF
            delta = (relocation_offset - previous_offset) & 0x0FFF
            entries.append((entry_type << 12) | delta)
            previous_offset = relocation_offset
        cursor += block_size
    if not pages:
        return None

    transformed = bytearray(_DWORD.pack(len(pages)))
    for values, item in ((pages, _DWORD), (sizes, _DWORD), (entries, _WORD)):
        for value in values:
            transformed.extend(item.pack(value))
    transformed.extend(data[cursor:])
    return bytes(transformed)


def relocation_pointer_offsets(
    data: bytes, section_rva: int, section_size: int, pointer_width: int
) -> tuple[int, ...] | None:
    """Locate absolute pointers in a section from PE base-relocation blocks.

    Args:
        data: Raw ``.reloc`` section bytes.
        section_rva: Target section relative virtual address.
        section_size: Target section raw size.
        pointer_width: Four for PE32 or eight for PE32+.

    Returns:
        Sorted byte offsets within the target section, or ``None`` if malformed.
    """

    if pointer_width not in (4, 8):
        raise ValueError("pointer width must be four or eight")
    expected_type = (
        _IMAGE_REL_BASED_HIGHLOW if pointer_width == 4 else _IMAGE_REL_BASED_DIR64
    )
    cursor = 0
    offsets: list[int] = []
    while cursor + 8 <= len(data):
        page, block_size = struct.unpack_from("<II", data, cursor)
        if page == 0 and block_size == 0:
            break
        if block_size < 8 or block_size % 2 or cursor + block_size > len(data):
            return None
        for entry_offset in range(cursor + 8, cursor + block_size, _WORD.size):
            entry = _WORD.unpack_from(data, entry_offset)[0]
            if entry >> 12 != expected_type:
                continue
            pointer_rva = page + (entry & 0x0FFF)
            section_offset = pointer_rva - section_rva
            if 0 <= section_offset <= section_size - pointer_width:
                offsets.append(section_offset)
        cursor += block_size
    return tuple(sorted(set(offsets)))


def decode_relocations(data: bytes, expected_size: int) -> bytes:
    """Restore PE base-relocation blocks from reordered streams.

    Args:
        data: Transformed relocation bytes.
        expected_size: Required restored section size.

    Raises:
        ValueError: If block metadata or transformed size is inconsistent.

    Returns:
        Original ``.reloc`` section bytes.
    """

    if len(data) != expected_size + _DWORD.size:
        raise ValueError("relocation transform size does not match")
    (block_count,) = _DWORD.unpack_from(data)
    if block_count == 0 or block_count > expected_size // 8:
        raise ValueError("invalid relocation block count")
    pages_start = _DWORD.size
    sizes_start = pages_start + block_count * _DWORD.size
    entries_start = sizes_start + block_count * _DWORD.size
    if entries_start > len(data):
        raise ValueError("relocation headers are truncated")
    page_deltas = [
        value[0] for value in _DWORD.iter_unpack(data[pages_start:sizes_start])
    ]
    block_sizes = [
        value[0] for value in _DWORD.iter_unpack(data[sizes_start:entries_start])
    ]
    if any(size < 8 or size % 2 for size in block_sizes):
        raise ValueError("invalid relocation block size")
    entry_bytes = sum(size - 8 for size in block_sizes)
    entries_end = entries_start + entry_bytes
    if entries_end > len(data):
        raise ValueError("relocation entries are truncated")

    restored = bytearray()
    page = 0
    entry_cursor = entries_start
    for page_delta, block_size in zip(page_deltas, block_sizes, strict=True):
        page = (page + page_delta) & 0xFFFFFFFF
        restored.extend(struct.pack("<II", page, block_size))
        relocation_offset = 0
        for _ in range((block_size - 8) // _WORD.size):
            encoded = _WORD.unpack_from(data, entry_cursor)[0]
            entry_cursor += _WORD.size
            entry_type = encoded >> 12
            relocation_offset = (relocation_offset + (encoded & 0x0FFF)) & 0x0FFF
            restored.extend(_WORD.pack((entry_type << 12) | relocation_offset))
    restored.extend(data[entries_end:])
    if len(restored) != expected_size:
        raise ValueError("restored relocation size does not match")
    return bytes(restored)
