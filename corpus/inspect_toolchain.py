"""Inspect PE toolchain evidence for corpus manifest entries.

Detects the target machine from the COFF header, decodes the Rich header
(compid table proves the MSVC toolchain generation), and applies string
heuristics for Go, Rust, MinGW, and FreePascal/Delphi builds. Prints a JSON
report; use it to fill ``toolchain_evidence`` in manifest.json.

Usage:
    python corpus/inspect_toolchain.py [corpus/files/*.exe ...]
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x64",
    0xAA64: "arm64",
}

HEURISTIC_MARKERS: list[tuple[str, bytes]] = [
    ("go-buildinfo", b"\xff Go buildinf:"),
    ("rust-cargo", b".cargo\\registry\\"),
    ("rust-panic", b"RUST_BACKTRACE"),
    ("mingw-gcc", b"libgcc_s"),
    ("mingw-gcc", b"__mingw_"),
    ("fpc-lazarus", b"Free Pascal"),
    ("fpc-lazarus", b"Lazarus"),
    ("delphi-rtl", b"Embarcadero"),
]


def read_rich_header(data: bytes) -> list[tuple[int, int, int]] | None:
    """Decode the Rich header compid table, if present.

    Returns a list of (compid, product_id, build_id) triples per entry count,
    or None when the file carries no Rich header.
    """
    rich_pos = data.find(b"Rich")
    if rich_pos < 0 or rich_pos + 8 > len(data):
        return None
    (key,) = struct.unpack_from("<I", data, rich_pos + 4)
    dans_tag = struct.unpack("<I", b"DanS")[0]
    dans_pos = -1
    cursor = rich_pos - 4
    while cursor >= 0x80:
        (word,) = struct.unpack_from("<I", data, cursor)
        if (word ^ key) == dans_tag:
            dans_pos = cursor
            break
        cursor -= 4
    if dans_pos < 0:
        return None
    entries = []
    cursor = dans_pos + 16  # skip DanS and the three zero dwords (all XORed)
    while cursor + 8 <= rich_pos:
        compid_xor, count_xor = struct.unpack_from("<II", data, cursor)
        compid = compid_xor ^ key
        count = count_xor ^ key
        product_id = compid >> 16
        build_id = compid & 0xFFFF
        entries.append((product_id, build_id, count))
        cursor += 8
    return entries or None


def pe_machine(data: bytes) -> str:
    if data[:2] != b"MZ":
        return "not-pe"
    (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
    if pe_offset + 6 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return "not-pe"
    (machine,) = struct.unpack_from("<H", data, pe_offset + 4)
    return MACHINE_NAMES.get(machine, f"unknown-0x{machine:04x}")


def inspect(path: Path) -> dict:
    data = path.read_bytes()
    rich = read_rich_header(data)
    markers = sorted({name for name, needle in HEURISTIC_MARKERS if needle in data})
    evidence: dict[str, object] = {
        "machine": pe_machine(data),
        "rich_header": (
            [{"product_id": p, "build_id": b, "count": c} for p, b, c in rich]
            if rich
            else None
        ),
        "markers": markers,
    }
    return {"file": path.name, "size": len(data), "evidence": evidence}


def main() -> int:
    args = sys.argv[1:]
    files = (
        [Path(a) for a in args]
        if args
        else sorted((Path(__file__).resolve().parent / "files").glob("*.exe"))
    )
    report = [inspect(path) for path in files]
    json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
