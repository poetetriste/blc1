"""Command-line interface for the BLC research codec."""

from __future__ import annotations

import argparse
import hashlib
import logging
import lzma
import sys
import time
from pathlib import Path

from bincompress.codec import compress, decompress
from bincompress.exceptions import BinCompressError
from bincompress.profiler import profile_archive

_LOGGER = logging.getLogger(__name__)


def _parser() -> argparse.ArgumentParser:
    """Build the command-line parser.

    Returns:
        Configured argument parser.
    """

    parser = argparse.ArgumentParser(prog="bincompress")
    subparsers = parser.add_subparsers(dest="command", required=True)

    encode = subparsers.add_parser("encode", help="compress a file")
    encode.add_argument("input", type=Path)
    encode.add_argument("output", type=Path)
    encode.add_argument("--preset", type=int, default=9)

    decode = subparsers.add_parser("decode", help="decompress a BLC1 file")
    decode.add_argument("input", type=Path)
    decode.add_argument("output", type=Path)

    bench = subparsers.add_parser("bench", help="compare BLC1 with whole-file XZ")
    bench.add_argument("inputs", type=Path, nargs="+")
    bench.add_argument("--preset", type=int, default=9)

    profile = subparsers.add_parser("profile", help="report exact archive composition")
    profile.add_argument("inputs", type=Path, nargs="+")
    profile.add_argument("--preset", type=int, default=9)
    return parser


def _read(path: Path) -> bytes:
    """Read a regular file.

    Args:
        path: Input path.

    Raises:
        ValueError: If the path is not a regular file.

    Returns:
        File bytes.
    """

    if not path.is_file():
        raise ValueError(f"not a regular file: {path.name}")
    return path.read_bytes()


def _write(path: Path, data: bytes) -> None:
    """Write bytes without overwriting an existing file.

    Args:
        path: Output path.
        data: Bytes to write.

    Raises:
        ValueError: If the output already exists.
    """

    if path.exists():
        raise ValueError(f"output already exists: {path.name}")
    path.write_bytes(data)


def _bench(paths: list[Path], preset: int) -> None:
    """Benchmark full archive size and round-trip correctness.

    Args:
        paths: Input files.
        preset: Shared LZMA preset.
    """

    for path in paths:
        source = _read(path)
        started = time.perf_counter()
        archive = compress(source, preset=preset)
        elapsed = time.perf_counter() - started
        restored = decompress(archive)
        baseline = lzma.compress(source, format=lzma.FORMAT_XZ, preset=preset)
        ratio = len(source) / len(archive) if archive else 1.0
        delta = 100 * (len(archive) / len(baseline) - 1) if baseline else 0.0
        _LOGGER.info(
            "%s input=%d blc1=%d xz=%d ratio=%.3fx vs_xz=%+.2f%% seconds=%.3f sha256=%s",
            path.name,
            len(source),
            len(archive),
            len(baseline),
            ratio,
            delta,
            elapsed,
            hashlib.sha256(restored).hexdigest(),
        )


def _profile(paths: list[Path], preset: int) -> None:
    """Report archive, segment, and independently coded stream sizes.

    Args:
        paths: Input files.
        preset: Shared LZMA preset.
    """

    for path in paths:
        profile = profile_archive(_read(path), preset=preset)
        _LOGGER.info(
            "PROFILE file=%s input=%d archive=%d global_header=%d segments=%d",
            path.name,
            profile.original_size,
            profile.archive_size,
            profile.global_header_size,
            len(profile.segments),
        )
        for segment in profile.segments:
            share = 100 * segment.stored_size / profile.archive_size
            _LOGGER.info(
                "SEGMENT name=%s method=%s raw=%d payload=%d framing=%d share=%.3f%%",
                segment.name,
                segment.method.name,
                segment.original_size,
                segment.payload_size,
                segment.framing_size,
                share,
            )
            for stream in segment.streams:
                _LOGGER.info(
                    "STREAM segment=%s name=%s raw=%d stored=%d",
                    segment.name,
                    stream.name,
                    stream.original_size,
                    stream.stored_size,
                )


def main(argv: list[str] | None = None) -> int:
    """Run the CLI.

    Args:
        argv: Optional arguments excluding the executable name.

    Returns:
        Process exit code.
    """

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = _parser().parse_args(argv)
    try:
        if args.command == "encode":
            _write(args.output, compress(_read(args.input), preset=args.preset))
        elif args.command == "decode":
            _write(args.output, decompress(_read(args.input)))
        elif args.command == "bench":
            _bench(args.inputs, args.preset)
        else:
            _profile(args.inputs, args.preset)
    except (BinCompressError, OSError, ValueError) as error:
        _LOGGER.error("%s", error)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
