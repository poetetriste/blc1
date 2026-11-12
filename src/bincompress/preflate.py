"""Bounded ctypes adapter for the versioned preflate-rs 0.7 container DLL."""

from __future__ import annotations

import ctypes
from pathlib import Path

from bincompress.exceptions import FormatError

_DLL_PATH = Path(__file__).with_name("preflate_rs_0_7.dll")
_CHUNK_SIZE = 64 * 1024
_ERROR_SIZE = 1024


def _load_library() -> ctypes.CDLL | None:
    """Load and configure the optional versioned native library."""

    if not _DLL_PATH.is_file():
        return None
    library = ctypes.CDLL(str(_DLL_PATH))
    library.create_compression_context.argtypes = [ctypes.c_uint32]
    library.create_compression_context.restype = ctypes.c_void_p
    library.free_compression_context.argtypes = [ctypes.c_void_p]
    library.compress_buffer.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint64,
        ctypes.c_bool,
        ctypes.c_void_p,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.c_void_p,
        ctypes.c_uint64,
    ]
    library.compress_buffer.restype = ctypes.c_int32
    library.create_decompression_context.argtypes = [ctypes.c_uint32, ctypes.c_uint64]
    library.create_decompression_context.restype = ctypes.c_void_p
    library.free_decompression_context.argtypes = [ctypes.c_void_p]
    library.decompress_buffer.argtypes = library.compress_buffer.argtypes
    library.decompress_buffer.restype = ctypes.c_int32
    return library


_LIBRARY = _load_library()


def is_available() -> bool:
    """Return whether the pinned native preflate decoder is available."""

    return _LIBRARY is not None


def _error_text(buffer: ctypes.Array[ctypes.c_char]) -> str:
    """Decode the native zero-terminated error buffer safely."""

    return bytes(buffer).split(b"\0", 1)[0].decode("utf-8", errors="replace")


def _call_buffer(
    function: object,
    context: int,
    chunk: bytes,
    input_complete: bool,
) -> tuple[int, bytes]:
    """Call one native streaming step and copy its bounded output."""

    output = (ctypes.c_ubyte * _CHUNK_SIZE)()
    result_size = ctypes.c_uint64()
    error = ctypes.create_string_buffer(_ERROR_SIZE)
    input_buffer = (
        (ctypes.c_ubyte * len(chunk)).from_buffer_copy(chunk) if chunk else None
    )
    status = function(
        context,
        input_buffer,
        len(chunk),
        input_complete,
        output,
        len(output),
        ctypes.byref(result_size),
        error,
        len(error),
    )
    if status < 0:
        message = _error_text(error) or f"native preflate error {status}"
        raise FormatError(message)
    if result_size.value > len(output):
        raise FormatError("native preflate output exceeded its buffer")
    return status, bytes(output[: result_size.value])


def compress(data: bytes, *, level: int = 14) -> bytes:
    """Encode bytes into a verified preflate container.

    Args:
        data: Input containing possible DEFLATE or PNG streams.
        level: Internal Zstandard level from zero through fourteen.

    Raises:
        FormatError: If the native encoder is unavailable or fails.

    Returns:
        Bit-exact reconstruction container bytes.
    """

    if _LIBRARY is None:
        raise FormatError("preflate-rs 0.7 native encoder is unavailable")
    if not 0 <= level <= 14:
        raise ValueError("preflate level must be between zero and fourteen")
    context = _LIBRARY.create_compression_context(level | 0x20)
    if not context:
        raise FormatError("could not create native preflate encoder")
    output = bytearray()
    try:
        for offset in range(0, len(data), _CHUNK_SIZE):
            _, produced = _call_buffer(
                _LIBRARY.compress_buffer,
                context,
                data[offset : offset + _CHUNK_SIZE],
                False,
            )
            output.extend(produced)
        for _ in range(len(data) // _CHUNK_SIZE * 4 + 1024):
            status, produced = _call_buffer(
                _LIBRARY.compress_buffer, context, b"", True
            )
            output.extend(produced)
            if status == 1:
                return bytes(output)
        raise FormatError("native preflate encoder did not terminate")
    finally:
        _LIBRARY.free_compression_context(context)


def decompress(payload: bytes, expected_size: int) -> bytes:
    """Recreate exact bytes from a bounded preflate container.

    Args:
        payload: Versioned preflate container bytes.
        expected_size: Exact permitted reconstructed size.

    Raises:
        FormatError: If the decoder is unavailable, malformed, or exceeds its bound.

    Returns:
        Original bytes.
    """

    if _LIBRARY is None:
        raise FormatError("preflate-rs 0.7 native decoder is unavailable")
    if expected_size < 0:
        raise ValueError("expected size cannot be negative")
    context = _LIBRARY.create_decompression_context(0, expected_size)
    if not context:
        raise FormatError("could not create native preflate decoder")
    output = bytearray()
    try:
        for offset in range(0, len(payload), _CHUNK_SIZE):
            _, produced = _call_buffer(
                _LIBRARY.decompress_buffer,
                context,
                payload[offset : offset + _CHUNK_SIZE],
                False,
            )
            output.extend(produced)
            if len(output) > expected_size:
                raise FormatError("preflate output exceeds the declared size")
        for _ in range(expected_size // _CHUNK_SIZE + 1024):
            status, produced = _call_buffer(
                _LIBRARY.decompress_buffer, context, b"", True
            )
            output.extend(produced)
            if len(output) > expected_size:
                raise FormatError("preflate output exceeds the declared size")
            if status == 1:
                if len(output) != expected_size:
                    raise FormatError("preflate output size does not match")
                return bytes(output)
        raise FormatError("native preflate decoder did not terminate")
    finally:
        _LIBRARY.free_decompression_context(context)
