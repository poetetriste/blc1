import pytest

from bincompress.exceptions import FormatError, IntegrityError
from bincompress.ppmd import compress, decompress


def test_ppmd_round_trip() -> None:
    source = b"\x48\x8b\x00\x00\x00\x00\x00" * 4096

    payload = compress(source)

    assert decompress(payload, len(source)) == source


def test_ppmd_rejects_truncated_payload() -> None:
    payload = compress(b"structured instruction skeleton" * 1024)

    with pytest.raises((FormatError, IntegrityError)):
        decompress(payload[:-2], 31 * 1024)


def test_ppmd_rejects_output_beyond_declared_size() -> None:
    source = bytes(range(256)) * 64
    payload = compress(source)

    with pytest.raises(FormatError, match=r"declared|terminator"):
        decompress(payload, len(source) - 1)


def test_ppmd_rejects_unknown_order() -> None:
    with pytest.raises(FormatError, match="order"):
        decompress(b"\xffpayload", 1)


def test_ppmd_rejects_truncated_header() -> None:
    with pytest.raises(FormatError, match="header"):
        decompress(b"", 0)
