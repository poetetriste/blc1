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


def test_ppmd_round_trip_above_pyppmd_single_shot_limit() -> None:
    """Regression: pyppmd mis-encodes single-shot inputs above ~4 MiB.

    The adapter must feed and drain the coder in bounded chunks, so a
    skeleton larger than the pyppmd limit still round-trips exactly.
    """

    import random

    rng = random.Random(20261112)  # noqa: S311 - deterministic test data, not crypto
    block = bytes(rng.randrange(256) for _ in range(256))
    source = (block * 64 + rng.randbytes(64)) * 640  # ~5.5 MiB of structured data
    assert len(source) > 4 << 20

    payload = compress(source)

    assert decompress(payload, len(source)) == source
