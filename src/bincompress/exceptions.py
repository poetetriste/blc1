"""Application exceptions."""


class BinCompressError(Exception):
    """Base exception for the binary compressor."""


class FormatError(BinCompressError):
    """Raised when an archive or executable structure is invalid."""


class IntegrityError(BinCompressError):
    """Raised when decoded bytes fail an integrity check."""
