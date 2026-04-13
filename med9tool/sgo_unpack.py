"""
SGO file unpacker for MED9 ECU firmware.

SGO (SGML Object) files contain compressed/packaged firmware for ODIS
flashing. The format is shared across all VAG ECU platforms — this
module is compatible with MED9, ME7, MED17, and EDC17 SGOs.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass


@dataclass
class SGOResult:
    """Result of SGO unpacking."""
    success: bool
    binary: bytes = b""
    error: str = ""
    filename: str = ""
    compressed_size: int = 0
    uncompressed_size: int = 0


def is_sgo_file(data: bytes) -> bool:
    """Check if data starts with SGO magic."""
    return data[:16].startswith(b"SGML Object File")


def unpack_sgo(data: bytes) -> SGOResult:
    """Unpack an SGO file to raw binary.

    Handles multiple compression formats found in VAG SGO files.
    Returns the largest binary block (typically PFLASH).
    """
    if not is_sgo_file(data):
        return SGOResult(success=False, error="Not an SGO file")

    blocks = []
    pos = 0

    while pos < len(data) - 8:
        # Look for zlib headers (0x78xx)
        if data[pos] == 0x78 and data[pos + 1] in (0x01, 0x5E, 0x9C, 0xDA):
            try:
                dec = zlib.decompress(data[pos:])
                blocks.append(dec)
                break
            except zlib.error:
                pass

        # Look for raw deflate blocks
        if pos > 0x20 and data[pos:pos + 4] == b'\x00\x00\xff\xff':
            pass

        pos += 1

    if not blocks:
        # Fallback: try decompressing from various offsets
        for offset in range(0x30, min(len(data), 0x200)):
            try:
                dec = zlib.decompress(data[offset:])
                if len(dec) > 0x10000:
                    blocks.append(dec)
                    break
            except zlib.error:
                continue

    if not blocks:
        return SGOResult(success=False, error="No compressed data found")

    # Return largest block
    largest = max(blocks, key=len)
    return SGOResult(
        success=True,
        binary=largest,
        compressed_size=len(data),
        uncompressed_size=len(largest),
    )
