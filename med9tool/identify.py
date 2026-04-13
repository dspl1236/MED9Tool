"""
ROM identification for MED9 ECU firmware.

Detects variant (MED9.1/MED9.5), VAG part number, RTOS version,
and key calibration landmarks in MPC5xx binaries.

MPC5xx is big-endian PowerPC — all multi-byte values use big-endian
byte order, opposite of TriCore (little-endian).
"""

from __future__ import annotations

import re
import struct
import zlib
from dataclasses import dataclass, field

from .variants import ECUVariant, detect_variant


@dataclass
class ROMInfo:
    """ROM identification results."""
    file_size: int = 0
    crc32: int = 0
    variant: ECUVariant | None = None
    vag_part_number: str = ""
    rtos_version: str = ""
    cal_start: int = 0
    cal_end: int = 0
    byte_order: str = "big"  # MPC5xx = big endian


def identify_rom(data: bytes) -> ROMInfo:
    """Identify a MED9 ROM binary."""
    info = ROMInfo(
        file_size=len(data),
        crc32=zlib.crc32(data) & 0xFFFFFFFF,
    )

    info.variant = detect_variant(data)
    info.vag_part_number = _find_vag_pn(data)
    info.rtos_version = _find_rtos(data)
    info.cal_start, info.cal_end = _find_cal_area(data)

    return info


def _find_vag_pn(data: bytes) -> str:
    """Find VAG part number (e.g., 03H906032A)."""
    text = data.decode("latin-1", errors="replace")
    patterns = [
        re.compile(r'(03H\s*906\s*\d{3}\s*[A-Z]{0,3})'),
        re.compile(r'(1K0\s*907\s*\d{3}\s*[A-Z]{0,3})'),
        re.compile(r'([0-9A-Z]{3}\s*906\s*\d{3}\s*[A-Z]{0,3})'),
        re.compile(r'([0-9A-Z]{3}\s*907\s*\d{3}\s*[A-Z]{0,3})'),
    ]
    for pat in patterns:
        m = pat.search(text)
        if m:
            return m.group(1).replace(" ", "")
    return ""


def _find_rtos(data: bytes) -> str:
    """Find ERCOSEK/RTOS version string."""
    text = data.decode("latin-1", errors="replace")
    m = re.search(r'(ERCOSEK\s+V[\d.]+\s+MPC\d+\w*)', text)
    if m:
        return m.group(1)
    return ""


def _find_cal_area(data: bytes) -> tuple[int, int]:
    """Estimate calibration data area boundaries.

    MED9.1 typically has cal data in the 0x1C0000-0x1E0000 range
    (where speed limiters and map tables are concentrated).
    """
    text = data.decode("latin-1", errors="replace")

    # Look for CAL DATA marker
    pos = text.find("CAL DATA")
    if pos > 0:
        # Cal typically starts around 0x1C0000 for MED9.1
        return (0x1C0000, min(len(data), 0x1E0000))

    # Fallback: estimate from file size
    if len(data) > 0x400000:  # 4MB+
        return (0x1C0000, 0x1E0000)
    elif len(data) > 0x180000:  # 1.5MB+
        return (0x100000, 0x180000)
    return (0, 0)
