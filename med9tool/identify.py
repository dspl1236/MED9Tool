"""
ROM identification for MED9 ECU firmware (MPC5xx big-endian PowerPC).

Detects variant (MED9.1/MED9.5), VAG part number, RTOS/ERCOSEK version,
and the calibration area boundaries.
"""
from __future__ import annotations

import re
import zlib
from dataclasses import dataclass

from .variants import ECUVariant, detect_variant
from .scanner import find_cal_area


@dataclass
class ROMInfo:
    """ROM identification results."""
    file_size: int = 0
    crc32: int = 0
    variant: ECUVariant | None = None
    vag_part_number: str = ""
    sw_version: str = ""
    rtos_version: str = ""
    cal_start: int = 0
    cal_end: int = 0
    byte_order: str = "big"   # MPC5xx = big endian


def identify_rom(data: bytes) -> ROMInfo:
    """Identify a MED9 ROM binary."""
    info = ROMInfo(
        file_size=len(data),
        crc32=zlib.crc32(data) & 0xFFFFFFFF,
    )
    info.variant = detect_variant(data)
    info.vag_part_number = _find_vag_pn(data)
    info.sw_version = _find_sw_version(data)
    info.rtos_version = _find_rtos(data)
    info.cal_start, info.cal_end = find_cal_area(data)
    return info


def _find_vag_pn(data: bytes) -> str:
    """Find VAG part number (e.g. 03H906032BE)."""
    text = data.decode("latin-1", errors="replace")
    patterns = [
        # MED9.1 Cayenne / Golf VR6
        re.compile(r'(03H\s*906\s*0(?:32|26)\s*[A-Z]{0,3})'),
        # Golf V / Jetta MED9.1 early
        re.compile(r'(1K0\s*907\s*\d{3}\s*[A-Z]{0,3})'),
        # Generic VAG engine ECU PN
        re.compile(r'([0-9][0-9A-Z]{2}\s*906\s*\d{3}\s*[A-Z]{0,3})'),
    ]
    for pat in patterns:
        m = pat.search(text)
        if m:
            return m.group(1).replace(" ", "").upper()
    return ""


def _find_sw_version(data: bytes) -> str:
    """Find MED9 software version string (e.g. MED91/3/6W6432.D)."""
    text = data.decode("latin-1", errors="replace")
    m = re.search(r'(MED9[015.]+/[\w./]+)', text)
    if m:
        return m.group(1)[:30]
    return ""


def _find_rtos(data: bytes) -> str:
    """Find ERCOSEK RTOS version string."""
    text = data.decode("latin-1", errors="replace")
    m = re.search(r'(ERCOSEK\s+V[\d.]+\s+MPC\w*)', text)
    if m:
        return m.group(1)
    return ""
