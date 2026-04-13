"""
Binary scanner for MED9 ECU firmware.

Scans MPC5xx (big-endian PowerPC) binaries for calibration data:
speed limiters, ignition maps, injection maps, and diagnostic codes.

KEY DIFFERENCE FROM TRICORETOOL: MPC5xx is BIG ENDIAN.
All multi-byte values are stored MSB-first.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass
class ScanHit:
    """A scanner result with address and metadata."""
    name: str
    offset: int
    value: float = 0.0
    size_bytes: int = 2
    confidence: str = "medium"
    notes: str = ""


def find_speed_limiter(data: bytes) -> list[ScanHit]:
    """Find speed limiter values in MED9 binary.

    MED9 uses big-endian uint16 for speed in km/h * 100.
    Common values: 18000 (180), 20000 (200), 25000 (250), 25700 (257).

    The strongest pattern is a cluster of identical values (speed
    limiter table with same value repeated for different gears).
    """
    hits = []
    seen = set()

    for off in range(0x1C0000, min(len(data) - 10, 0x1E0000), 2):
        v = struct.unpack_from(">H", data, off)[0]
        if not (15000 <= v <= 30000):
            continue

        # Check for cluster pattern: same value repeated 3+ times
        cluster = 0
        for delta in range(0, 20, 2):
            if off + delta + 2 <= len(data):
                v2 = struct.unpack_from(">H", data, off + delta)[0]
                if v2 == v:
                    cluster += 1
                else:
                    break

        if cluster >= 3 and off not in seen:
            hits.append(ScanHit(
                name="VMAX",
                offset=off,
                value=v / 100.0,
                confidence="high" if cluster >= 4 else "medium",
                notes=f"cluster of {cluster} × {v / 100:.0f} km/h (BE)",
            ))
            for d in range(0, cluster * 2, 2):
                seen.add(off + d)

    # Sort by confidence then address
    hits.sort(key=lambda h: (0 if h.confidence == "high" else 1, h.offset))
    return hits


def find_rev_limiter(data: bytes) -> list[ScanHit]:
    """Find rev limiter values (RPM cutoff).

    Common values: 6000-8000 RPM stored as big-endian uint16.
    """
    hits = []
    for off in range(0x1C0000, min(len(data) - 4, 0x1E0000), 2):
        v = struct.unpack_from(">H", data, off)[0]
        if 5500 <= v <= 8500:
            # Check context: nearby values should be in RPM range too
            if off >= 2:
                prev = struct.unpack_from(">H", data, off - 2)[0]
                nxt = struct.unpack_from(">H", data, off + 2)[0]
                if (4000 <= prev <= 9000) and (4000 <= nxt <= 9000):
                    hits.append(ScanHit(
                        name="NMAX",
                        offset=off,
                        value=float(v),
                        confidence="medium",
                        notes=f"{v} RPM (context: {prev}/{v}/{nxt})",
                    ))
    return hits


def scan_binary(data: bytes) -> dict[str, list[ScanHit]]:
    """Run all scanners on a MED9 binary."""
    return {
        "speed_limiter": find_speed_limiter(data),
        "rev_limiter": find_rev_limiter(data),
    }
