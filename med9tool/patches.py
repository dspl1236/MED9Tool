"""
Preset and patch engine for MED9 ECU firmware.

Applies calibration patches to MPC5xx binaries. All values are
stored big-endian (PowerPC byte order).

Presets:
  speed_remove   — Remove speed limiter (set to 655.34 km/h)
  rev_raise      — Raise rev limiter
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .scanner import find_speed_limiter, find_rev_limiter
from .fr_database import SPEED_REMOVE_RAW as SPEED_REMOVE_VALUE


@dataclass
class PatchResult:
    """Result of applying a single patch."""
    name: str
    success: bool
    address: int = 0
    old_value: str = ""
    new_value: str = ""
    notes: str = ""


@dataclass
class PresetResult:
    """Result of applying a preset (collection of patches)."""
    preset_name: str
    patches: list[PatchResult] = field(default_factory=list)

    @property
    def applied(self) -> int:
        return sum(1 for p in self.patches if p.success)

    @property
    def total(self) -> int:
        return len(self.patches)



def apply_speed_remove(data: bytearray) -> PresetResult:
    """Remove speed limiter by setting all speed limit values to max.

    MED9 stores speed as big-endian uint16 in km/h × 100.
    Finds clusters of identical speed values and overwrites them.
    """
    result = PresetResult(preset_name="speed_remove")
    hits = find_speed_limiter(bytes(data))

    if not hits:
        result.patches.append(PatchResult(
            name="VMAX", success=False,
            notes="No speed limiter found in binary",
        ))
        return result

    # Patch the highest-confidence cluster
    best = hits[0]
    patched = 0
    old_val = struct.unpack_from(">H", data, best.offset)[0]

    # Patch the entire cluster
    for off in range(best.offset, min(len(data) - 2, best.offset + 40), 2):
        v = struct.unpack_from(">H", data, off)[0]
        if v == old_val:
            struct.pack_into(">H", data, off, SPEED_REMOVE_VALUE)
            patched += 1
        else:
            break

    result.patches.append(PatchResult(
        name="VMAX",
        success=True,
        address=best.offset,
        old_value=f"{old_val / 100:.0f} km/h × {patched}",
        new_value=f"{SPEED_REMOVE_VALUE / 100:.0f} km/h",
        notes=f"Patched {patched} values at 0x{best.offset:06X} ({best.confidence})",
    ))
    return result


def apply_rev_raise(data: bytearray, target_rpm: int = 8000) -> PresetResult:
    """Raise rev limiter to target RPM."""
    result = PresetResult(preset_name="rev_raise")
    hits = find_rev_limiter(bytes(data))

    if not hits:
        result.patches.append(PatchResult(
            name="NMAX", success=False,
            notes="No rev limiter found",
        ))
        return result

    for hit in hits[:3]:  # Patch top 3 candidates
        old_val = struct.unpack_from(">H", data, hit.offset)[0]
        struct.pack_into(">H", data, hit.offset, target_rpm)
        result.patches.append(PatchResult(
            name="NMAX",
            success=True,
            address=hit.offset,
            old_value=f"{old_val} RPM",
            new_value=f"{target_rpm} RPM",
        ))

    return result


# Preset registry
PRESETS = {
    "speed_remove": {
        "name": "Speed Limiter Remove",
        "description": "Remove electronic speed limiter",
        "apply": apply_speed_remove,
    },
    "rev_raise": {
        "name": "Rev Limiter Raise",
        "description": "Raise rev limiter to 8000 RPM",
        "apply": apply_rev_raise,
    },
}
