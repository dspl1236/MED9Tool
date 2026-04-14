"""
Named patch presets for MED9.x ECUs.

A preset is a named collection of patches that are commonly applied together.
Each preset documents what it does and what data it requires.

Usage:
    from med9tool.presets import apply_preset, list_presets

    patched = apply_preset(data, "swap_full")
    patched = apply_preset(data, "emissions_full")
    patched = apply_preset(data, "speed_remove")
"""

from __future__ import annotations
from dataclasses import dataclass

from .immo_patches  import apply_immo_brute, apply_dtc_disable, CD_PARAMS_1K0907115
from .patches       import apply_speed_remove as _patches_speed_remove
from .patches       import apply_rev_raise as _patches_rev_raise
from .checksum      import checksum_status


@dataclass
class PresetResult:
    preset_name: str
    steps: list[str]          # what was applied
    warnings: list[str]       # non-fatal issues
    bytes_changed: int


def _diff(original: bytes, patched: bytes) -> int:
    return sum(a != b for a, b in zip(original, patched))


def preset_speed_remove(data: bytes) -> tuple[bytes, PresetResult]:
    """Remove top speed limiter (VMAXNB KL patch)."""
    buf = bytearray(data)
    r = _patches_speed_remove(buf)
    patched = bytes(buf)
    steps = [f"{p.name}: {p.old_value} → {p.new_value}  {p.notes}" for p in r.patches if p.success]
    return patched, PresetResult(
        preset_name="speed_remove",
        steps=steps or ["VMAXNB per-gear KL → 0xFFFC (655 km/h) — no hits found"],
        warnings=[] if r.applied else ["Speed limiter not found in binary"],
        bytes_changed=_diff(data, patched),
    )


def preset_rev_raise(data: bytes, target_rpm: int = 8800) -> tuple[bytes, PresetResult]:
    """Raise rev limit."""
    buf = bytearray(data)
    r = _patches_rev_raise(buf, target_rpm)
    patched = bytes(buf)
    steps = [f"{p.name}: {p.old_value} → {p.new_value}  {p.notes}" for p in r.patches if p.success]
    return patched, PresetResult(
        preset_name="rev_raise",
        steps=steps or [f"NMAXOGGA → {target_rpm} RPM — no hits found"],
        warnings=["Verify NMAX (hard cutoff) is also raised if needed"],
        bytes_changed=_diff(data, patched),
    )


def preset_emissions_full(data: bytes) -> tuple[bytes, PresetResult]:
    """
    Disable all emissions-related diagnostics.

    Zeroes all CD* diagnostic enable parameters:
      CDKAT, CDKATSP : catalyst monitor
      CDHSH, CDHSV   : downstream O2 heater/voltage
      CDLASH, CDLSH, CDLSV : O2 adaptation/heater/voltage
      CDLATP         : lambda adaptation plausibility
      CDSLS          : secondary air injection (usually already 0)
      CDTES          : exhaust temperature sensor
      CWKONABG       : EGR configuration codeword
      CWKONLS        : lambda sensor config codeword

    Addresses confirmed for 1K0907115S via community XDF.
    Cayenne 03H906032 addresses not yet confirmed (different cal layout).
    """
    patched = apply_dtc_disable(data)
    steps = [f"CD param 0x{p.addr:06X} {p.name} → 0x{p.patch_val:02X}" 
             for p in CD_PARAMS_1K0907115 if data[p.addr] != p.patch_val]
    warnings = []
    if not steps:
        warnings.append("All CD params already at target values — no changes made")
    return patched, PresetResult(
        preset_name="emissions_full",
        steps=steps or ["(no changes needed)"],
        warnings=warnings,
        bytes_changed=_diff(data, patched),
    )


def preset_immo_off(data: bytes) -> tuple[bytes, PresetResult]:
    """
    Brute-force immo-off: NOP all flag-gate branches and poll loops
    in the PowerPC code section.

    392 patches in 1K0907115S, 323-385 in Cayenne variants.

    NOTE: EEPROM immo byte (0x59 in EEPROM dump) is the more surgical
    alternative. This flash-level approach survives without EEPROM access.
    Checksum: ECU recalculates via requestCalculateChecksum on KWP2000 flash.
    BDM flash: checksum at 0x1C2080 remains AFFE placeholder — bootloader
    will reject unless using a BSL that skips checksum validation.
    """
    patched = apply_immo_brute(data)
    n = _diff(data, patched) // 4   # 4 bytes per NOP
    return patched, PresetResult(
        preset_name="immo_off",
        steps=[f"{n} PowerPC branches NOPed with 0x60000000 (ori r0,r0,0)",
               "Flag-gate branches (lbz→cmpwi→bc_fwd≥100B) → NOP",
               "Polling loops (tight backward bc with compare) → NOP"],
        warnings=[
            "Brute-force: also NOPs other feature gates (limp-mode, etc.)",
            "EEPROM immo byte (0x59) is more surgical — use if EEPROM accessible",
            checksum_status(data),
        ],
        bytes_changed=_diff(data, patched),
    )


def preset_swap_full(data: bytes) -> tuple[bytes, PresetResult]:
    """
    Full swap preset: immo-off + speed remove + emissions full.

    Combines all patches needed for a standalone engine swap:
      1. Immo-off (flash brute-force)
      2. Speed limiter removed
      3. All emissions diagnostics disabled

    Use this when dropping a MED9.1 engine into a vehicle without
    the original CAN bus / instrument cluster for immo clearance.
    """
    steps: list[str] = []
    warnings: list[str] = []

    # 1. Immo-off
    p1, r1 = preset_immo_off(data)
    steps.extend(r1.steps)
    warnings.extend(r1.warnings)

    # 2. Speed remove
    p2, r2 = preset_speed_remove(p1)
    steps.extend(r2.steps)
    warnings.extend(r2.warnings)

    # 3. Emissions
    p3, r3 = preset_emissions_full(p2)
    steps.extend(r3.steps)
    warnings.extend(r3.warnings)

    return p3, PresetResult(
        preset_name="swap_full",
        steps=steps,
        warnings=warnings,
        bytes_changed=_diff(data, p3),
    )


_PRESETS = {
    "speed_remove":     (preset_speed_remove,    "Remove top speed limiter"),
    "rev_raise":        (preset_rev_raise,        "Raise rev limit to 8800 RPM"),
    "emissions_full":   (preset_emissions_full,   "Disable all emissions diagnostics (CD params)"),
    "immo_off":         (preset_immo_off,         "Brute-force immobilizer bypass (flash NOP)"),
    "swap_full":        (preset_swap_full,        "Full swap: immo-off + speed remove + emissions"),
}


def list_presets() -> dict[str, str]:
    """Return {preset_name: description}."""
    return {k: v[1] for k, v in _PRESETS.items()}


def apply_preset(data: bytes, preset_name: str, **kwargs) -> tuple[bytes, PresetResult]:
    """
    Apply a named preset to binary data.

    Args:
        data:        Raw binary bytes.
        preset_name: One of the keys from list_presets().
        **kwargs:    Passed to the preset function (e.g. target_rpm for rev_raise).

    Returns:
        (patched_bytes, PresetResult)
    """
    if preset_name not in _PRESETS:
        raise ValueError(
            f"Unknown preset {preset_name!r}. "
            f"Available: {', '.join(_PRESETS)}"
        )
    fn = _PRESETS[preset_name][0]
    return fn(data, **kwargs)
