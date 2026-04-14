"""
Binary scanner for MED9 ECU firmware (MPC5xx, big-endian PowerPC).

KEY DIFFERENCE FROM TRICORETOOL: MPC5xx is BIG ENDIAN.
All multi-byte values use struct.unpack_from(">H") not ("<H").

MED9.1 flash layout (03H906032, Cayenne 3.6L VR6):
  Image spans 0x00000000 – 0x0047FFFF (4.5 MB).
  Section 5 @ 0x1C0000:  256 KB  — calibration parameters
    Header  @ 0x1C2000:  magic 5A5A5A5A CCCCCCCC + pointer table
    Sentinel@ 0x1C2080:  AFFE0815 (ERCOSEK sub-segment marker)
    Cal data @ 0x1C2100+: ignition/fuel maps, speed/rev limiters, etc.
  Section 3 @ 0x0A0000: 1.15 MB  — main application code

Speed limiter encoding:
  uint16 big-endian, km/h × 100  (e.g. 25000 = 250.00 km/h)
  Located in section 5 (0x1C2000 – 0x1E0000).
  Typically appears ISOLATED: preceded by ≥ 6 consecutive zero bytes.

Rev limiter encoding:
  uint16 big-endian, RPM direct  (e.g. 7000 = 7000 RPM)
  May appear doubled (two consecutive identical values).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass


# Known round-number market speed limits (km/h × 100)
_MARKET_SPEEDS: set[int] = {
    20000, 21000, 24000, 25000, 25600, 25700, 26000,
    25500, 26500, 27000,
}


@dataclass
class ScanHit:
    """A scanner result with address and metadata."""
    name: str
    offset: int
    value: float = 0.0
    size_bytes: int = 2
    confidence: str = "medium"
    notes: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Section / calibration area detection
# ─────────────────────────────────────────────────────────────────────────────

_ERCOSEK_MAGIC = b"\x5A\x5A\x5A\x5A\xCC\xCC\xCC\xCC"  # section 5 header
_AFFE_SENTINEL = b"\xAF\xFE\x08\x15"                    # sub-section marker


def find_cal_area(data: bytes) -> tuple[int, int]:
    """
    Locate the calibration parameter area in a MED9 binary.

    Searches for the ERCOSEK segment header (5A5A5A5A CCCCCCCC) which
    marks the start of the calibration section.  Returns (cal_start, cal_end)
    as image offsets.

    Falls back to well-known defaults if the header isn't found.
    """
    # Primary: ERCOSEK header
    idx = data.find(_ERCOSEK_MAGIC)
    if idx >= 0:
        # Actual cal data starts after the pointer table (~0x100 bytes in)
        cal_start = idx + 0x100
        cal_end = min(len(data), idx + 0x40000)   # up to 256KB of cal
        return cal_start, cal_end

    # Secondary: AFFE0815 sentinel
    idx = data.find(_AFFE_SENTINEL)
    if idx >= 0:
        return idx, min(len(data), idx + 0x30000)

    # Fallback: well-known MED9.1 range
    if len(data) >= 0x1E0000:
        return 0x1C2000, 0x1E0000

    # Compact MED9.5 fallback
    return max(0, len(data) - 0x80000), len(data)


# ─────────────────────────────────────────────────────────────────────────────
# Speed limiter
# ─────────────────────────────────────────────────────────────────────────────

def find_speed_limiter(data: bytes) -> list[ScanHit]:
    """
    Find speed limiter candidates in a MED9 calibration area.

    Confirmed encoding: big-endian uint16, km/h × 100.
    Isolation fingerprint: ≥ 6 consecutive zero bytes immediately before
    the value, value in 18000–28000 range (180–280 km/h).

    False-positive rejection:
    - Value is part of a monotonically increasing axis (axis table)
    - No isolation (value embedded mid-table without zero prefix)
    - Value at an even 256-boundary below 200 km/h (map scaling artefact)
    """
    cal_start, cal_end = find_cal_area(data)
    seen_vals: dict[int, ScanHit] = {}      # best hit per distinct value

    for off in range(cal_start, min(cal_end, len(data) - 10), 2):
        v = struct.unpack_from(">H", data, off)[0]
        if not (18000 <= v <= 28000):
            continue

        # Isolation: require ≥ 6 zero bytes immediately before
        pre = data[max(0, off - 8) : off]
        zero_run = 0
        for b in reversed(pre):
            if b == 0:
                zero_run += 1
            else:
                break
        if zero_run < 6:
            continue

        # Reject ascending tables: if next 4 words all increase, it's a map axis
        try:
            words = [struct.unpack_from(">H", data, off + i * 2)[0]
                     for i in range(5)]
            if all(words[i] < words[i + 1] for i in range(4)):
                continue
        except struct.error:
            pass

        # Reject plain 0x4000-boundary values (common MPC5xx map scaling)
        if v % 0x4000 == 0 and v < 20000:
            continue

        kmh = v / 100.0
        is_market = v in _MARKET_SPEEDS
        confidence = "high" if is_market else (
            "medium" if zero_run >= 8 else "low"
        )

        hit = ScanHit(
            name="VMAX",
            offset=off,
            value=kmh,
            confidence=confidence,
            notes=f"{v} ({kmh:.1f} km/h) isolated={zero_run}B BE",
        )

        # Keep best confidence per distinct value
        if v not in seen_vals or (
            _conf_rank(confidence) > _conf_rank(seen_vals[v].confidence)
        ):
            seen_vals[v] = hit

    # Sort: market values first (highest speed first), then by confidence
    def _sort_key(h: ScanHit) -> tuple:
        v = int(h.value * 100)
        return (0 if v in _MARKET_SPEEDS else 1, -v)

    return sorted(seen_vals.values(), key=_sort_key)[:10]


def _conf_rank(conf: str) -> int:
    return {"high": 2, "medium": 1, "low": 0}.get(conf, 0)


# ─────────────────────────────────────────────────────────────────────────────
# Rev limiter
# ─────────────────────────────────────────────────────────────────────────────

def find_rev_limiter(data: bytes) -> list[ScanHit]:
    """
    Find rev limiter candidates (NMAXOGGA / NMAXGA per-gear table).

    Encoding: big-endian uint16, RPM direct.
    Range: 5000–9500 RPM (covers all known Cayenne V8, VR6, and TFSI variants).

    Two detection strategies, both scanning 0x1C0000–0x200000:

    1. Run-of-4 pattern (NMAXGA table): the per-gear RPM limit table stores
       the same value in 4–9+ consecutive uint16 slots.  Confirmed in BG/BE/DA/L
       Cayenne variants.  High confidence.

    2. Doubled-pair pattern (NMAXOGGA scalar): single value stored twice.
       Two variants:
         a. Neighbours are RPM-like (1000–9500): high confidence.
         b. Neighbours are not RPM-like: medium confidence (Cayenne Turbo
            cal sections often have non-RPM data adjacent to NMAXOGGA).
    """
    scan_start = 0x1C0000
    scan_end   = min(0x200000, len(data) - 6)

    hits: list[ScanHit] = []
    seen: set[int] = set()

    off = scan_start
    while off < scan_end:
        v = struct.unpack_from(">H", data, off)[0]

        if not (5000 <= v <= 9500):
            off += 2
            continue
        if off in seen:
            off += 2
            continue

        # Measure run length
        run = 1
        while (off + run * 2 < scan_end and
               struct.unpack_from(">H", data, off + run * 2)[0] == v):
            run += 1

        if run >= 4:
            # Run-of-4+: strong NMAXGA per-gear table
            hits.append(ScanHit(
                name="NMAXGA",
                offset=off,
                value=float(v),
                confidence="high" if 5000 <= v <= 9200 else "medium",
                notes=f"{v} RPM run×{run} BE (per-gear table)",
            ))
            for i in range(run):
                seen.add(off + i * 2)
            off += run * 2
            continue

        if run >= 2:
            # Doubled-pair: check neighbours
            pre1 = struct.unpack_from(">H", data, off - 2)[0] if off >= scan_start + 2 else 0
            nxt2_off = off + 4
            nxt2 = struct.unpack_from(">H", data, nxt2_off)[0] if nxt2_off < scan_end else 0

            pre_ok = pre1 == 0 or 1000 <= pre1 <= 9500
            nxt_ok = nxt2 == 0 or 1000 <= nxt2 <= 9500

            conf = "high" if (pre_ok and nxt_ok) else "medium"
            hits.append(ScanHit(
                name="NMAX",
                offset=off,
                value=float(v),
                confidence=conf,
                notes=f"{v} RPM doubled BE"
                      + ("" if pre_ok and nxt_ok else " (non-RPM neighbours)"),
            ))
            seen.add(off)
            seen.add(off + 2)

        off += 2

    # Deduplicate by RPM value; prefer high-confidence and earlier address
    seen_vals: dict[int, ScanHit] = {}
    for h in sorted(hits, key=lambda h: (0 if h.confidence == "high" else 1, h.offset)):
        iv = int(h.value)
        if iv not in seen_vals:
            seen_vals[iv] = h

    result = sorted(seen_vals.values(), key=lambda h: -h.value)
    return result[:8]


# ─────────────────────────────────────────────────────────────────────────────
# Main scanner
# ─────────────────────────────────────────────────────────────────────────────

def scan_binary(data: bytes) -> dict[str, list[ScanHit]]:
    """Run all scanners on a MED9 binary. Returns dict of category → hits."""
    cal_start, cal_end = find_cal_area(data)
    return {
        "speed_limiter": find_speed_limiter(data),
        "rev_limiter": find_rev_limiter(data),
        "_cal_range": [ScanHit(
            "CAL_RANGE", cal_start,
            notes=f"0x{cal_start:06X}–0x{cal_end:06X}",
        )],
    }


# ─────────────────────────────────────────────────────────────────────────────
# FR-database-aware annotated scan
# ─────────────────────────────────────────────────────────────────────────────

def annotate_hits(hits: list[ScanHit], category: str) -> list[ScanHit]:
    """
    Cross-reference scan hits against the FR parameter database.

    Adds the canonical Bosch parameter name to hits whose values match
    known defaults (e.g. VMAXNB=250 km/h → notes: "VMAXNB default").
    """
    from .fr_database import BGVMAX_PARAMS

    if category == "speed_limiter":
        for hit in hits:
            raw = round(hit.value * 100)
            for name, param in BGVMAX_PARAMS.items():
                if param.default is not None:
                    try:
                        expected_raw = round(param.default * 100)
                        if abs(raw - expected_raw) <= 5:   # ±0.05 km/h tolerance
                            hit.notes += f"  [{name} default={param.default}]"
                            if param.default == 250.0:
                                hit.confidence = "high"
                    except Exception:
                        pass
    return hits
