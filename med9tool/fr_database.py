"""
MED9.1 Funktionsrahmen parameter database.

All entries confirmed from:
  Bosch Funktionsrahmen MED9-1, EA827 TSI, 41W038_PQ35
  System SG-MED9-1, Author Alexander Frick, 20.AUG.2004

Encoding conventions (all confirmed from FR):
  Speed (VMAX*): big-endian uint16, km/h × 100
    PHY = raw / 100  →  raw = km/h × 100
    Example: VMAXNB = 250 km/h → raw 25000 = 0x61A8

  Rev limit (NMAX*): big-endian uint16, direct RPM
    PHY = raw  →  raw = RPM
    Example: NMAX = 6400 rpm → raw 6400 = 0x1900

  NMAXKBI (CAN field only): PHY = 100.INT (÷100 from CAN integer)
    Not used for internal ECU storage.

BGVMAX function block (speed limiting):
  VMAXNB  — normal operation speed limit           default 250 km/h
  VMAXEB  — emergency fallback (sensor fail)        default  70 km/h
  VMAXTMEB— temperature-limited fallback            default 511.992 km/h (∞)
  VMAXESP — ESP deactivated limit                   default 200 km/h
  VMAXNIV — level-control active limit              default  80 km/h
  VMAXPNG — planetary gearbox active limit          default  50 km/h
  VMAXTM  — f(engine temp), all defaults 511.992 km/h
  VMAXTOL — f(oil temp),    all defaults 511.992 km/h

NMAXMD function block (rev limiting):
  NMAX    — hard diagnostic rev cutoff              default ~6400 RPM (FW)
  NMAXGA  — per-gear stationary limit               KL indexed by gangist
  NMAXOGGA— per-gear brief overspeed allowance      KL indexed by gangist
  NMAXF   — sensor-fail diagnostic limit            default 16384 RPM (=0x4000, ∞)
  NMAXDV  — speed-signal-fail limit (manual gearbox) FW
  NMAXNL  — rev limit in speed-sensor limp home     FW
  NMAXKR  — rev limit at knock retard safety        FW
  NMAXHMM — rev limit in lean-homogeneous mode      FW (BDE only)
  NMAXSCH — rev limit in stratified mode            FW (BDE only)

Source: FR page 495 (BGVMAX APP defaults table), pages 485-487 (NMAXMD ABK).
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class FRParam:
    """One calibration parameter from the Funktionsrahmen."""
    name: str
    description: str
    unit: str
    encoding: str        # "be_u16_x100" | "be_u16_direct" | "KL" | "FW_other"
    default: float | None = None
    default_notes: str = ""
    page: int | None = None   # FR PDF page number


# ─────────────────────────────────────────────────────────────────────────────
# BGVMAX — Berechnungsgröße Maximalgeschwindigkeit für VMAX-Regelung
# Source: FR page 495 defaults table
# ─────────────────────────────────────────────────────────────────────────────
BGVMAX_PARAMS: dict[str, FRParam] = {
    "VMAXNB": FRParam(
        name="VMAXNB",
        description="Max-Geschwindigkeit Normalbetrieb (normal operation speed limit)",
        unit="km/h",
        encoding="be_u16_x100",
        default=250.0,
        default_notes="raw=25000=0x61A8; raised to 0xFFFC to remove",
        page=495,
    ),
    "VMAXEB": FRParam(
        name="VMAXEB",
        description="Ersatzwert Geschwindigkeit (emergency fallback speed)",
        unit="km/h",
        encoding="be_u16_x100",
        default=70.0,
        default_notes="raw=7000=0x1B58; activated on CAN/sensor fault",
        page=495,
    ),
    "VMAXTMEB": FRParam(
        name="VMAXTMEB",
        description="Ersatzwert Geschwindigkeit bei Temperaturüberschreitung (temp fallback)",
        unit="km/h",
        encoding="be_u16_x100",
        default=511.992,
        default_notes="raw=0xFFFF; effectively unlimited",
        page=495,
    ),
    "VMAXESP": FRParam(
        name="VMAXESP",
        description="Max-Geschwindigkeit bei ESP-Ausfall (ESP deactivated limit)",
        unit="km/h",
        encoding="be_u16_x100",
        default=200.0,
        default_notes="raw=20000=0x4E20",
        page=495,
    ),
    "VMAXNIV": FRParam(
        name="VMAXNIV",
        description="Max-Geschwindigkeit bei Niveauregelung (level control active)",
        unit="km/h",
        encoding="be_u16_x100",
        default=80.0,
        default_notes="raw=8000=0x1F40; SY_CANNIV must be set",
        page=495,
    ),
    "VMAXPNG": FRParam(
        name="VMAXPNG",
        description="Max-Geschwindigkeit bei Planetennachgelege (planetary gearbox active)",
        unit="km/h",
        encoding="be_u16_x100",
        default=50.0,
        default_notes="raw=5000=0x1388; SY_CANALL must be set",
        page=495,
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# NMAXMD — Drehzahlbegrenzung (rev limiting)
# Source: FR pages 484–491 (NMAXMD section), page 487 ABK table
# ─────────────────────────────────────────────────────────────────────────────
NMAXMD_PARAMS: dict[str, FRParam] = {
    "NMAX": FRParam(
        name="NMAX",
        description="Drehzahlbegrenzung — hard PI-controller rev cutoff",
        unit="rpm",
        encoding="be_u16_direct",
        default=None,
        default_notes="vehicle-specific; set by NMAXGA/NMAXOGGA logic",
        page=487,
    ),
    "NMAXGA": FRParam(
        name="NMAXGA",
        description="Max. zulässige Motordrehzahl stationär, per-gear KL (stationary limit)",
        unit="rpm",
        encoding="KL",
        default=None,
        default_notes="KL indexed by gangist (gear); typical 6000-6800 rpm",
        page=487,
    ),
    "NMAXOGGA": FRParam(
        name="NMAXOGGA",
        description="Max. zulässige Motordrehzahl kurzzeitig, per-gear KL (brief overspeed)",
        unit="rpm",
        encoding="KL",
        default=None,
        default_notes="KL indexed by gangist; slightly above NMAXGA",
        page=487,
    ),
    "NMAXF": FRParam(
        name="NMAXF",
        description="Drehzahlgrenze Diagnosefehler DNMAX (sensor-fail diagnostic limit)",
        unit="rpm",
        encoding="be_u16_direct",
        default=16384.0,
        default_notes="raw=0x4000; effectively no limit (fault state)",
        page=490,
    ),
    "NMAXDV": FRParam(
        name="NMAXDV",
        description="Drehzahlbegrenzung bei Fehler Fahrzeuggeschwindigkeitssignal",
        unit="rpm",
        encoding="be_u16_direct",
        default=None,
        default_notes="manual gearbox: set to prevent VMAX exceedance in top gear",
        page=487,
    ),
    "NMAXNL": FRParam(
        name="NMAXNL",
        description="Drehzahlgrenze bei Drehzahlgeber-Notlauf (speed-sensor limp home)",
        unit="rpm",
        encoding="be_u16_direct",
        default=None,
        page=487,
    ),
    "NMAXKR": FRParam(
        name="NMAXKR",
        description="Drehzahlgrenze bei Klopfregelung-Sicherheitsspätverstellung",
        unit="rpm",
        encoding="be_u16_direct",
        default=None,
        page=487,
    ),
    "NMAXSBT": FRParam(
        name="NMAXSBT",
        description="Maximale Drehzahl für TesterKommunikation (tester comms max rpm)",
        unit="rpm",
        encoding="be_u16_direct",
        default=None,
        page=487,
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# Combined lookup
# ─────────────────────────────────────────────────────────────────────────────
ALL_PARAMS: dict[str, FRParam] = {**BGVMAX_PARAMS, **NMAXMD_PARAMS}


def get_param(name: str) -> FRParam | None:
    """Look up a parameter by name. Returns None if not in database."""
    return ALL_PARAMS.get(name)


def raw_to_phys(param: FRParam, raw: int) -> float:
    """Convert a raw integer value to physical units."""
    if param.encoding == "be_u16_x100":
        return raw / 100.0
    if param.encoding == "be_u16_direct":
        return float(raw)
    raise ValueError(f"Cannot convert KL/FW_other param {param.name} with raw_to_phys")


def phys_to_raw(param: FRParam, physical: float) -> int:
    """Convert a physical value to raw integer for writing to binary."""
    if param.encoding == "be_u16_x100":
        return round(physical * 100) & 0xFFFF
    if param.encoding == "be_u16_direct":
        return round(physical) & 0xFFFF
    raise ValueError(f"Cannot convert KL/FW_other param {param.name} with phys_to_raw")


# Removal sentinel values
SPEED_REMOVE_RAW   = 0xFFFC  # 655.32 km/h — effectively unlimited
SPEED_REMOVE_PHYS  = 655.32
