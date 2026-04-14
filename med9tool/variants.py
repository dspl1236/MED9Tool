"""
ECU variant database for MPC5xx-based Bosch MED9 ECUs.

MED9 = Motronic Electronic Direct Injection, generation 9.
Gasoline direct injection ECUs using Freescale MPC5xx PowerPC.
Predecessor to MED17 (TriCore). Successor to ME7 (port injection).

Hardware architecture (confirmed from MPC5554 data sheet, Rev. 4):
  CPU core:    Power Architecture embedded (100% PowerPC ISA compatible)
               + DSP extensions, big-endian
  Flash:       H7Fa internal flash, up to 4MB depending on variant
               Low blocks:  16KB + 48KB + 64KB at 0x000000
               High blocks: 128KB × N up to 0x3FFFFF
  SRAM:        64KB on-chip at 0x40000000
  Cache:       32KB unified
  Timers:      2× eTPU (32 ch each), eMIOS (24 ch)
  ADC:         eQADC 40-channel
  Serial:      FlexCAN, DSPI, eSCI
  EBI:         External Bus Interface — used by Bosch for external cal flash

Memory map in MED9.1 (03H906032 Cayenne):
  0x000000 - 0x1FFFFF  Internal flash (2MB):
    0x020000 - 0x07FFFF  Code section 2 (384KB)
    0x080000 - 0x09FFFF  Code section 4 (128KB)
    0x0A0000 - 0x1BFFFF  Main application section 3 (1152KB)
    0x1C0000 - 0x1FFFFF  Calibration section 5 (256KB) ← ERCOSEK params
  0x404000 - 0x47FFFF  EXTERNAL flash via EBI (496KB):
    Section 1 — additional application CODE (not calibration)
    Contains PowerPC machine code; do NOT scan for cal values here.
"""
from dataclasses import dataclass, field
from enum import Enum


class Processor(Enum):
    MPC5534 = "MPC5534"   # 768KB flash
    MPC5554 = "MPC5554"   # 2MB flash, 80/112/132 MHz, 416-pin PBGA
    MPC5566 = "MPC5566"   # 3MB flash
    MPC5567 = "MPC5567"   # 4MB flash
    UNKNOWN = "UNKNOWN"


@dataclass
class ECUVariant:
    """MED9 ECU variant definition."""
    name: str
    processor: Processor
    flash_kb_internal: int = 2048   # internal H7Fa flash size
    flash_kb_external: int = 0      # EBI-mapped external flash (code only)
    cal_section_base: int = 0x1C0000  # ERCOSEK section 5 start
    cal_section_size: int = 0x40000   # 256KB typical
    applications: list[str] = field(default_factory=list)
    vag_pn_prefixes: list[str] = field(default_factory=list)
    notes: str = ""


VARIANTS: dict[str, ECUVariant] = {
    "MED9.1": ECUVariant(
        name="MED9.1",
        processor=Processor.MPC5554,
        flash_kb_internal=2048,
        flash_kb_external=496,   # section 1 at 0x404000 — application code
        cal_section_base=0x1C0000,
        cal_section_size=0x40000,
        applications=[
            "Porsche Cayenne 3.6 FSI V6 (M55.01) 2008-2010  [03H906032xx]",
            "VW Touareg 3.6 FSI V6 2008-2010",
            "Audi Q7 3.6 FSI 2007-2010",
            "VW Golf R32 MK5 (BUB)  [03H906026xx]",
            "Audi TT 3.2 VR6 (BUB)",
            "VW Passat 3.6 VR6 (BLV)",
            "VW CC 3.6 VR6",
            "VW Golf V 2.0 TFSI early (BWA)  [1K0907115]",
        ],
        vag_pn_prefixes=["03H906032", "03H906026", "03H997033", "03H997034", "1K0907115"],
        notes=(
            "MPC5554 (Power Architecture, 2MB H7Fa flash, 64KB SRAM, 132 MHz max). "
            "Additional 496KB code-only flash at EBI 0x404000 (do not scan for cal). "
            "ERCOSEK V4.x RTOS. Cal section at 0x1C0000, active cal from 0x1C2000. "
            "03H906032 SGOs: key=CodeRobert, section 5 = VMAXNB per-gear KL (9 entries). "
            "03H906032BG/CA/DA/EK/L: VMAXNB=260 km/h; 03H906032BE: VMAXNB in VMAXTM table. "
            "NMAXOGGA ≈ 8473–8481 RPM, consistent across all variants. "
        ),
    ),
    "MED9.5": ECUVariant(
        name="MED9.5",
        processor=Processor.MPC5566,
        flash_kb_internal=3072,
        applications=[
            "VW Golf GTI MK5 (BWA/BPY)",
            "Audi A4 2.0 TFSI (BWE/BWT)",
            "Audi A3 2.0 TFSI (AXX/BPY)",
            "SEAT Leon FR 2.0 TFSI",
        ],
        vag_pn_prefixes=["1K0907115", "06F906056"],
        notes=(
            "MPC5566 (3MB flash). Transitional variant between MED9.1 and MED17.5. "
            "Same ERCOSEK RTOS, same cal area location. "
            "Speed encoding identical to MED9.1 (be_u16_x100)."
        ),
    ),
    "MED9.5.10": ECUVariant(
        name="MED9.5.10",
        processor=Processor.MPC5566,
        flash_kb_internal=3072,
        applications=[
            "VW Golf GTI MK5 (CCTA early)",
            "Audi A3 2.0 TFSI (CCTA early)",
            "Audi TT 2.0 TFSI (CCTA early)",
        ],
        notes="MED9.5 sub-variant for CCTA engine family.",
    ),
}


def detect_variant(data: bytes) -> ECUVariant | None:
    """Detect MED9 variant from binary content."""
    text = data.decode("latin-1", errors="replace")

    # MED9.1 identifiers (Bosch internal SW version strings)
    if any(m in text for m in ("MED91", "MED9/1", "MED9.1", "MED91/")):
        return VARIANTS["MED9.1"]

    # MED9.5 sub-variants
    if "MED9.5.10" in text or "MED9/5/10" in text:
        return VARIANTS["MED9.5.10"]
    if any(m in text for m in ("MED95", "MED9/5", "MED9.5")):
        return VARIANTS["MED9.5"]

    return None
