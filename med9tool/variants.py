"""
ECU variant database for MPC5xx-based Bosch MED9 ECUs.

MED9 = Motronic Electronic Direct Injection, generation 9.
Gasoline direct injection ECUs using Freescale MPC5xx PowerPC.
Predecessor to MED17 (TriCore). Successor to ME7 (port injection).

Hardware architecture (MPC5554 data sheet, Rev. 4, Freescale 2008/2012):
  CPU core:    Power Architecture embedded (100% PowerPC ISA compatible)
               + DSP/SPE extensions, BIG ENDIAN (all multi-byte values MSB first)
               Runs up to 132 MHz (product variants: 80/112/132 MHz)
  Flash:       H7Fa internal flash, 2MB on MPC5554 (MPC5566=3MB, MPC5567=4MB)
               Block sizes: 16KB, 48KB, 64KB, 128KB
               Program/erase endurance: 100k cycles (16/48/64KB), 1k (128KB)
               Data retention: 20y (0-1k P/E), 5y (1k-100k P/E)
               Min flash op frequency: 25 MHz
               BIU settings for 132 MHz: APC=0b010, RWSC=0b011, WWSC=0b01
  SRAM:        64KB on-chip (+ 32KB unified cache)
               Standby supply VSTBY=0.8-1.2V; IDD_STBY 20-2000 µA (25-150°C)
  Timers:      2× eTPU (32 ch each = 64 total) — handles crank/cam capture
               → rev limit comparison lives in eTPU microcode, NOT cal flash
               eMIOS 24 ch (PWM/single/double action)
  ADC:         eQADC dual 40-channel, 12-bit, max 12 MHz ADCLK (800 KS/s)
               Resolution 1.25 mV/count at 5.12V reference
  Serial:      FlexCAN × 3, DSPI × 5, eSCI × 2
  Debug:       JTAG (IEEE 1149.1) + Nexus debug port (MDO0-11, MCKO, MSEO0-1)
               → Nexus is the bench-read path used by commercial tools
  EBI:         External Bus Interface — Bosch maps additional code flash here
               Max EBI clock = ½ internal clock (66 MHz at 132 MHz core)

Memory map in MED9.1 (03H906032 Cayenne, confirmed from SGO section table):
  0x000000 - 0x1FFFFF  Internal H7Fa flash (2MB on MPC5554):
    0x000000 - 0x01FFFF  Boot + low address blocks (128KB, not in SGO)
    0x020000 - 0x07FFFF  Code section 2 (384KB)
    0x080000 - 0x09FFFF  Code section 4 (128KB, 1 × 128KB block)
    0x0A0000 - 0x1BFFFF  Main application section 3 (1152KB)
    0x1C0000 - 0x1FFFFF  Calibration section 5 (256KB) ← ERCOSEK params
      0x1C2000: ERCOSEK header (5A5A5A5A CCCCCCCC)
      0x1C2080: AFFE0815 sub-section sentinel
      0x1C2100: Cal data start (VMAXNB KL, NMAXGA KL, etc.)
  0x404000 - 0x471FFF  External flash via EBI (496KB, section 1):
    Additional application CODE only — do NOT scan for calibration here.
    PowerPC big-endian machine code; speed/rev patterns here are coincidental.
  [gap 0x200000-0x403FFF: unmapped / 0xFF in image]
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
            "MPC5554 (Power Architecture, 2MB H7Fa internal flash + 496KB EBI code flash). "
            "64KB SRAM, 32KB cache, 132 MHz max. ERCOSEK V4.x RTOS. "
            "Cal section at 0x1C0000 (ERCOSEK header), active cal from 0x1C2100. "
            "EBI section at 0x404000 = application code only — do NOT scan for cal values. "
            "IMPORTANT: eTPU engines handle crank/cam capture — rev limit comparison "
            "lives in eTPU microcode params (SRAM), NOT in the H7Fa cal flash. "
            "Direct RPM values found in cal flash (0x1C2000+) are NMAXGA/NMAXOGGA tables. "
            "Speed: VMAXNB stored as per-gear KL, 9 entries × uint16 BE × km/h×100. "
            "03H906032BG/CA/DA/EK/L: VMAXNB=260 km/h (26000). "
            "03H906032BE: top scan hit is VMAXTM[0]=262.14 km/h (ascending curve, not VMAXNB). "
            "Rev: NMAXOGGA=8473–8481 RPM (direct BE uint16), consistent across all 9 variants. "
            "Bench read: Nexus debug port (MDO0-11, MCKO pins) per MPC5554 datasheet §3.13.3. "
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
