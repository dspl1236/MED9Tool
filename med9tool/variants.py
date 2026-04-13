"""
ECU variant database for MPC5xx-based Bosch MED9 ECUs.

MED9 = Motronic Electronic Direct injection, generation 9.
Gasoline direct injection ECUs using Freescale MPC5xx PowerPC.
Predecessor to MED17 (TriCore). Successor to ME7 (port injection).
"""

from dataclasses import dataclass, field
from enum import Enum


class Processor(Enum):
    MPC5534 = "MPC5534"
    MPC5554 = "MPC5554"
    MPC5566 = "MPC5566"
    MPC5567 = "MPC5567"
    UNKNOWN = "UNKNOWN"


@dataclass
class ECUVariant:
    """MED9 ECU variant definition."""
    name: str
    processor: Processor
    flash_size_kb: int = 2048
    applications: list[str] = field(default_factory=list)
    vag_pn_prefixes: list[str] = field(default_factory=list)
    notes: str = ""


VARIANTS: dict[str, ECUVariant] = {
    "MED9.1": ECUVariant(
        name="MED9.1",
        processor=Processor.MPC5567,
        flash_size_kb=2048,
        applications=[
            "Porsche Cayenne 3.6 FSI V6 (M55.01) 2008-2010",
            "VW Touareg 3.6 FSI V6 2008-2010",
            "Audi Q7 3.6 FSI 2007-2010",
            "VW Golf R32 MK5 (BUB)",
            "Audi TT 3.2 VR6 (BUB)",
            "VW Passat 3.6 VR6 (BLV)",
            "VW CC 3.6 VR6",
            "Audi A3 2.0 TFSI early (BWA)",
            "VW Golf GTI MK5 late (CCTA early HW)",
        ],
        vag_pn_prefixes=[
            "03H906032",
            "03H906026",
            "03H997033",
            "03H997034",
            "1K0907115",
        ],
        notes=(
            "Most common MED9 variant. MPC5567 PowerPC, 2MB flash. "
            "Replaced by MED17.1 (TC1797) in 2011+ models. "
            "03H906032 SGOs unpack cleanly. "
            "03H906026 FRFs use AES encryption (key unknown)."
        ),
    ),
    "MED9.5": ECUVariant(
        name="MED9.5",
        processor=Processor.MPC5566,
        flash_size_kb=2048,
        applications=[
            "VW Golf GTI MK5 early (BWA/BPY)",
            "Audi A4 2.0 TFSI early (BWE)",
            "Audi A3 2.0 TFSI early (AXX)",
        ],
        notes="Transitional variant. Less common than MED9.1.",
    ),
    "MED9.5.10": ECUVariant(
        name="MED9.5.10",
        processor=Processor.MPC5566,
        flash_size_kb=2048,
        applications=[
            "VW Golf GTI MK5 (BWA/BPY/CCTA)",
            "Audi A3 2.0 TFSI (BWA/CCTA)",
        ],
        notes="Updated MED9.5 sub-variant.",
    ),
}


def detect_variant(data: bytes) -> ECUVariant | None:
    """Detect MED9 variant from binary content."""
    text = data.decode("latin-1", errors="replace")

    if "MED91" in text or "MED9/1" in text or "MED9.1" in text:
        return VARIANTS["MED9.1"]
    if "MED95" in text or "MED9/5" in text or "MED9.5" in text:
        if "MED9.5.10" in text or "MED9/5/10" in text:
            return VARIANTS.get("MED9.5.10", VARIANTS["MED9.5"])
        return VARIANTS["MED9.5"]

    return None
