"""
Immobilizer bypass and DTC disable patches for MED9.x ECUs.

Brute-force immo-off strategy (MPC5554 PowerPC):
  Finds and NOPs two categories of conditional branches in the code section:
  1. Flag-gate branches: lbz rX, N(r13); cmpwi rX, 0/1; bc fwd≥100B
     These guard large blocks by checking a byte flag from the global data area (r13=SDA).
     The immo "cleared" flag is stored this way. NOPing the bc removes the gate.
  2. Polling loops: tight backward branches with a compare in the loop body.
     These spin-wait on CAN data or EEPROM reads. NOPing escapes the loop.

DTC disable strategy:
  CD* (Code-Direct) parameters are single-byte FW values in the calibration section.
  CD=0x00 → diagnosis disabled. CD=0x01 → enabled.
  Addresses are confirmed from community XDF (1K090711S_Definition__1_.xdf).

Checksum note:
  These patches modify the code section (immo) and cal section (DTCs).
  Bosch MED9 ECUs validate a checksum on first startup. The patched binary
  requires checksum correction before flashing. Use WinOLS (Checksum module)
  or ODIS-E to correct before programming the ECU.

NOP value for PowerPC e200z core: 0x60000000 (ori r0, r0, 0)
"""

import struct
from dataclasses import dataclass
from typing import Iterator

NOP_PPC = 0x60000000  # PowerPC NOP: ori r0, r0, 0

# === DTC / CD parameter addresses ===
# Confirmed from 1K090711S_Definition__1_.xdf for 1K0907115S (Golf V 2.0 TFSI)
# These addresses apply to MED9.1 binaries sharing this cal layout.
# Test: verify stock values match STOCK_VAL before patching.

@dataclass
class CDParam:
    name: str
    addr: int
    stock_val: int
    patch_val: int      # 0x00 = disable
    description: str

CD_PARAMS_1K0907115 = [
    # Downstream / rear O2 sensor diagnostics
    # Disable these when running without rear O2 sensors (cat delete, swap)
    CDParam("CDHSH",    0x1DD649, 0x01, 0x00, "Downstream O2 heater diagnostic"),
    CDParam("CDHSHE",   0x1DD64A, 0x00, 0x00, "Downstream O2 heater end diagnostic"),
    CDParam("CDHSV",    0x1DD64B, 0x01, 0x00, "Downstream O2 sensor voltage diagnostic"),
    CDParam("CDHSVSA",  0x1DD64C, 0x00, 0x00, "Downstream O2 SA diagnostic"),
    CDParam("CDKAT",    0x1DD64D, 0x00, 0x00, "Catalyst monitor diagnostic"),
    CDParam("CDKATSP",  0x1DD64E, 0x07, 0x00, "Catalyst monitor specific (multi-bit)"),
    CDParam("CDLASH",   0x1DD652, 0x01, 0x00, "Downstream O2 adaptation diagnostic"),
    CDParam("CDLATP",   0x1DD653, 0x00, 0x00, "Lambda adaptation plausibility"),
    CDParam("CDLSH",    0x1DD659, 0x01, 0x00, "O2 heater circuit diagnostic"),
    CDParam("CDLSV",    0x1DD65A, 0x01, 0x00, "O2 sensor voltage diagnostic"),
    # Secondary air injection (not present in TFSI, already 0)
    CDParam("CDSLS",    0x1DD665, 0x00, 0x00, "Secondary air injection diagnostic"),
    # Exhaust temperature sensor
    CDParam("CDTES",    0x1DD669, 0x01, 0x00, "Exhaust temperature sensor diagnostic"),
    # Codewords
    CDParam("CWKONABG", 0x1DD678, 0x01, 0x00, "EGR system configuration CW"),
    CDParam("CWKONLS",  0x1DD67A, 0x07, 0x00, "Lambda sensor configuration CW"),
]


def _find_flag_gates(data: bytes, code_start: int, code_end: int) -> Iterator[tuple[int, int]]:
    """
    Yield (offset, original_word) for lbz→cmpwi→bc_fwd triplets.
    These are flag-gate branches: check a byte from SDA, skip forward if 0 or 1.
    """
    for i in range(code_start, code_end - 12, 4):
        w0, w1, w2 = struct.unpack_from(">III", data, i)
        # lbz rX, N(r13): opcode=34, rA=13
        if (w0 >> 26) != 34 or ((w0 >> 16) & 0x1F) != 13:
            continue
        # cmpwi rX, 0 or 1: opcode=11
        if (w1 >> 26) != 11 or (w1 & 0xFFFF) not in (0, 1):
            continue
        # bc forward ≥ 100 bytes
        if (w2 >> 26) != 16:
            continue
        bd = (w2 >> 2) & 0x3FFF
        if bd & 0x2000:
            bd -= 0x4000
        if 25 <= bd <= 2000:
            yield (i + 8, w2)


def _find_poll_loops(data: bytes, code_start: int, code_end: int) -> Iterator[tuple[int, int]]:
    """
    Yield (offset, original_word) for tight backward-branch polling loops.
    These spin-wait on CAN data or EEPROM reads.
    """
    for i in range(code_start, code_end - 4, 4):
        w = struct.unpack_from(">I", data, i)[0]
        if (w >> 26) != 16:
            continue
        bd = (w >> 2) & 0x3FFF
        if bd & 0x2000:
            bd -= 0x4000
        if not (-16 <= bd <= -1):
            continue
        # Verify loop body contains a compare
        loop_start = i + bd * 4 + 4
        has_cmp = any(
            (struct.unpack_from(">I", data, j)[0] >> 26) in (10, 11)
            for j in range(max(code_start, loop_start), i, 4)
        )
        if has_cmp:
            yield (i, w)


def apply_immo_brute(data: bytes, code_start: int = 0x020000,
                     code_end: int = 0x0C0000) -> bytes:
    """
    Brute-force immo-off: NOP all flag-gate branches and poll loops in code section.

    Returns patched binary (same length). Does not modify cal section.
    Checksum correction required before flashing.

    Args:
        data:        Raw binary bytes.
        code_start:  First code section address (default: 0x020000 for MED9.1).
        code_end:    End of code section to scan (default: 0x0C0000).
    """
    patched = bytearray(data)
    count = 0
    for off, orig in _find_flag_gates(data, code_start, code_end):
        if struct.unpack_from(">I", patched, off)[0] == orig:
            struct.pack_into(">I", patched, off, NOP_PPC)
            count += 1
    for off, orig in _find_poll_loops(data, code_start, code_end):
        if struct.unpack_from(">I", patched, off)[0] == orig:
            struct.pack_into(">I", patched, off, NOP_PPC)
            count += 1
    return bytes(patched)


def apply_dtc_disable(data: bytes,
                      params: list[CDParam] | None = None) -> bytes:
    """
    Disable DTCs by zeroing CD parameter bytes in calibration section.

    Args:
        data:   Raw binary bytes.
        params: List of CDParam; defaults to CD_PARAMS_1K0907115.
    """
    if params is None:
        params = CD_PARAMS_1K0907115
    patched = bytearray(data)
    for p in params:
        patched[p.addr] = p.patch_val
    return bytes(patched)


def count_immo_patches(data: bytes, code_start: int = 0x020000,
                       code_end: int = 0x0C0000) -> dict[str, int]:
    """Return count of each patch type without modifying the binary."""
    flag_gates = sum(1 for _ in _find_flag_gates(data, code_start, code_end))
    poll_loops = sum(1 for _ in _find_poll_loops(data, code_start, code_end))
    return {"flag_gates": flag_gates, "poll_loops": poll_loops,
            "total": flag_gates + poll_loops}
