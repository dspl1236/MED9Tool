"""
MED9.1 EEPROM parser and immo-off patcher.

The MED9.1 stores immobilizer state in the external EEPROM chip (typically
24C04/24C08 on the ECU board), NOT in the main flash binary. This module
parses EEPROM dumps and can clear the immo lock byte.

Block layout confirmed from EliasTuning/MED9-EEPROM-Tool.
EEPROM is 512 bytes total, divided into named blocks at fixed offsets.

IMMO NOTE:
  The Bosch Immo4 clearance state lives in block_reserved1 at EEPROM
  offset 0x59 (immo_byte). Setting this to the correct value bypasses
  the CAN immo handshake check. This is more surgical than the brute-force
  flash NOP approach and survives reflashing the main ECU binary.

  However: the EEPROM requires physical access (I2C read/write on the board)
  or live KWP2000 writeMemoryByAddress. The live KWP2000 path requires
  SA2 write access (see security.py) plus knowledge of the EEPROM RAM mirror
  address (varies by variant, typically in the 0x40xxxxxx SRAM range).

EEPROM blocks:
  0x000  PRGID   (32B)  Flash programming ID, FPC code, state/attempts
  0x040  RESV1   (32B)  Reserved - contains immo_byte at +0x19
  0x080  RESV2   (62B)  Encrypted reserved data
  0x100  RESV3   (32B)  Encrypted reserved data
  0x140  SGID    (32B)  SG hardware ID
  0x180  TESTER  (32B)  Workshop code (WSC), variant coding
  0x1C0  CALIB   (32B)  Adaptation values (lambda, idle, etc.)
  0x200  DFPMEEP (96B)  Fault path manager storage (DTCs)
  0x2E0  BLOCK13 (32B)  Empty/reserved
  ...
"""

import struct
from dataclasses import dataclass

# EEPROM total size
EEPROM_SIZE = 512

# Block offsets
BLOCK_PRGID   = 0x000
BLOCK_RESV1   = 0x040   # contains immo_byte
BLOCK_RESV2   = 0x080
BLOCK_RESV3   = 0x100
BLOCK_SGID    = 0x140
BLOCK_TESTER  = 0x180
BLOCK_CALIB   = 0x1C0
BLOCK_DFPMEEP = 0x200
BLOCK_13      = 0x2E0

# immo_byte offset within RESV1 block:
# eepVersion(2) + data[9](9) + sec_code(2) + sec_bytes[7](7) + data2[5](5) = 25 bytes
IMMO_BYTE_OFFSET_IN_RESV1 = 25           # relative to BLOCK_RESV1 start
IMMO_BYTE_ABS = BLOCK_RESV1 + IMMO_BYTE_OFFSET_IN_RESV1  # = 0x59


@dataclass
class EEPROMInfo:
    """Parsed EEPROM metadata."""
    raw: bytes
    prgid_version: int
    fpc: str              # Flash programming code (6 chars)
    prog_state: int       # Programming state byte
    prog_attempts: int    # Number of flash sessions
    prog_success: int     # Successful sessions
    immo_byte: int        # Immobilizer lock byte (at 0x59)
    wsc: str              # Workshop code (6 chars)
    variant_coding: int   # pmc_w variant codeword


def parse_eeprom(data: bytes) -> EEPROMInfo:
    """Parse an EEPROM dump into structured fields."""
    if len(data) < EEPROM_SIZE:
        raise ValueError(f"EEPROM too short: {len(data)} < {EEPROM_SIZE}")

    # PRGID block at 0x000 - FPC starts at BLOCK_PRGID (separate from PRGID struct)
    # From block_prgid.py: eepVersion(2) fpc(6) state(1) attempt(1) success(1) flash_info(1)
    prgid_b = data[BLOCK_PRGID:]
    prgid_ver2 = struct.unpack_from(">H", prgid_b)[0]
    fpc = prgid_b[2:8].decode("latin-1", errors="replace").rstrip("\x00")
    state = prgid_b[8]
    attempts = prgid_b[9]
    success = prgid_b[10]

    # RESV1 at 0x040 - immo_byte at +25
    immo_byte = data[IMMO_BYTE_ABS]

    # TESTER at 0x180: eepVersion(2) WSC[6] coding2[4] pmc_w(2)
    tester = data[BLOCK_TESTER:]
    wsc = tester[2:8].decode("latin-1", errors="replace").rstrip("\x00")
    pmc_w = struct.unpack_from(">H", tester, 12)[0]

    return EEPROMInfo(
        raw=data,
        prgid_version=prgid_ver2,
        fpc=fpc,
        prog_state=state,
        prog_attempts=attempts,
        prog_success=success,
        immo_byte=immo_byte,
        wsc=wsc,
        variant_coding=pmc_w,
    )


def apply_immo_eeprom(data: bytes, target_value: int = 0x00) -> bytes:
    """
    Clear the EEPROM immo_byte (surgical immo-off).

    This is more reliable than brute-force flash NOPs: it clears the
    hardware immo state in the EEPROM directly.

    After modifying, the EEPROM checksum for RESV1 block must be updated.
    The checksum is a simple 16-bit sum of the block bytes (excluding the
    last 2 checksum bytes).

    Args:
        data:         Raw EEPROM dump bytes (512 bytes).
        target_value: Byte value to write to immo_byte (default 0x00 = clear).

    Returns:
        Modified EEPROM bytes with updated block checksum.
    """
    if len(data) < EEPROM_SIZE:
        raise ValueError(f"EEPROM too short: {len(data)} < {EEPROM_SIZE}")

    result = bytearray(data)
    result[IMMO_BYTE_ABS] = target_value

    # Update RESV1 block checksum (last 2 bytes of the 32-byte block)
    # Block is 32 bytes: checksum covers bytes 0-29, stored in bytes 30-31
    block_data = result[BLOCK_RESV1:BLOCK_RESV1 + 30]
    checksum = sum(block_data) & 0xFFFF
    struct.pack_into(">H", result, BLOCK_RESV1 + 30, checksum)

    return bytes(result)


def describe_eeprom(info: EEPROMInfo) -> str:
    """Return a human-readable EEPROM summary."""
    lines = [
        f"FPC:            {info.fpc!r}",
        f"Prog state:     0x{info.prog_state:02X}",
        f"Prog attempts:  {info.prog_attempts}",
        f"Prog successes: {info.prog_success}",
        f"Immo byte:      0x{info.immo_byte:02X} @ EEPROM 0x{IMMO_BYTE_ABS:02X}"
        + (" (CLEARED)" if info.immo_byte == 0x00 else " (SET — immo active)"),
        f"WSC:            {info.wsc!r}",
        f"Variant coding: 0x{info.variant_coding:04X}",
    ]
    return "\n".join(lines)
