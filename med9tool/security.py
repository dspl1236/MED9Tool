"""
Security access algorithms for MED9.x ECUs (KWP2000 seed/key).

Confirmed from EliasTuning/MED9RamReader (src/crypto/secaccess.py).

Two access levels:
  Level 1 (READ / Normal session):
    Simple: key = (seed + 0x00011170) & 0xFFFFFFFF
    Used for: readMemoryByAddress, measuring blocks, live data

  Level 1 (WRITE / Programming session) — "SA2":
    5-round conditional rotate-left with XOR against 0x5FBD5DBD
    Used for: flash programming, writeMemoryByAddress, EEPROM writes

KWP2000 transport: TP2.0 over CAN, ECU physical address 0x01.
"""

# Known SGO/flash XOR key variants (same cipher, different byte order)
SGO_XOR_KEY  = "CodeRobert"   # rolling-XOR for SGO container decryption
FLASH_XOR_KEY = "RobertCode"  # block-XOR for flash programming payload (LZSS → XOR)


def sa_read_key(seed: int) -> int:
    """
    MED9.1 Level-1 read access key.
    key = (seed + 0x00011170) & 0xFFFFFFFF
    """
    return (seed + 0x00011170) & 0xFFFFFFFF


def sa_write_key(seed: int) -> int:
    """
    MED9.1 Level-1 programming (SA2) key.
    5 rounds of conditional rotate-left-1 XOR with 0x5FBD5DBD.
    Python note: no visible sign bit, u32 clamp applied after each op.
    """
    SEED_DATA = 0x5FBD5DBD
    for _ in range(5):
        if seed & 0x80000000:
            seed = (SEED_DATA ^ ((seed << 1) | (seed >> 31))) & 0xFFFFFFFF
        else:
            seed = ((seed << 1) | (seed >> 31)) & 0xFFFFFFFF
    return seed


def validate_sa_pair(seed: int, key: int, mode: str = "read") -> bool:
    """Return True if key is the correct response for the given seed."""
    fn = sa_read_key if mode == "read" else sa_write_key
    return fn(seed) == key
