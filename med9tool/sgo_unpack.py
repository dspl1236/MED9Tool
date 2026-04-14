"""
SGO file unpacker for MED9 ECU firmware.

VAG SGO files use a rolling-XOR cipher followed by a section-based layout.
The cipher key is brute-forced from the known structure of the section table.
Identical format to TriCoreTool's SGO unpacker (MED17/EDC17).
"""
from __future__ import annotations
import struct
from dataclasses import dataclass, field


@dataclass
class SGOSection:
    offset: int   # flash offset where this section is placed
    length: int
    data: bytes = b""


@dataclass
class SGOResult:
    success: bool
    binary: bytes = b""
    error: str = ""
    sections: list[SGOSection] = field(default_factory=list)
    key: str = ""
    compressed_size: int = 0
    uncompressed_size: int = 0


def is_sgo_file(data: bytes) -> bool:
    """Heuristic: SGO starts with a big-endian flash offset in low range."""
    if len(data) < 16:
        return False
    if data[:4] in (b"MZ\x90\x00", b"\x7fELF", b"RIFF", b"PK\x03\x04"):
        return False
    first = struct.unpack_from(">I", data)[0]
    return first < 0x00600000


def _xor_decrypt(data: bytes, key: str) -> bytes:
    kb = key.encode("ascii")
    kl = len(kb)
    out = bytearray(len(data))
    acc = 0
    for i, b in enumerate(data):
        k = kb[i % kl]
        d = b ^ k ^ (acc & 0xFF)
        out[i] = d
        acc = (acc + k + b) & 0xFF
    return bytes(out)


# All known keys observed across VAG SGO files
_KNOWN_KEYS = [
    "CodeRobert", "BiWbBuD101", "Mst2Bosch", "VagSgo01",
    "BoschKey1",  "VW_ECU_01",  "Audi_ECU1", "FlashData",
    "EcuFlash1",  "CalibData",  "SGO_KEY_1",
]


def _crack_key(data: bytes) -> str | None:
    """Find the rolling-XOR key by checking if section table decodes cleanly."""
    candidates = list(_KNOWN_KEYS) + [chr(k) for k in range(0x20, 0x7F)]
    for key in candidates:
        dec = _xor_decrypt(data, key)
        try:
            off = struct.unpack_from(">I", dec, 0)[0]
            ln  = struct.unpack_from(">I", dec, 4)[0]
            if 0x0 <= off <= 0x00580000 and 0x1000 <= ln <= 0x400000:
                return key
        except Exception:
            pass
    return None


def _parse_table(dec: bytes) -> list[tuple[int, int, int]]:
    """
    Parse section table → list of (flash_offset, data_offset, length).

    Table format: repeated [u32BE flash_offset, u32BE length]
    until flash_offset == 0xFFFFFFFF or clearly invalid.
    """
    sections = []
    pos = 0
    while pos + 8 <= len(dec):
        flash_off = struct.unpack_from(">I", dec, pos)[0]
        length    = struct.unpack_from(">I", dec, pos + 4)[0]
        pos += 8
        if flash_off == 0xFFFFFFFF or length == 0xFFFFFFFF:
            break
        if flash_off > 0x00580000 or length > 0x800000 or length == 0:
            break
        sections.append((flash_off, length))
        if len(sections) > 20:
            break

    table_bytes = 8 * len(sections) + 8   # entries + terminator
    data_cur = table_bytes
    result = []
    for flash_off, length in sections:
        result.append((flash_off, data_cur, length))
        data_cur += length
    return result


def unpack_sgo(data: bytes, verbose: bool = False) -> SGOResult:
    """Unpack a VAG SGO file into a flat binary image (0xFF-padded)."""
    if verbose:
        print(f"  Loading: {len(data):,} bytes")

    key = _crack_key(data)
    if key is None:
        return SGOResult(success=False, error="Could not crack SGO key")

    dec = _xor_decrypt(data, key)
    table = _parse_table(dec)
    if not table:
        return SGOResult(success=False, error="Empty section table")

    img_size = max(off + ln for off, _, ln in table)
    img_size = (img_size + 0xFFFF) & ~0xFFFF  # round up to 64KB
    image = bytearray(b"\xFF" * img_size)

    secs_out = []
    for flash_off, data_off, length in table:
        end = data_off + length
        sec_data = dec[data_off : min(end, len(dec))]
        copy_len = min(length, img_size - flash_off)
        if copy_len > 0:
            image[flash_off : flash_off + copy_len] = sec_data[:copy_len]
        secs_out.append(SGOSection(offset=flash_off, length=length, data=sec_data))
        if verbose:
            print(f"  Section @ 0x{flash_off:06X}: {length:,} bytes")

    if verbose:
        print(f"  Output: {img_size:,} bytes  key={key}")

    return SGOResult(
        success=True,
        binary=bytes(image),
        sections=secs_out,
        key=key,
        compressed_size=len(data),
        uncompressed_size=img_size,
    )
