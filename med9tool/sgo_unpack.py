"""
SGO file unpacker for MED9 ECU firmware.

Supports two formats:

1. Rolling-XOR SGO (legacy, pre-2018 flashdaten):
   VAG SGO files use a rolling-XOR cipher followed by a section-based layout.
   The cipher key is brute-forced from the known structure of the section table.

2. SGML Object File v2 (modern flashdaten, 2018+):
   Container format used by ODIS/VAS-PC. 16-byte magic "SGML Object File",
   binary header with section offsets, blocks XOR'd with 0xFF. Each compressed
   block (fmt=0x11) contains a plaintext FRF-style header followed by
   BCB Type1 compressed binary data.

   BCB Type1 algorithm (Bosch Compact Binary, d3irb / nefariousmotorsports #6583):
   - Flag-byte approach: 1 flag byte controls 8 tokens (MSB first)
   - Flag=0 → literal byte; Flag=1 → back-reference (2 bytes, BE: count[6]|disp[10])
   - disp=0 or count=0 → no-op token (not end-of-stream)
   - No ring-buffer pre-fill; back-reference indexes directly into decoded output

   Source addresses in SGML are physical flash addresses (no virtual offset needed).
"""
from __future__ import annotations
import re
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


_SGML_MAGIC = b"SGML Object File\x00"


def is_sgml_file(data: bytes) -> bool:
    """Detect SGML Object File v2 format (modern flashdaten)."""
    return len(data) >= 21 and data[:17] == _SGML_MAGIC


def is_sgo_file(data: bytes) -> bool:
    """Detect either legacy rolling-XOR SGO or modern SGML Object File."""
    if len(data) < 16:
        return False
    if is_sgml_file(data):
        return True
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


def _unpack_rolling_xor(data: bytes, verbose: bool = False) -> SGOResult:
    """Unpack legacy rolling-XOR SGO into a flat binary (0xFF-padded)."""
    key = _crack_key(data)
    if key is None:
        return SGOResult(success=False, error="Could not crack SGO key")

    dec = _xor_decrypt(data, key)
    table = _parse_table(dec)
    if not table:
        return SGOResult(success=False, error="Empty section table")

    img_size = max(off + ln for off, _, ln in table)
    img_size = (img_size + 0xFFFF) & ~0xFFFF
    image = bytearray(b"\xFF" * img_size)

    secs_out = []
    for flash_off, data_off, length in table:
        sec_data = dec[data_off : min(data_off + length, len(dec))]
        copy_len = min(length, img_size - flash_off)
        if copy_len > 0:
            image[flash_off : flash_off + copy_len] = sec_data[:copy_len]
        secs_out.append(SGOSection(offset=flash_off, length=length, data=sec_data))
        if verbose:
            print(f"  Section @ 0x{flash_off:06X}: {length:,} bytes")

    if verbose:
        print(f"  Output: {img_size:,} bytes  key={key}")

    return SGOResult(
        success=True, binary=bytes(image), sections=secs_out, key=key,
        compressed_size=len(data), uncompressed_size=img_size,
    )


# ── SGML Object File v2 decoder ───────────────────────────────────────────────

def _bcb_decompress(compressed: bytes, expected_size: int) -> bytes:
    """
    BCB Type1 decompressor (Bosch Compact Binary).

    Flag-byte approach: one byte controls 8 tokens (MSB first).
      flag=0 → literal (1 byte)
      flag=1 → back-reference (2 bytes BE: upper 6 bits = count, lower 10 = disp)
    disp=0 or count=0 are no-ops (not end-of-stream).

    Confirmed by d3irb (nefariousmotorsports.com topic 6583) and validated
    against TriCoreTool FRF block decompression.
    """
    out = bytearray()
    pos = 0
    while pos < len(compressed) and len(out) < expected_size:
        flag_byte = compressed[pos]; pos += 1
        for bit in range(7, -1, -1):
            if len(out) >= expected_size or pos >= len(compressed):
                break
            if not (flag_byte >> bit) & 1:
                # Literal
                out.append(compressed[pos]); pos += 1
            else:
                # Back-reference
                if pos + 1 >= len(compressed):
                    break
                sh = (compressed[pos] << 8) | compressed[pos + 1]; pos += 2
                count = sh >> 10
                disp  = sh & 0x3FF
                if count == 0 or disp == 0:
                    continue  # no-op, not EOF
                for _ in range(count):
                    if len(out) >= expected_size:
                        break
                    out.append(out[-disp] if len(out) >= disp else 0)
    return bytes(out[:expected_size])


def _parse_sgml_block(blk_raw: bytes) -> tuple[int, int, bytes] | None:
    """
    Parse one SGML data block (fmt=0x11, already XOR'd with 0xFF).

    Returns (start_addr, end_addr, decompressed_bytes) or None on failure.

    Each block contains a plaintext FRF-style header:
        [SOURCE]\\n<name>\\n[CHECKSUM]\\n<hex>\\n[FORMAT]\\nBCB Type1...\\n
        [START_ADDRESS]\\n<hex>\\n[END_ADDRESS]\\n<hex>\\n
    Followed immediately by BCB-compressed binary data.
    """
    text = blk_raw.decode("latin-1", errors="replace")

    m_end = re.search(r'\[END_ADDRESS\]\n([0-9A-Fa-f]+)\n', text)
    m_sta = re.search(r'\[START_ADDRESS\]\n([0-9A-Fa-f]+)\n', text)
    if not (m_end and m_sta):
        return None

    start_addr = int(m_sta.group(1), 16)
    end_addr   = int(m_end.group(1), 16)
    expected   = end_addr - start_addr + 1
    if expected <= 0 or expected > 0x400000:
        return None

    bcb_data = blk_raw[m_end.end():]
    dec = _bcb_decompress(bcb_data, expected)
    return start_addr, end_addr, dec


def _read_3byte_be(data: bytes, off: int) -> int:
    b = data[off:off + 3]
    return (b[0] << 16) | (b[1] << 8) | b[2]


def _xorstr_sgml(data: bytes) -> str:
    """Decode a null-terminated, 0xFF-XOR'd string from SGML IDENT section."""
    result = []
    for b in data:
        if b == 0:
            break
        result.append(b ^ 0xFF)
    return bytes(result).decode("ascii", errors="replace")


def unpack_sgml(data: bytes, verbose: bool = False) -> SGOResult:
    """
    Unpack an SGML Object File v2 into a flat binary image.

    Header layout (offsets from file start):
        0x00-0x10: "SGML Object File" (16 bytes ASCII)
        0x10:      null terminator
        0x11-0x14: SGO_COMPATIBILITY (LE uint32, always 2)
        0x15-0x18: checksum (LE uint32, varies per SW version)
        0x19-0x1C: indexIDENT (LE uint32, file offset to IDENT section)
        0x1D-0x20: indexbaudrate (LE uint32)
        0x21-0x24: indexkwp_2000_rei
        0x25-0x28: indexkwp_2000_acp
        0x29-0x2C: indexkwp_2000_sa2 (LE uint32, file offset to SA2 bytecode)
        0x2D-0x30: index_DATA_BLOCKS (LE uint32, file offset to block index)

    IDENT section:
        260 bytes: part-number filename (XOR'd with 0xFF, null-terminated)
          5 bytes: SW version string (XOR'd with 0xFF, null-terminated)
          4 bytes: SW version as LE uint32

    DATA_BLOCKS section:
        4B LE uint32: block count
        N × 4B LE uint32: file offsets to each block descriptor

    Block descriptor:
        3B BE: start virtual address (= physical address for MED9 flash)
        1B:    format (0x00=uncompressed, 0x11=BCB-compressed)
        3B BE: decompressed size
        3B BE: erase start
        3B BE: erase end
        3B BE: check start
        3B BE: check end
        2B BE: checksum
        4B LE uint32: compressed data size
        NB:    data (XOR'd with 0xFF; for fmt=0x11 contains FRF header + BCB stream)
    """
    if not is_sgml_file(data):
        return SGOResult(success=False, error="Not an SGML Object File")

    compat = struct.unpack_from("<I", data, 17)[0]
    if compat != 2:
        return SGOResult(success=False,
                         error=f"Unsupported SGML compatibility version {compat}")

    # Parse IDENT
    idx_ident = struct.unpack_from("<I", data, 25)[0]
    pn_raw  = data[idx_ident : idx_ident + 260]
    sw_raw  = data[idx_ident + 260 : idx_ident + 265]
    part_number = _xorstr_sgml(pn_raw).replace(".sgm", "").replace(".sgo", "")
    sw_version  = _xorstr_sgml(sw_raw)

    # Parse SA2
    idx_sa2   = struct.unpack_from("<I", data, 41)[0]
    sa2_count = struct.unpack_from("<I", data, idx_sa2)[0]
    sa2_data  = data[idx_sa2 + 4 : idx_sa2 + 4 + sa2_count]

    # Parse block index
    idx_blocks = struct.unpack_from("<I", data, 45)[0]
    nblocks    = struct.unpack_from("<I", data, idx_blocks)[0]
    if nblocks == 0 or nblocks > 32:
        return SGOResult(success=False, error=f"Implausible block count {nblocks}")
    block_offs = [struct.unpack_from("<I", data, idx_blocks + 4 + i * 4)[0]
                  for i in range(nblocks)]

    # Decode all blocks
    binary = bytearray(0x480000)  # covers all MED9 flash incl. shadow at 0x404000
    secs_out: list[SGOSection] = []
    total_comp = 0
    total_decomp = 0

    for bi, boff in enumerate(block_offs):
        off = boff
        start_virt = _read_3byte_be(data, off);  off += 3
        fmt        = data[off];                  off += 1
        size_dec   = _read_3byte_be(data, off);  off += 3
        off += 12   # skip erase_start, erase_end, check_start, check_end (3+3+3+3)
        off += 2    # skip checksum (2 bytes)
        data_sz    = struct.unpack_from("<I", data, off)[0]; off += 4
        raw_file   = data[off : off + data_sz]
        total_comp += data_sz

        if fmt == 0x00:
            # Uncompressed: raw data XOR'd with 0xFF
            blk_data = bytes(b ^ 0xFF for b in raw_file)
        elif fmt == 0x11:
            # BCB-compressed with embedded FRF header
            blk_xor = bytes(b ^ 0xFF for b in raw_file)
            parsed  = _parse_sgml_block(blk_xor)
            if parsed is None:
                if verbose:
                    print(f"  Block {bi}: no FRF header, fmt=0x11 — skipped")
                continue
            start_virt, end_virt, blk_data = parsed
        else:
            if verbose:
                print(f"  Block {bi}: unknown fmt=0x{fmt:02X} — skipped")
            continue

        total_decomp += len(blk_data)
        phys = start_virt  # SGML addresses are physical flash addresses
        end_phys = min(phys + len(blk_data), len(binary))
        if 0 <= phys < len(binary):
            binary[phys : end_phys] = blk_data[: end_phys - phys]
        secs_out.append(SGOSection(offset=phys, length=len(blk_data), data=blk_data))

        if verbose:
            print(f"  Block {bi}: 0x{phys:06X}  "
                  f"{data_sz//1024}KB→{len(blk_data)//1024}KB  fmt=0x{fmt:02X}")

    if not secs_out:
        return SGOResult(success=False, error="No decodable blocks found")

    if verbose:
        print(f"  PN={part_number}  SW={sw_version}  "
              f"SA2={sa2_data.hex()}  blocks={len(secs_out)}")

    # Trim to 2MB if upper shadow region (0x200000+) is empty
    upper = binary[0x200000:]
    if all(b == 0 for b in upper):
        binary = binary[:0x200000]

    return SGOResult(
        success=True,
        binary=bytes(binary),
        sections=secs_out,
        key=f"SGML:PN={part_number},SW={sw_version},SA2={sa2_data.hex()}",
        compressed_size=total_comp,
        uncompressed_size=total_decomp,
    )


def unpack_sgo(data: bytes, verbose: bool = False) -> SGOResult:
    """
    Unpack a VAG SGO file into a flat binary image.

    Dispatches to the appropriate decoder based on file format:
    - SGML Object File v2 (magic "SGML Object File") → unpack_sgml()
    - Legacy rolling-XOR SGO → _unpack_rolling_xor()
    """
    if verbose:
        print(f"  Loading: {len(data):,} bytes")
    if is_sgml_file(data):
        return unpack_sgml(data, verbose=verbose)
    return _unpack_rolling_xor(data, verbose=verbose)
