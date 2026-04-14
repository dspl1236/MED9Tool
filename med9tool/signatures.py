"""
Signature-based address finder for MED9.x binaries.

Adapted from EliasTuning/MED9Toolchain (analysis/src/AddressFinderRegExp.py
and analysis/addresses/). Uses byte-pattern matching with XX wildcards to
locate calibration tables, variables, and free memory across all MED9.1
variants regardless of SW version.

Virtual address space note:
  ECU runs with flash mapped at virtual base 0x400000.
  physical_offset = virtual_address - VIRT_BASE
  All patch addresses in EliasTuning repos use virtual addresses.

Usage:
    sig = Signatures(binary_data)
    addr = sig.find_free_flash()   # returns physical offset
    vmaxnb = sig.find_vmaxnb()
    bfgren = sig.find_bfgren_var()
"""

import re
import struct
from dataclasses import dataclass

VIRT_BASE = 0x400000   # Virtual address base (ECU runtime mapping)


@dataclass
class SigResult:
    """Result of a signature search."""
    physical: int      # physical offset in flat binary
    virtual: int       # virtual address at runtime (physical + VIRT_BASE)
    found: bool = True
    note: str = ""


def _to_virt(phys: int) -> int:
    return phys + VIRT_BASE


def _hex_to_regex(sig: str) -> re.Pattern:
    """Convert 'AA BB XX CC' pattern to regex, XX = wildcard byte."""
    s = sig.upper().replace(" ", "")
    s = re.sub(r"XX", "[0-9A-F]{2}", s)
    return re.compile(s)


class Signatures:
    """
    Byte-pattern searcher for a flat MED9 binary.
    All patterns use big-endian PowerPC encoding.
    """

    def __init__(self, data: bytes):
        self._data = data
        self._hex = data.hex().upper()

    def _find(self, pattern: str, region_start: int = 0x020000,
              region_end: int = 0x1C0000) -> int:
        """
        Find pattern in binary, return physical offset of match start.
        region_start/end are physical offsets.
        Raises ValueError if not found or ambiguous.
        """
        rx = _hex_to_regex(pattern)
        region_hex = self._hex[region_start * 2: region_end * 2]
        matches = list(rx.finditer(region_hex))
        if not matches:
            raise ValueError(f"Pattern not found: {pattern[:32]}...")
        if len(matches) > 1:
            raise ValueError(f"Pattern ambiguous ({len(matches)} matches): {pattern[:32]}...")
        return region_start + matches[0].start() // 2

    def _pick16(self, phys: int) -> int:
        return struct.unpack_from(">H", self._data, phys)[0]

    def _pick16s(self, phys: int) -> int:
        v = self._pick16(phys)
        return v - 0x10000 if v >= 0x8000 else v

    # ── Free flash (code cave) ────────────────────────────────────────────────

    def find_free_flash(self, min_ff_run: int = 0x800) -> SigResult:
        """
        Find a large block of 0xFF bytes suitable for code injection.
        Looks in the cal section tail (0x1E0000-0x1F0000) after the
        ERCOSEK end magic.

        The MED9Toolchain approach: search for ERCOSEK end (5A5A5A5A)
        followed by the large FF region.
        """
        # Search in cal tail
        search_start = 0x1C0000
        search_end   = min(len(self._data), 0x1F0000)

        for off in range(search_end - 1, search_start, -1):
            # Find large FF run ending at off
            if self._data[off] != 0xFF:
                continue
            start = off
            while start > search_start and self._data[start - 1] == 0xFF:
                start -= 1
            run = off - start + 1
            if run >= min_ff_run:
                # Align to 256-byte boundary
                aligned = (start + 0xFF) & ~0xFF
                return SigResult(physical=aligned, virtual=_to_virt(aligned),
                                 note=f"FF run {run//1024}KB from 0x{start:06X}")

        raise ValueError("No suitable free flash region found")

    # ── Calibration variable locators ────────────────────────────────────────

    def find_bfgren_var(self) -> SigResult:
        """
        BFGREN — Cruise control on/off flag (byte in SRAM via r13).
        Signature from MED9Toolchain/analysis/addresses/variables/BFGREN.py

        Pattern: entry before BFGREN variable reference
          3b f9 00 00   addi rX, r25, 0
          48 00 00 08   b +8
          57 7f 04 3e   rlwinm
          b3 ed XX XX   sth rX, N(r13)
          8b 6d XX XX   lbz rX, N(r13)   ← target: N = SDA offset to BFGREN
        """
        pattern = "3BF90000 48000008 577F043E B3EDXXXX 8B6DXXXX"
        sig_start = self._find(pattern)
        # lbz instruction is at sig_start + 18 (+18 bytes from pattern start)
        lbz_off = sig_start + 18
        sda_offset = self._pick16s(lbz_off + 2)
        # SDA base (r13) for MED9.1 = 0x7FFFF0 (varies; approx)
        sda_base = 0x7FFFF0
        ram_addr = (sda_base + sda_offset) & 0xFFFFFFFF
        return SigResult(physical=lbz_off, virtual=_to_virt(lbz_off),
                         note=f"SDA offset={sda_offset:+d}, RAM≈0x{ram_addr:08X}")

    def find_ldrxn(self) -> dict:
        """
        LDRXN — Load-request table (load vs RPM curve).

        The MED9.1 LDRXN is accessed via an INDIRECT pointer array:
          - A pointer array in cal section holds 6 pointers, one per entry
          - Each pointer points to: 16-entry RPM axis + 16-entry load values (33 uint16 total)
          - The lwzx instruction selects which pointer to load based on engine state
          - LDRXN1 = ptr_array[0] (normal map), LDRXN2 = ptr_array[1] (alternate map)
          - PATCH_LDRXN = address of the lwzx r3, r10, r9 instruction to redirect

        Confirmed structure on 1K0907115S:
          PATCHADDR_LDRXN: phys=0x11A61C  (lwzx r3, r10, r9)
          TABLE_LDRXN1:    phys=0x1CF308  (RPM axis; values at +32B = 0x1CF328)
          TABLE_LDRXN2:    phys=0x1CF34A  (RPM axis; values at +32B = 0x1CF36A)

        Signature v2 (confirmed for EA113 TFSI Golf V):
          3D40005D   lis  r10, 0x5D
          394AXXXX   addi r10, r10, N   ← encodes pointer array address
          552915BA   rlwinm r9, r9, 2, 22, 29
          7C6A482E   lwzx r3, r10, r9   ← PATCH POINT
          A08DXXXX   lhz  r4, N(r13)

        Note: VR6 Cayenne variants use a different pattern — Ghidra session needed.
        """
        # v2 pattern: lis r10, 0x5D + addi + rlwinm (fixed) + lwzx (fixed) + lhz r4,(r13)
        pattern = "3D40005D 394AXXXX 552915BA 7C6A482E A08DXXXX"
        sig_start = self._find(pattern)

        # lwzx is at +12 bytes from pattern start
        patch_addr = sig_start + 12

        # addi encodes pointer array address: lis r10, 0x5D + addi r10, r10, lo
        addi_off = sig_start + 4
        lo = self._pick16s(addi_off + 2)
        ptr_array_virt = (0x5D0000 + lo) & 0xFFFFFFFF
        ptr_array_phys = ptr_array_virt - VIRT_BASE

        # Read first two pointers from the array
        if ptr_array_phys + 8 > len(self._data):
            raise ValueError(f"Pointer array out of range: 0x{ptr_array_phys:06X}")
        ldrxn1 = struct.unpack_from(">I", self._data, ptr_array_phys)[0]
        ldrxn2 = struct.unpack_from(">I", self._data, ptr_array_phys + 4)[0]

        return {
            "PATCH_LDRXN":  SigResult(physical=patch_addr,
                                      virtual=_to_virt(patch_addr),
                                      note="lwzx r3,r10,r9 — redirect this for multimap"),
            "TABLE_LDRXN1": SigResult(physical=ldrxn1 - VIRT_BASE,
                                      virtual=ldrxn1,
                                      note="RPM axis; load values at +32B"),
            "TABLE_LDRXN2": SigResult(physical=ldrxn2 - VIRT_BASE,
                                      virtual=ldrxn2,
                                      note="RPM axis; load values at +32B (alternate map)"),
        }

    def find_kwp_table(self) -> SigResult:
        """
        KWP_TABLE — KWP2000 service handler dispatch table.
        Used by the KWP handler extension patch (EliasTuning/MED9-Patches).

        Signature v1:
          20 ff ff ff   (−1 sentinel entry)
          00 00 00 XX   service ID byte
          00 XX XX XX   handler address
          00 00 00 00
          00 00 00 00
        """
        pattern = "20FFFFFF 000000XX 00XXXXXX 00000000 00000000"
        try:
            sig_start = self._find(pattern)
            table_addr = sig_start + 20
            return SigResult(physical=table_addr, virtual=_to_virt(table_addr))
        except ValueError:
            # v2: has FFFFFFFF in second entry
            pattern2 = "20FFFFFF FFFFFFFF 00XXXXXX 00000000 00000000 01FFFFFF"
            sig_start = self._find(pattern2)
            table_addr = sig_start + 24
            return SigResult(physical=table_addr, virtual=_to_virt(table_addr))

    def find_vkKraQu(self) -> SigResult:
        """
        vkKraQu — Knock retard write instruction.
        NOPing this is used by multimap to prevent one map's knock
        adaptation from corrupting the other map.
        Signature: stb rX, N(r13) near a specific sequence.
        (Address 0x57A820 in 1K8907115F, varies by variant.)
        """
        # stb rX, N(r13) = 0x99 xD XX XX (op=38, rA=13)
        # Preceded by specific knock calculation pattern
        pattern = "994DXXXX 546XXXXX"
        sig_start = self._find(pattern, 0x0A0000, 0x1C0000)
        return SigResult(physical=sig_start, virtual=_to_virt(sig_start),
                         note="NOP this to prevent cross-map knock adaptation")

    # ── CD diagnostic parameter locator ──────────────────────────────────────

    def find_cd_block(self) -> SigResult:
        """
        Find the CD diagnostic enable parameter block.
        Confirmed at 0x1DD640 in 1K0907115S (physical).
        Uses the known byte sequence pattern around CDKAT/CDHSH.

        Pattern: isolated single-byte values 0x00/0x01/0x07 in a
        contiguous run, preceded by numeric data — fragile across variants.
        A more robust approach uses the XDF or a DAMOS map.
        """
        # CDHSH=0x01, CDHSHE=0x00, CDHSV=0x01, CDHSVSA=0x00, CDKAT=0x00, CDKATSP=0x07
        pattern = "01000100000701"  # CDHSH..CDKATSP
        try:
            off = self._find(pattern, 0x1C0000, 0x200000)
            return SigResult(physical=off, virtual=_to_virt(off),
                             note="CD block: CDHSH at offset +0, CDKAT at +4")
        except ValueError:
            raise ValueError("CD param block not found — needs XDF or DAMOS for this variant")
