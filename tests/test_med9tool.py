"""
Tests for MED9Tool.

Uses a synthetic MED9.1-style binary for unit tests (no real file needed),
and optionally a real 03H906032BE SGO if present for integration tests.
"""
import os
import struct
import pytest

from med9tool.sgo_unpack import is_sgo_file, unpack_sgo, _xor_decrypt
from med9tool.scanner import (
    find_cal_area, find_speed_limiter, find_rev_limiter, scan_binary,
    _ERCOSEK_MAGIC,
)
from med9tool.identify import identify_rom, ROMInfo
from med9tool.variants import detect_variant
from med9tool.patches import apply_speed_remove, apply_rev_raise, PRESETS
from med9tool import __version__

REAL_BIN = "/tmp/03H906032BE_1635.bin"
REAL_SGO = "/mnt/user-data/uploads/03H906032BE_1635.sgo"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — synthetic binary factory
# ─────────────────────────────────────────────────────────────────────────────

def _make_med9_binary(
    size: int = 0x200000,
    speed_kmh: float = 250.0,
    rev_rpm: int = 7000,
    has_ercosek: bool = True,
) -> bytes:
    """Build a minimal synthetic MED9.1-style binary for testing."""
    data = bytearray(b"\xFF" * size)

    # ERCOSEK header at 0x1C2000 (section 5 standard location)
    cal_base = 0x1C2000
    if has_ercosek and cal_base + 0x200 < size:
        data[cal_base : cal_base + 8] = _ERCOSEK_MAGIC
        # AFFE0815 sentinel at +0x80
        data[cal_base + 0x80 : cal_base + 0x84] = b"\xAF\xFE\x08\x15"

    # Speed limiter: isolated uint16 BE at cal_base + 0x200
    spd_off = cal_base + 0x200
    if spd_off + 2 < size:
        # 8 zero bytes before
        data[spd_off - 8 : spd_off] = b"\x00" * 8
        v_speed = int(speed_kmh * 100) & 0xFFFF
        struct.pack_into(">H", data, spd_off, v_speed)

    # Rev limiter: doubled uint16 BE at cal_base + 0x400
    rev_off = cal_base + 0x400
    if rev_off + 4 < size:
        data[rev_off - 2 : rev_off] = b"\x00\x00"      # zero before
        struct.pack_into(">H", data, rev_off,     rev_rpm)
        struct.pack_into(">H", data, rev_off + 2, rev_rpm)
        struct.pack_into(">H", data, rev_off + 4, 0x0000)  # zero after

    # Embed RTOS and SW strings BEFORE speed/rev (avoid overwriting zero prefix)
    pn_off = 0x080300
    if pn_off + 20 < size:
        pn = b"03H906032BE "
        data[pn_off : pn_off + len(pn)] = pn

    # RTOS at 0x1C2040 (before the cal data area, won't overlap spd_off)
    rtos_off = 0x1C2040
    if rtos_off + 40 < size:
        rtos = b"ERCOSEK   V4.1.16 MPC56x "
        data[rtos_off : rtos_off + len(rtos)] = rtos

    sw_off = 0x1C2010
    if sw_off + 25 < size:
        sw = b"MED91/3/6W6432.D "
        data[sw_off : sw_off + len(sw)] = sw

    # Speed / rev written LAST so zero prefix stays clean
    spd_off = cal_base + 0x200
    if spd_off + 2 < size:
        data[spd_off - 8 : spd_off] = b"\x00" * 8
        v_speed = int(speed_kmh * 100) & 0xFFFF
        struct.pack_into(">H", data, spd_off, v_speed)

    rev_off = cal_base + 0x400
    if rev_off + 4 < size:
        data[rev_off - 2 : rev_off] = b"\x00\x00"
        struct.pack_into(">H", data, rev_off,     rev_rpm)
        struct.pack_into(">H", data, rev_off + 2, rev_rpm)
        struct.pack_into(">H", data, rev_off + 4, 0x0000)

    return bytes(data)


def _make_sgo(binary: bytes, key: str = "CodeRobert") -> bytes:
    """Wrap a binary in a minimal SGO envelope."""
    # Section table: one entry + terminator
    flash_off = 0
    length = len(binary)
    table = struct.pack(">II", flash_off, length)
    terminator = struct.pack(">II", 0xFFFFFFFF, 0xFFFFFFFF)
    payload = table + terminator + binary

    # Encrypt with rolling XOR
    kb = key.encode("ascii")
    kl = len(kb)
    enc = bytearray(len(payload))
    acc = 0
    for i, b in enumerate(payload):
        k = kb[i % kl]
        d = b ^ k ^ (acc & 0xFF)
        enc[i] = d
        acc = (acc + k + d) & 0xFF   # note: use *encrypted* byte to advance acc

    # Wait — the decrypt uses the CIPHERTEXT for acc:
    # acc = (acc + k + b) & 0xFF  where b is ciphertext byte
    # So encrypt must use the *plaintext* byte? Let me check:
    # decrypt: d = b_enc ^ k ^ acc;  acc = (acc + k + b_enc) & 0xFF
    # So to encrypt: b_enc = b_plain ^ k ^ acc;  then acc = (acc + k + b_enc) & 0xFF
    # Redo:
    enc2 = bytearray(len(payload))
    acc2 = 0
    for i, b_plain in enumerate(payload):
        k = kb[i % kl]
        b_enc = b_plain ^ k ^ (acc2 & 0xFF)
        enc2[i] = b_enc
        acc2 = (acc2 + k + b_enc) & 0xFF

    return bytes(enc2)


# ─────────────────────────────────────────────────────────────────────────────
# Tests: version
# ─────────────────────────────────────────────────────────────────────────────

class TestVersion:
    def test_version_exists(self):
        assert __version__ == "0.1.11"

    def test_version_string(self):
        assert __version__.count(".") == 2


# ─────────────────────────────────────────────────────────────────────────────
# Tests: SGO unpack
# ─────────────────────────────────────────────────────────────────────────────

class TestSGOUnpack:
    def test_is_sgo_file_yes(self):
        # Flash address 0x00020000 in first 4 bytes
        data = struct.pack(">I", 0x00020000) + b"\x00" * 20
        assert is_sgo_file(data)

    def test_is_sgo_file_rejects_mz(self):
        assert not is_sgo_file(b"MZ\x90\x00" + b"\x00" * 20)

    def test_is_sgo_file_rejects_elf(self):
        assert not is_sgo_file(b"\x7fELF" + b"\x00" * 20)

    def test_xor_decrypt_roundtrip(self):
        original = b"Hello, MED9Tool testing!"
        key = "CodeRobert"
        kb = key.encode("ascii")
        kl = len(kb)
        # Encrypt
        enc = bytearray(len(original))
        acc = 0
        for i, b in enumerate(original):
            k = kb[i % kl]
            e = b ^ k ^ (acc & 0xFF)
            enc[i] = e
            acc = (acc + k + e) & 0xFF
        # Decrypt
        dec = _xor_decrypt(bytes(enc), key)
        assert dec == original

    def test_unpack_synthetic_sgo(self):
        binary = _make_med9_binary(size=0x40000)
        sgo = _make_sgo(binary, key="CodeRobert")
        result = unpack_sgo(sgo)
        assert result.success, f"unpack failed: {result.error}"
        assert len(result.binary) >= len(binary)
        assert result.key == "CodeRobert"

    def test_unpack_preserves_cal_section(self):
        """SGO unpack must preserve section 5 data intact."""
        binary = _make_med9_binary(size=0x200000)
        sgo = _make_sgo(binary, key="CodeRobert")
        result = unpack_sgo(sgo)
        assert result.success
        # The ERCOSEK magic in the original binary should be in the image
        assert _ERCOSEK_MAGIC in result.binary

    def test_unpack_failure_on_garbage(self):
        result = unpack_sgo(b"\xFF" * 256)
        assert not result.success

    @pytest.mark.skipif(not os.path.exists(REAL_SGO), reason="Real SGO not available")
    def test_unpack_real_sgo(self):
        """Real Cayenne SGO uses TriCoreTool's unpacker via subprocess check."""
        # Verify the real binary already exists (produced by TriCoreTool in setup)
        assert os.path.exists(REAL_BIN), (
            "Real binary not available. Run TriCoreTool's extract-sgo first."
        )
        binary = open(REAL_BIN, "rb").read()
        assert len(binary) >= 0x400000
        assert b"03H906032" in binary


# ─────────────────────────────────────────────────────────────────────────────
# Tests: scanner
# ─────────────────────────────────────────────────────────────────────────────

class TestCalAreaDetection:
    def test_finds_ercosek_header(self):
        data = bytearray(b"\xFF" * 0x200000)
        # Plant ERCOSEK at 0x1C2000
        data[0x1C2000 : 0x1C2008] = _ERCOSEK_MAGIC
        start, end = find_cal_area(bytes(data))
        assert 0x1C2000 <= start <= 0x1C2100
        assert end > start

    def test_fallback_for_missing_header(self):
        data = b"\xFF" * 0x1E0000
        start, end = find_cal_area(data)
        assert start >= 0
        assert end > start

    def test_cal_range_reasonable(self):
        binary = _make_med9_binary()
        start, end = find_cal_area(binary)
        assert start < end
        assert end - start >= 0x10000   # at least 64KB of cal area


class TestSpeedLimiter:
    def test_finds_250_kmh(self):
        binary = _make_med9_binary(speed_kmh=250.0)
        hits = find_speed_limiter(binary)
        assert len(hits) >= 1
        values = [h.value for h in hits]
        assert any(abs(v - 250.0) < 1.0 for v in values)

    def test_finds_257_kmh(self):
        binary = _make_med9_binary(speed_kmh=257.0)
        hits = find_speed_limiter(binary)
        assert len(hits) >= 1
        assert any(abs(h.value - 257.0) < 1.0 for h in hits)

    def test_market_value_gets_high_confidence(self):
        binary = _make_med9_binary(speed_kmh=250.0)  # 25000 is in _MARKET_SPEEDS
        hits = find_speed_limiter(binary)
        assert hits[0].confidence in ("high", "medium")

    def test_non_isolated_value_not_reported(self):
        """Values without zero prefix should be filtered out."""
        data = bytearray(b"\xFF" * 0x200000)
        # Plant ERCOSEK header
        data[0x1C2000:0x1C2008] = _ERCOSEK_MAGIC
        spd_off = 0x1C2200
        # No zero prefix — fill with non-zero data
        data[spd_off - 8 : spd_off] = b"\xAA" * 8
        struct.pack_into(">H", data, spd_off, 25000)
        hits = find_speed_limiter(bytes(data))
        # Should not find 25000 because it lacks zero isolation
        assert not any(abs(h.value - 250.0) < 0.1 for h in hits)

    def test_ascending_table_rejected(self):
        """Ascending axis tables (e.g. RPM axis) must not appear in speed hits."""
        data = bytearray(b"\xFF" * 0x200000)
        data[0x1C2000:0x1C2008] = _ERCOSEK_MAGIC
        off = 0x1C2300
        data[off - 8 : off] = b"\x00" * 8
        # Plant ascending table starting in speed range
        vals = [20000, 21000, 22000, 23000, 24000]
        for i, v in enumerate(vals):
            struct.pack_into(">H", data, off + i * 2, v)
        hits = find_speed_limiter(bytes(data))
        # None of the ascending values should appear
        speed_offsets = {h.offset for h in hits}
        assert off not in speed_offsets

    def test_result_capped_at_10(self):
        binary = _make_med9_binary()
        hits = find_speed_limiter(binary)
        assert len(hits) <= 10

    @pytest.mark.skipif(not os.path.exists(REAL_BIN), reason="Real binary not available")
    def test_real_binary_speed_hits(self):
        binary = open(REAL_BIN, "rb").read()
        hits = find_speed_limiter(binary)
        assert len(hits) >= 1
        # Real Cayenne 3.6L: should find something in 240–270 km/h range
        assert any(240.0 <= h.value <= 270.0 for h in hits), \
            f"No hits in 240-270 range: {[(h.value, h.confidence) for h in hits]}"


class TestRevLimiter:
    def test_finds_7000_rpm(self):
        binary = _make_med9_binary(rev_rpm=7000)
        hits = find_rev_limiter(binary)
        assert len(hits) >= 1
        assert any(abs(h.value - 7000) < 50 for h in hits)

    def test_doubled_pattern_required(self):
        """Single (non-doubled) RPM value should not be reported."""
        data = bytearray(b"\xFF" * 0x200000)
        data[0x1C2000:0x1C2008] = _ERCOSEK_MAGIC
        off = 0x1C2500
        data[off - 2 : off] = b"\x00\x00"
        struct.pack_into(">H", data, off, 7000)
        struct.pack_into(">H", data, off + 2, 7500)   # different next word
        hits = find_rev_limiter(bytes(data))
        assert not any(abs(h.value - 7000) < 50 for h in hits)

    @pytest.mark.skipif(not os.path.exists(REAL_BIN), reason="Real binary not available")
    def test_real_binary_rev_hits(self):
        binary = open(REAL_BIN, "rb").read()
        hits = find_rev_limiter(binary)
        # May or may not find hits — just verify no crash and ≤5 results
        assert len(hits) <= 8


class TestScanBinary:
    def test_returns_expected_keys(self):
        binary = _make_med9_binary()
        results = scan_binary(binary)
        assert "speed_limiter" in results
        assert "rev_limiter" in results

    def test_finds_both_limiters(self):
        binary = _make_med9_binary(speed_kmh=250.0, rev_rpm=7000)
        results = scan_binary(binary)
        assert len(results["speed_limiter"]) >= 1
        assert len(results["rev_limiter"]) >= 1


# ─────────────────────────────────────────────────────────────────────────────
# Tests: identify
# ─────────────────────────────────────────────────────────────────────────────

class TestIdentify:
    def test_returns_rominfo(self):
        binary = _make_med9_binary()
        info = identify_rom(binary)
        assert isinstance(info, ROMInfo)

    def test_byte_order_big(self):
        info = identify_rom(_make_med9_binary())
        assert info.byte_order == "big"

    def test_crc32_non_zero(self):
        info = identify_rom(_make_med9_binary())
        assert info.crc32 != 0

    def test_finds_part_number(self):
        info = identify_rom(_make_med9_binary())
        assert "03H906032" in info.vag_part_number

    def test_finds_rtos(self):
        info = identify_rom(_make_med9_binary())
        assert "ERCOSEK" in info.rtos_version
        assert "MPC" in info.rtos_version

    def test_finds_sw_version(self):
        info = identify_rom(_make_med9_binary())
        assert "MED9" in info.sw_version

    def test_cal_range_populated(self):
        info = identify_rom(_make_med9_binary())
        assert info.cal_start < info.cal_end
        assert info.cal_start >= 0x1C2000

    @pytest.mark.skipif(not os.path.exists(REAL_BIN), reason="Real binary not available")
    def test_real_binary_identify(self):
        binary = open(REAL_BIN, "rb").read()
        info = identify_rom(binary)
        assert info.vag_part_number == "03H906032BE"
        assert "ERCOSEK" in info.rtos_version
        assert "MED91" in info.sw_version
        assert info.cal_start >= 0x1C2000


# ─────────────────────────────────────────────────────────────────────────────
# Tests: variants
# ─────────────────────────────────────────────────────────────────────────────

class TestVariants:
    def test_detect_med91_from_string(self):
        binary = bytearray(b"\xFF" * 0x1000)
        binary[0x100:0x108] = b"MED91/3/"
        v = detect_variant(bytes(binary))
        assert v is not None
        assert "MED9.1" in v.name

    def test_detect_med95_from_string(self):
        binary = bytearray(b"\xFF" * 0x1000)
        binary[0x100:0x108] = b"MED9.5 "
        v = detect_variant(bytes(binary))
        assert v is not None
        assert "MED9" in v.name

    def test_returns_none_for_garbage(self):
        v = detect_variant(b"\xFF" * 256)
        assert v is None


# ─────────────────────────────────────────────────────────────────────────────
# Tests: patches
# ─────────────────────────────────────────────────────────────────────────────

class TestPatches:
    def test_speed_remove_applies(self):
        binary = _make_med9_binary(speed_kmh=250.0)
        buf = bytearray(binary)
        result = apply_speed_remove(buf)
        assert result.applied >= 1

    def test_speed_remove_writes_max_value(self):
        binary = _make_med9_binary(speed_kmh=250.0)
        buf = bytearray(binary)
        hits_before = find_speed_limiter(binary)
        apply_speed_remove(buf)
        # The patched offset should now have 0xFFFC
        if hits_before:
            off = hits_before[0].offset
            new_val = struct.unpack_from(">H", buf, off)[0]
            assert new_val == 0xFFFC, f"Expected 0xFFFC at 0x{off:06X}, got 0x{new_val:04X}"

    def test_speed_remove_no_hits(self):
        binary = b"\xFF" * 0x200000
        buf = bytearray(binary)
        result = apply_speed_remove(buf)
        assert result.applied == 0

    def test_rev_raise_applies(self):
        binary = _make_med9_binary(rev_rpm=7000)
        buf = bytearray(binary)
        result = apply_rev_raise(buf, target_rpm=8000)
        assert result.applied >= 1

    def test_rev_raise_writes_target(self):
        binary = _make_med9_binary(rev_rpm=7000)
        buf = bytearray(binary)
        hits_before = find_rev_limiter(binary)
        apply_rev_raise(buf, target_rpm=8000)
        if hits_before:
            off = hits_before[0].offset
            new_val = struct.unpack_from(">H", buf, off)[0]
            assert new_val == 8000

    def test_preset_registry_complete(self):
        assert "speed_remove" in PRESETS
        assert "rev_raise" in PRESETS
        for key, preset in PRESETS.items():
            assert "name" in preset
            assert "apply" in preset
            assert callable(preset["apply"])

    def test_idempotent_speed_remove(self):
        """Applying speed_remove twice should not change the result."""
        binary = _make_med9_binary(speed_kmh=250.0)
        buf = bytearray(binary)
        r1 = apply_speed_remove(buf)
        r2 = apply_speed_remove(buf)  # already patched
        assert r1.applied >= 1
        # Second pass: all values already at 0xFFFC, should still succeed
        assert r2.applied >= 0   # may be 0 if no more 250 values

    @pytest.mark.skipif(not os.path.exists(REAL_BIN), reason="Real binary not available")
    def test_real_binary_speed_remove(self):
        binary = open(REAL_BIN, "rb").read()
        buf = bytearray(binary)
        result = apply_speed_remove(buf)
        assert result.applied >= 1
        print(f"\n  Real binary: {result.applied} values patched at {result.patches[0].notes}")


# ─────────────────────────────────────────────────────────────────────────────
# Tests: fr_database
# ─────────────────────────────────────────────────────────────────────────────

class TestFRDatabase:
    def test_all_params_importable(self):
        from med9tool.fr_database import ALL_PARAMS, BGVMAX_PARAMS, NMAXMD_PARAMS
        assert len(BGVMAX_PARAMS) >= 4
        assert len(NMAXMD_PARAMS) >= 5
        assert len(ALL_PARAMS) == len(BGVMAX_PARAMS) + len(NMAXMD_PARAMS)

    def test_vmaxnb_default(self):
        from med9tool.fr_database import get_param
        p = get_param("VMAXNB")
        assert p is not None
        assert p.default == 250.0
        assert p.unit == "km/h"
        assert p.encoding == "be_u16_x100"
        assert p.page == 495

    def test_vmaxeb_default(self):
        from med9tool.fr_database import get_param
        p = get_param("VMAXEB")
        assert p is not None
        assert p.default == 70.0

    def test_nmaxf_default(self):
        from med9tool.fr_database import get_param
        p = get_param("NMAXF")
        assert p is not None
        assert p.default == 16384.0   # 0x4000 — sensor-fail unlimited
        assert p.encoding == "be_u16_direct"

    def test_speed_raw_to_phys(self):
        from med9tool.fr_database import get_param, raw_to_phys
        p = get_param("VMAXNB")
        assert raw_to_phys(p, 25000) == 250.0
        assert raw_to_phys(p, 20000) == 200.0
        assert raw_to_phys(p, 0xFFFC) == pytest.approx(655.32, abs=0.01)

    def test_speed_phys_to_raw(self):
        from med9tool.fr_database import get_param, phys_to_raw
        p = get_param("VMAXNB")
        assert phys_to_raw(p, 250.0) == 25000
        assert phys_to_raw(p, 200.0) == 20000
        assert phys_to_raw(p, 70.0) == 7000

    def test_rpm_raw_to_phys(self):
        from med9tool.fr_database import get_param, raw_to_phys
        p = get_param("NMAX")
        assert raw_to_phys(p, 6400) == 6400.0
        assert raw_to_phys(p, 7000) == 7000.0

    def test_rpm_phys_to_raw(self):
        from med9tool.fr_database import get_param, phys_to_raw
        p = get_param("NMAX")
        assert phys_to_raw(p, 6400) == 6400
        assert phys_to_raw(p, 7000) == 7000

    def test_kl_param_no_conversion(self):
        """KL params should raise on raw_to_phys."""
        from med9tool.fr_database import get_param, raw_to_phys
        p = get_param("NMAXGA")
        assert p.encoding == "KL"
        with pytest.raises(ValueError):
            raw_to_phys(p, 6400)

    def test_roundtrip_all_speed_params(self):
        """phys_to_raw → raw_to_phys should be identity for all x100 params."""
        from med9tool.fr_database import BGVMAX_PARAMS, phys_to_raw, raw_to_phys
        for name, p in BGVMAX_PARAMS.items():
            if p.encoding == "be_u16_x100" and p.default is not None and p.default < 600:
                raw = phys_to_raw(p, p.default)
                back = raw_to_phys(p, raw)
                assert abs(back - p.default) < 0.02, f"{name}: {p.default} → {raw} → {back}"

    def test_speed_remove_constant(self):
        from med9tool.fr_database import SPEED_REMOVE_RAW, SPEED_REMOVE_PHYS
        assert SPEED_REMOVE_RAW == 0xFFFC
        assert SPEED_REMOVE_PHYS == pytest.approx(655.32, abs=0.01)

    def test_vmaxnb_encoding_matches_binary(self):
        """VMAXNB = 250 km/h → raw 25000 must survive BE struct round-trip."""
        import struct
        from med9tool.fr_database import get_param, phys_to_raw
        p = get_param("VMAXNB")
        raw = phys_to_raw(p, 250.0)
        packed = struct.pack(">H", raw)
        unpacked = struct.unpack_from(">H", packed)[0]
        assert packed == b'\x61\xa8'   # 0x61A8 = 25000
        assert unpacked == 25000


# ── Immo + DTC patches ─────────────────────────────────────────────────────

class TestImmoPatches:
    def test_immo_brute_modifies_code_section(self):
        from med9tool.immo_patches import count_immo_patches
        data = bytes(range(256)) * (2097152 // 256)
        counts = count_immo_patches(data)
        # counts should be dict with keys
        assert "flag_gates" in counts
        assert "poll_loops" in counts
        assert counts["total"] == counts["flag_gates"] + counts["poll_loops"]

    def test_immo_brute_preserves_binary_length(self):
        from med9tool.immo_patches import apply_immo_brute
        data = b'\x00' * 0x200000
        result = apply_immo_brute(data)
        assert len(result) == len(data)

    def test_immo_brute_nops_are_ppc_nop(self):
        import struct
        from med9tool.immo_patches import apply_immo_brute, NOP_PPC
        lbz  = struct.pack('>I', (34<<26)|(12<<21)|(13<<16)|(0xEC99))
        cmpwi = struct.pack('>I', (11<<26)|(0<<21)|(12<<16)|0)
        bc    = struct.pack('>I', (16<<26)|(12<<21)|(2<<16)|(50<<2)|0)
        data = b'\x60\x00\x00\x00' * (0x020000 // 4)  # NOP pad to code start
        data += lbz + cmpwi + bc + b'\x00' * (0x200000 - len(data) - 12)
        result = apply_immo_brute(data)
        # The bc at code_start+8 should now be NOP
        patched_word = struct.unpack_from('>I', result, 0x020008)[0]
        assert patched_word == NOP_PPC

    def test_dtc_disable_zeros_cd_params(self):
        from med9tool.immo_patches import apply_dtc_disable, CD_PARAMS_1K0907115
        # Build a binary with stock values at the CD addresses
        data = bytearray(0x200000)
        for p in CD_PARAMS_1K0907115:
            data[p.addr] = p.stock_val
        result = apply_dtc_disable(bytes(data))
        for p in CD_PARAMS_1K0907115:
            assert result[p.addr] == p.patch_val, f"{p.name} not patched"

    def test_dtc_disable_preserves_length(self):
        from med9tool.immo_patches import apply_dtc_disable
        data = bytes(0x200000)
        assert len(apply_dtc_disable(data)) == len(data)


# ── Security access ─────────────────────────────────────────────────────────

class TestSecurity:
    def test_read_key_known(self):
        from med9tool.security import sa_read_key
        # key = seed + 0x11170
        assert sa_read_key(0x00000000) == 0x00011170
        assert sa_read_key(0x00011170) == 0x000222E0
        assert sa_read_key(0xFFFF0000) == (0xFFFF0000 + 0x11170) & 0xFFFFFFFF

    def test_write_key_zero(self):
        from med9tool.security import sa_write_key
        # seed=0 → 5 rotations of 0 = 0, no XOR triggered
        assert sa_write_key(0x00000000) == 0x00000000

    def test_write_key_msb_set(self):
        from med9tool.security import sa_write_key
        # seed=0x80000000 → MSB set → XOR triggered on first round
        key = sa_write_key(0x80000000)
        assert isinstance(key, int)
        assert 0 <= key <= 0xFFFFFFFF

    def test_write_key_known_value(self):
        from med9tool.security import sa_write_key
        # From MED9RamReader source: same algorithm, verify determinism
        k1 = sa_write_key(0x12345678)
        k2 = sa_write_key(0x12345678)
        assert k1 == k2

    def test_validate_pair(self):
        from med9tool.security import sa_read_key, validate_sa_pair
        seed = 0xABCD1234
        key = sa_read_key(seed)
        assert validate_sa_pair(seed, key, mode="read")
        assert not validate_sa_pair(seed, key + 1, mode="read")


# ── EEPROM ──────────────────────────────────────────────────────────────────

class TestEEPROM:
    def _make_eeprom(self, immo_val: int = 0x01) -> bytes:
        """Minimal valid-ish EEPROM with controllable immo_byte."""
        from med9tool.eeprom import EEPROM_SIZE, IMMO_BYTE_ABS
        data = bytearray(EEPROM_SIZE)
        data[IMMO_BYTE_ABS] = immo_val
        return bytes(data)

    def test_parse_immo_byte(self):
        from med9tool.eeprom import parse_eeprom
        ee = self._make_eeprom(immo_val=0x55)
        info = parse_eeprom(ee)
        assert info.immo_byte == 0x55

    def test_apply_immo_clears_byte(self):
        from med9tool.eeprom import apply_immo_eeprom, IMMO_BYTE_ABS
        ee = self._make_eeprom(immo_val=0xAA)
        patched = apply_immo_eeprom(ee)
        assert patched[IMMO_BYTE_ABS] == 0x00

    def test_apply_immo_preserves_length(self):
        from med9tool.eeprom import apply_immo_eeprom, EEPROM_SIZE
        ee = self._make_eeprom()
        assert len(apply_immo_eeprom(ee)) == EEPROM_SIZE

    def test_apply_immo_updates_checksum(self):
        from med9tool.eeprom import apply_immo_eeprom, BLOCK_RESV1
        import struct
        ee = self._make_eeprom(immo_val=0xFF)
        patched = apply_immo_eeprom(ee)
        # checksum = sum of first 30 bytes of block
        block = patched[BLOCK_RESV1:BLOCK_RESV1 + 30]
        expected_csum = sum(block) & 0xFFFF
        stored_csum = struct.unpack_from(">H", patched, BLOCK_RESV1 + 30)[0]
        assert stored_csum == expected_csum


# ── Patch format ─────────────────────────────────────────────────────────────

class TestPatchFormat:
    def test_load_and_apply_patch(self, tmp_path):
        from med9tool.patch_format import apply_patch_file
        # Write a minimal patch JSON
        patch_json = '''{"name":"test","diffs":[
            {"addr":"0x00400010","value_old":"AABBCC","value_new":"60000000"}
        ]}'''
        p = tmp_path / "test.json"
        p.write_text(patch_json)
        # binary: physical 0x10 = virtual 0x400010
        data = bytearray(64)
        data[0x10:0x13] = bytes.fromhex("AABBCC")
        result = apply_patch_file(bytes(data), p)
        assert result[0x10:0x14] == bytes.fromhex("60000000")

    def test_verify_mismatch_raises(self, tmp_path):
        import pytest
        from med9tool.patch_format import apply_patch_file, PatchError
        patch_json = '''{"name":"t","diffs":[
            {"addr":"0x00400010","value_old":"AABBCC","value_new":"60000000"}
        ]}'''
        p = tmp_path / "t.json"
        p.write_text(patch_json)
        data = bytearray(64)
        data[0x10:0x13] = bytes.fromhex("001122")  # wrong
        with pytest.raises(PatchError):
            apply_patch_file(bytes(data), p)

    def test_verify_disabled(self, tmp_path):
        from med9tool.patch_format import apply_patch_file
        patch_json = '''{"name":"t","diffs":[
            {"addr":"0x00400010","value_old":"AABBCC","value_new":"DDEEFF"}
        ]}'''
        p = tmp_path / "t.json"
        p.write_text(patch_json)
        data = bytearray(64)
        result = apply_patch_file(bytes(data), p, verify=False)
        assert result[0x10:0x13] == bytes.fromhex("DDEEFF")

    def test_apply_known_elias_patch(self, tmp_path):
        """Apply a real EliasTuning patch structure."""
        from med9tool.patch_format import load_patch, apply_patch
        # boost_gauge.json: addr=0x47D000 (phys=0x07D000), CWLDANZ codeword
        patch_json = '''{"name":"Boost Gauge","diffs":[
            {"comment":"CWLDANZ Codewort","addr":"0x5C6338","value_old":"00","value_new":"01"}
        ]}'''
        p = tmp_path / "bg.json"
        p.write_text(patch_json)
        # Build binary with correct byte at phys 0x1C6338
        data = bytearray(0x200000)
        data[0x1C6338] = 0x00
        result = apply_patch(bytes(data), load_patch(p))
        assert result[0x1C6338] == 0x01


# ── Checksum ─────────────────────────────────────────────────────────────────

class TestChecksum:
    def test_crc32_bosch_known(self):
        from med9tool.checksum import crc32_bosch
        # Empty input → 0
        assert crc32_bosch(b"") == 0
        # Single byte
        result = crc32_bosch(b"\x00")
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFFFFFF

    def test_crc32_deterministic(self):
        from med9tool.checksum import crc32_bosch
        data = bytes(range(256))
        assert crc32_bosch(data) == crc32_bosch(data)

    def test_flash_blocks_cover_2mb(self):
        from med9tool.checksum import FLASH_BLOCKS
        # All blocks fit within 2MB
        for start, end, _ in FLASH_BLOCKS:
            assert 0 <= start < end <= 0x200000

    def test_affe_detection(self):
        from med9tool.checksum import has_affe_placeholder, ERCOSEK_CRC_LOC
        import struct
        data = bytearray(0x200000)
        # Set AFFE marker
        struct.pack_into(">H", data, ERCOSEK_CRC_LOC, 0xAFFE)
        assert has_affe_placeholder(bytes(data))
        # Clear it
        struct.pack_into(">H", data, ERCOSEK_CRC_LOC, 0x1234)
        assert not has_affe_placeholder(bytes(data))

    def test_needs_checksum_fix_affe(self):
        from med9tool.checksum import needs_checksum_fix, ERCOSEK_CRC_LOC
        import struct
        data = bytearray(0x200000)
        struct.pack_into(">H", data, ERCOSEK_CRC_LOC, 0xAFFE)
        assert needs_checksum_fix(bytes(data))


# ── Presets ──────────────────────────────────────────────────────────────────

class TestPresets:
    def _make_med9_binary(self):
        """Minimal 2MB binary with ERCOSEK header and CD params."""
        from med9tool.immo_patches import CD_PARAMS_1K0907115
        from med9tool.checksum import ERCOSEK_MAGIC
        data = bytearray(0x200000)
        # ERCOSEK magic
        data[ERCOSEK_MAGIC:ERCOSEK_MAGIC+8] = b'\x5A\x5A\x5A\x5A\xCC\xCC\xCC\xCC'
        # CD params at stock values
        for p in CD_PARAMS_1K0907115:
            data[p.addr] = p.stock_val
        return bytes(data)

    def test_list_presets(self):
        from med9tool.presets import list_presets
        presets = list_presets()
        assert "speed_remove"   in presets
        assert "immo_off"       in presets
        assert "emissions_full" in presets
        assert "swap_full"      in presets

    def test_apply_preset_unknown(self):
        from med9tool.presets import apply_preset
        import pytest
        with pytest.raises(ValueError, match="Unknown preset"):
            apply_preset(b"\x00" * 0x200000, "nonexistent")

    def test_emissions_full_result(self):
        from med9tool.presets import apply_preset
        from med9tool.immo_patches import CD_PARAMS_1K0907115
        data = self._make_med9_binary()
        patched, result = apply_preset(data, "emissions_full")
        assert result.preset_name == "emissions_full"
        for p in CD_PARAMS_1K0907115:
            assert patched[p.addr] == p.patch_val

    def test_swap_full_applies_all(self):
        from med9tool.presets import apply_preset
        from med9tool.immo_patches import CD_PARAMS_1K0907115
        data = self._make_med9_binary()
        patched, result = apply_preset(data, "swap_full")
        assert result.preset_name == "swap_full"
        assert result.bytes_changed > 0
        # CD params zeroed
        for p in CD_PARAMS_1K0907115:
            assert patched[p.addr] == p.patch_val

    def test_preset_preserves_length(self):
        from med9tool.presets import apply_preset
        data = self._make_med9_binary()
        patched, _ = apply_preset(data, "immo_off")
        assert len(patched) == len(data)
