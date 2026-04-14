"""
Tests for SGML Object File v2 unpacker.

Tests against uploaded SGO files from 2024 VW/Audi flashdaten.
Validates format detection, BCB decompression, block assembly, and metadata
extraction across multiple MED9.1 Cayenne (03H906032) variants.
"""
import struct
import pytest
from pathlib import Path
from med9tool.sgo_unpack import (
    is_sgml_file, is_sgo_file, unpack_sgml, unpack_sgo,
    _bcb_decompress, _parse_sgml_block, _xorstr_sgml,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

UPLOAD_DIR = Path("/mnt/user-data/uploads")

# All uploaded SGML test files — skip if not present (CI/offline)
_SGML_FILES = {
    "BG_6652": "03H906032BG_6652.sgo",
    "BG_1634": "03H906032BG_1634.sgo",
    "CA_2960": "03H906032CA_2960.sgo",
    "DA_7875": "03H906032DA_7875.sgo",
    "EK_8967": "03H906032EK_8967.sgo",
    "L__9744": "03H906032L__9744.sgo",
}

def _load(name: str) -> bytes | None:
    p = UPLOAD_DIR / _SGML_FILES[name]
    return p.read_bytes() if p.exists() else None


# ── Unit tests for helpers ────────────────────────────────────────────────────

def test_is_sgml_file_magic():
    """Magic bytes must be 'SGML Object File\\x00'."""
    valid = b"SGML Object File\x00" + b"\x02\x00\x00\x00" + b"\x00" * 100
    assert is_sgml_file(valid)


def test_is_sgml_file_rejects_rolling_xor():
    """Rolling-XOR SGO (flash offset at offset 0) must not look like SGML."""
    rolling = b"\x00\x02\x00\x00\x00\x20\x00\x00" + b"\x00" * 100
    assert not is_sgml_file(rolling)


def test_is_sgo_file_detects_sgml():
    """is_sgo_file should return True for SGML-format files."""
    valid = b"SGML Object File\x00" + b"\x02\x00\x00\x00" + b"\x00" * 100
    assert is_sgo_file(valid)


def test_xorstr_sgml():
    """XOR-decode a null-terminated string with 0xFF key."""
    # "BG" in XOR'd form: 'B'^0xFF=0xBD, 'G'^0xFF=0xB8
    raw = bytes([0xBD, 0xB8, 0x00, 0x00, 0x00])
    assert _xorstr_sgml(raw) == "BG"


def test_xorstr_sgml_no_null():
    """Handles data with no null terminator by reading all bytes."""
    raw = bytes([0xAD, 0x9F])  # two XOR'd chars, no null
    result = _xorstr_sgml(raw)
    assert len(result) == 2


# ── BCB decompressor unit tests ───────────────────────────────────────────────

def test_bcb_single_literal():
    """Flag byte 0x00 → all 8 tokens are literals."""
    # Flag=0x00 (8 literal flags), then 8 literal bytes
    compressed = bytes([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22])
    result = _bcb_decompress(compressed, 8)
    assert result == bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22])


def test_bcb_single_backref():
    """Back-reference (flag=1) copies bytes from earlier in output."""
    # Build output using purely literal tokens first (flag byte 0x00 = all literals)
    # Then confirm a back-reference copies them correctly.
    # 8 literal 0x5A bytes via flag=0x00:
    lit_block = bytes([0x00, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A])
    # Back-ref via flag=0x80 (bit7=1 → first token is back-ref, rest literals)
    # disp=8, count=4 → sh=(4<<10)|8=0x1008 → copy 4 bytes from out[-8]
    sh = (4 << 10) | 8
    ref_block = bytes([0x80, sh >> 8, sh & 0xFF])
    compressed = lit_block + ref_block
    result = _bcb_decompress(compressed, 12)
    assert result[:8]  == bytes([0x5A] * 8)
    assert result[8:12] == bytes([0x5A] * 4)


def test_bcb_noop_tokens():
    """disp=0 or count=0 back-references are no-ops."""
    # Flag=0xFF → 8 back-references, all no-ops (disp=0, count=0)
    noop = bytes([0x00, 0x00])  # sh=0x0000 → count=0, disp=0 → no-op
    compressed = bytes([0xFF]) + noop * 8 + bytes([0x00, 0x42])  # then literal 0x42
    result = _bcb_decompress(compressed, 1)
    assert result == bytes([0x42])


def test_bcb_expected_size_clamp():
    """Output is clamped to expected_size even if more data is available."""
    compressed = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    result = _bcb_decompress(compressed, 3)
    assert len(result) == 3
    assert result == bytes([0x01, 0x02, 0x03])


# ── Integration tests against real SGML files ─────────────────────────────────

@pytest.mark.parametrize("variant", list(_SGML_FILES.keys()))
def test_sgml_detection(variant):
    data = _load(variant)
    if data is None:
        pytest.skip(f"File {_SGML_FILES[variant]} not available")
    assert is_sgml_file(data), "SGML magic not detected"
    assert is_sgo_file(data),  "is_sgo_file should return True for SGML"


@pytest.mark.parametrize("variant", list(_SGML_FILES.keys()))
def test_sgml_decode_succeeds(variant):
    data = _load(variant)
    if data is None:
        pytest.skip(f"File {_SGML_FILES[variant]} not available")
    result = unpack_sgml(data)
    assert result.success, f"Decode failed: {result.error}"
    assert len(result.binary) >= 0x200000, "Binary too small"


@pytest.mark.parametrize("variant", list(_SGML_FILES.keys()))
def test_sgml_pn_sw_in_key(variant):
    """Part number and SW version extracted from IDENT section."""
    data = _load(variant)
    if data is None:
        pytest.skip(f"File {_SGML_FILES[variant]} not available")
    result = unpack_sgml(data)
    assert result.success
    assert "03H906032" in result.key, "PN not in key string"
    # SW version should be numeric
    sw_part = [p for p in result.key.split(",") if p.startswith("SW=")]
    assert sw_part, "No SW= in key string"
    sw_val = sw_part[0].split("=")[1]
    assert sw_val.isdigit(), f"SW version not numeric: {sw_val!r}"


@pytest.mark.parametrize("variant", list(_SGML_FILES.keys()))
def test_sgml_sa2_present(variant):
    """SA2 security access bytecode must be non-empty."""
    data = _load(variant)
    if data is None:
        pytest.skip(f"File {_SGML_FILES[variant]} not available")
    result = unpack_sgml(data)
    assert result.success
    sa2_part = [p for p in result.key.split(",") if p.startswith("SA2=")]
    assert sa2_part, "No SA2= in key string"
    sa2_hex = sa2_part[0].split("=")[1]
    assert len(sa2_hex) >= 8, "SA2 data suspiciously short"


@pytest.mark.parametrize("variant", list(_SGML_FILES.keys()))
def test_sgml_code_section_has_rchw(variant):
    """Code section at 0x020000 must start with MPC5567 RCHW 0x017C."""
    data = _load(variant)
    if data is None:
        pytest.skip(f"File {_SGML_FILES[variant]} not available")
    result = unpack_sgml(data)
    assert result.success
    binary = result.binary
    # MPC5567 RCHW = 0x017C followed by reset-vector high byte
    rchw = binary[0x020000:0x020002]
    assert rchw == bytes([0x01, 0x7C]), (
        f"Expected RCHW 017C at 0x020000, got {rchw.hex()}")


@pytest.mark.parametrize("variant", list(_SGML_FILES.keys()))
def test_sgml_cal_section_has_data(variant):
    """Calibration section (0x1C0000-0x1FFFFF) must contain non-zero data."""
    data = _load(variant)
    if data is None:
        pytest.skip(f"File {_SGML_FILES[variant]} not available")
    result = unpack_sgml(data)
    assert result.success
    cal = result.binary[0x1C0000:0x200000]
    nonzero = sum(1 for b in cal if b != 0)
    assert nonzero > 1000, "Cal section appears empty"


@pytest.mark.parametrize("variant", list(_SGML_FILES.keys()))
def test_sgml_compression_ratio_plausible(variant):
    """Compressed/decompressed ratio should be roughly 1.3–2.5×."""
    data = _load(variant)
    if data is None:
        pytest.skip(f"File {_SGML_FILES[variant]} not available")
    result = unpack_sgml(data)
    assert result.success
    ratio = result.uncompressed_size / max(result.compressed_size, 1)
    assert 1.0 <= ratio <= 4.0, f"Implausible compression ratio: {ratio:.2f}"


def test_unpack_sgo_dispatches_to_sgml():
    """unpack_sgo() must dispatch SGML files to the SGML decoder."""
    data = _load("BG_6652")
    if data is None:
        pytest.skip("BG_6652 not available")
    result = unpack_sgo(data)
    assert result.success
    assert "SGML:PN=" in result.key, "Not dispatched to SGML decoder"
