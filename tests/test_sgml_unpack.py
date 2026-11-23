"""
Tests for SGML Object File v2 unpacking (med9tool/sgo_unpack.py).

Helper and decoder-unit tests use synthetic vectors (no firmware needed). The
integration tests run against real 2024 VW/Audi MED9.1 Cayenne (03H906032) SGO
files when present, and skip otherwise.
"""
from pathlib import Path

import pytest

from med9tool.sgo_unpack import (
    is_sgml_file, is_sgo_file, unpack_sgml, unpack_sgo,
    record_decode, _record_decode_auto, _xorstr_sgml,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

UPLOAD_DIR = Path("/mnt/user-data/uploads")

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


# ── Container / helper unit tests ─────────────────────────────────────────────

def test_is_sgml_file_magic():
    valid = b"SGML Object File\x00" + b"\x02\x00\x00\x00" + b"\x00" * 100
    assert is_sgml_file(valid)


def test_is_sgml_file_rejects_rolling_xor():
    rolling = b"\x00\x02\x00\x00\x00\x20\x00\x00" + b"\x00" * 100
    assert not is_sgml_file(rolling)


def test_is_sgo_file_detects_sgml():
    valid = b"SGML Object File\x00" + b"\x02\x00\x00\x00" + b"\x00" * 100
    assert is_sgo_file(valid)


def test_xorstr_sgml():
    # "BG" XOR'd with 0xFF: 'B'^0xFF=0xBD, 'G'^0xFF=0xB8
    raw = bytes([0xBD, 0xB8, 0x00, 0x00, 0x00])
    assert _xorstr_sgml(raw) == "BG"


def test_xorstr_sgml_no_null():
    raw = bytes([0xAD, 0x9F])  # two XOR'd chars, no null terminator
    assert len(_xorstr_sgml(raw)) == 2


# ── Keyed record-stream decoder unit tests ────────────────────────────────────

def _enc_record(payload: bytes, key: bytes) -> bytes:
    """Build a raw fmt=0x11 body: XOR0xFF(1A 01 + XOR(key, BE16 literal records))."""
    rec = bytearray()
    i = 0
    while i < len(payload):
        chunk = payload[i:i + 0x3FFF]
        rec += len(chunk).to_bytes(2, "big") + chunk          # literal run
        i += len(chunk)
    rec += b"\xC0\x00" + b"\x00\x00\x00"                        # terminal + 24-bit field
    mask = bytes(key[j % len(key)] for j in range(len(rec)))
    wire = b"\x1A\x01" + bytes(a ^ b for a, b in zip(rec, mask))
    return bytes(c ^ 0xFF for c in wire)


def test_record_roundtrip_literal():
    payload = bytes(range(256)) * 20
    assert record_decode(_enc_record(payload, b"CodeRobert"), b"CodeRobert") == payload


def test_record_rle():
    key = b"CodeRobert"
    rec = (0x4000 | 5).to_bytes(2, "big") + b"\xAB" + b"\xC0\x00" + b"\x00\x00\x00"
    mask = bytes(key[j % len(key)] for j in range(len(rec)))
    raw = bytes(c ^ 0xFF for c in (b"\x1A\x01" + bytes(a ^ b for a, b in zip(rec, mask))))
    assert record_decode(raw, key) == b"\xAB" * 5


def test_record_missing_sync_raises():
    with pytest.raises(ValueError, match="sync"):
        record_decode(bytes(64), b"CodeRobert")


def test_record_auto_selects_key():
    payload = bytes((i * 7 + 3) & 0xFF for i in range(4096))
    assert _record_decode_auto(_enc_record(payload, b"CodeRobert"), len(payload)) == payload


def test_record_auto_size_mismatch_returns_none():
    payload = bytes(1000)
    assert _record_decode_auto(_enc_record(payload, b"CodeRobert"), len(payload) + 1) is None


# ── Integration tests against real SGML files (skip if absent) ────────────────

@pytest.mark.parametrize("variant", list(_SGML_FILES.keys()))
def test_sgml_detection(variant):
    data = _load(variant)
    if data is None:
        pytest.skip(f"File {_SGML_FILES[variant]} not available")
    assert is_sgml_file(data)
    assert is_sgo_file(data)


@pytest.mark.parametrize("variant", list(_SGML_FILES.keys()))
def test_sgml_decode_succeeds(variant):
    data = _load(variant)
    if data is None:
        pytest.skip(f"File {_SGML_FILES[variant]} not available")
    result = unpack_sgml(data)
    assert result.success, f"Decode failed: {result.error}"
    assert len(result.binary) >= 0x200000


@pytest.mark.parametrize("variant", list(_SGML_FILES.keys()))
def test_sgml_decoded_has_identity_strings(variant):
    """Decoded firmware must contain real MED9 identity strings — not garbage.

    This is the regression guard for the BCB decoder: a wrong decompressor
    still produces plausible-looking size/RCHW but no real strings.
    """
    data = _load(variant)
    if data is None:
        pytest.skip(f"File {_SGML_FILES[variant]} not available")
    binary = unpack_sgml(data).binary
    assert b"03H906032" in binary, "part number missing — decode produced garbage"
    assert b"MED9" in binary
    assert b"ERCOSEK" in binary


@pytest.mark.parametrize("variant", list(_SGML_FILES.keys()))
def test_sgml_code_section_has_rchw(variant):
    data = _load(variant)
    if data is None:
        pytest.skip(f"File {_SGML_FILES[variant]} not available")
    binary = unpack_sgml(data).binary
    assert binary[0x020000:0x020002] == bytes([0x01, 0x7C]), "RCHW 017C expected at 0x020000"


@pytest.mark.parametrize("variant", list(_SGML_FILES.keys()))
def test_sgml_pn_sw_in_key(variant):
    data = _load(variant)
    if data is None:
        pytest.skip(f"File {_SGML_FILES[variant]} not available")
    result = unpack_sgml(data)
    assert result.success
    assert "03H906032" in result.key
    sw_part = [p for p in result.key.split(",") if p.startswith("SW=")]
    assert sw_part and sw_part[0].split("=")[1].isdigit()


@pytest.mark.parametrize("variant", list(_SGML_FILES.keys()))
def test_sgml_cal_section_has_data(variant):
    data = _load(variant)
    if data is None:
        pytest.skip(f"File {_SGML_FILES[variant]} not available")
    cal = unpack_sgml(data).binary[0x1C0000:0x200000]
    assert sum(1 for b in cal if b not in (0, 0xFF)) > 1000


def test_unpack_sgo_dispatches_to_sgml():
    data = _load("BG_6652")
    if data is None:
        pytest.skip("BG_6652 not available")
    result = unpack_sgo(data)
    assert result.success
    assert "SGML:PN=" in result.key
