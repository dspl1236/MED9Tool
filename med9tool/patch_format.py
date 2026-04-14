"""
JSON patch format for MED9.x binaries.

Compatible with EliasTuning/MED9-Patches patch format:
  {
    "name":  "Patch Name",
    "diffs": [
      {
        "comment":   "optional description",
        "addr":      "0x4BA621",       ← VIRTUAL address (ECU runtime)
        "value_old": "162CDC",         ← expected bytes (hex string, no spaces)
        "value_new": "1E8710"          ← replacement bytes
      }, ...
    ]
  }

addr is virtual (physical = virtual - 0x400000).
value_old is verified before patching — mismatch raises PatchError.
"""

import json
from dataclasses import dataclass
from pathlib import Path

VIRT_BASE = 0x400000


class PatchError(Exception):
    pass


@dataclass
class Diff:
    comment: str
    virt_addr: int
    phys_addr: int
    old_bytes: bytes
    new_bytes: bytes


@dataclass
class Patch:
    name: str
    diffs: list[Diff]


def load_patch(path: str | Path) -> Patch:
    """Load a JSON patch file."""
    with open(path) as f:
        raw = json.load(f)

    # Handle both top-level dict and {"patches": [...]} wrapper
    if "patches" in raw:
        raw = raw["patches"][0]

    diffs = []
    for d in raw.get("diffs", []):
        virt = int(d["addr"], 16)
        phys = virt - VIRT_BASE
        if phys < 0:
            raise PatchError(f"Virtual address 0x{virt:08X} maps to negative physical offset")
        old_b = bytes.fromhex(d.get("value_old", ""))
        new_b = bytes.fromhex(d["value_new"])
        diffs.append(Diff(
            comment=d.get("comment", ""),
            virt_addr=virt,
            phys_addr=phys,
            old_bytes=old_b,
            new_bytes=new_b,
        ))

    return Patch(name=raw.get("name", "unnamed"), diffs=diffs)


def apply_patch(data: bytes, patch: Patch,
                verify: bool = True) -> bytes:
    """
    Apply a Patch to a binary.

    Args:
        data:   Flat binary bytes.
        patch:  Parsed Patch object.
        verify: If True, raise PatchError on value_old mismatch.

    Returns:
        Patched binary bytes.
    """
    result = bytearray(data)
    for diff in patch.diffs:
        off = diff.phys_addr
        sz_old = len(diff.old_bytes)
        sz_new = len(diff.new_bytes)

        if verify and sz_old > 0:
            actual = bytes(result[off:off + sz_old])
            if actual != diff.old_bytes:
                raise PatchError(
                    f"Mismatch at 0x{diff.virt_addr:08X} "
                    f"(phys 0x{off:06X}): "
                    f"expected {diff.old_bytes.hex()} "
                    f"got {actual.hex()}"
                    + (f" [{diff.comment}]" if diff.comment else "")
                )

        result[off:off + sz_new] = diff.new_bytes

    return bytes(result)


def apply_patch_file(data: bytes, path: str | Path,
                     verify: bool = True) -> bytes:
    """Convenience: load and apply in one call."""
    return apply_patch(data, load_patch(path), verify=verify)


def dump_patch(patch: Patch) -> str:
    """Serialize a Patch back to JSON string."""
    diffs = []
    for d in patch.diffs:
        entry: dict = {
            "addr": f"0x{d.virt_addr:08X}",
            "value_old": d.old_bytes.hex().upper(),
            "value_new": d.new_bytes.hex().upper(),
        }
        if d.comment:
            entry["comment"] = d.comment
        diffs.append(entry)
    return json.dumps({"name": patch.name, "diffs": diffs}, indent=2)
