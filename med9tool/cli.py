"""
MED9Tool command-line interface.

Usage:
    med9tool identify <file>        Identify a MED9 ROM
    med9tool scan <file>            Scan for calibration data
    med9tool patch <file> <preset>  Apply a preset patch
    med9tool extract-sgo <file>     Extract binary from SGO
    med9tool profile <directory>    Profile all files in directory
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__


def cmd_identify(args):
    """Identify a MED9 binary."""
    from .identify import identify_rom
    from .sgo_unpack import is_sgo_file, unpack_sgo

    data = Path(args.file).read_bytes()
    if is_sgo_file(data):
        result = unpack_sgo(data)
        if not result.success:
            print(f"SGO unpack failed: {result.error}")
            return 1
        data = result.binary
        print(f"SGO: {result.compressed_size} → {result.uncompressed_size} bytes")

    info = identify_rom(data)
    print(f"File:     {args.file}")
    print(f"Size:     {info.file_size:,} bytes ({info.file_size // 1024} KB)")
    print(f"CRC32:    0x{info.crc32:08X}")
    print(f"Variant:  {info.variant.name if info.variant else 'unknown'}")
    print(f"VAG PN:   {info.vag_part_number or 'not found'}")
    print(f"RTOS:     {info.rtos_version or 'not found'}")
    print(f"Cal area: 0x{info.cal_start:06X}-0x{info.cal_end:06X}")
    print(f"Endian:   {info.byte_order}")
    return 0


def cmd_scan(args):
    """Scan binary for calibration data."""
    from .scanner import scan_binary
    from .sgo_unpack import is_sgo_file, unpack_sgo

    data = Path(args.file).read_bytes()
    if is_sgo_file(data):
        data = unpack_sgo(data).binary

    results = scan_binary(data)
    for category, hits in results.items():
        print(f"\n{category}: {len(hits)} hits")
        for h in hits[:10]:
            print(f"  0x{h.offset:06X}: {h.value:8.1f}  [{h.confidence}]  {h.notes}")
    return 0


def cmd_patch(args):
    """Apply a preset patch."""
    from .patches import PRESETS
    from .sgo_unpack import is_sgo_file, unpack_sgo

    if args.preset not in PRESETS:
        print(f"Unknown preset: {args.preset}")
        print(f"Available: {', '.join(PRESETS.keys())}")
        return 1

    data = Path(args.file).read_bytes()
    was_sgo = is_sgo_file(data)
    if was_sgo:
        data = unpack_sgo(data).binary

    buf = bytearray(data)
    preset = PRESETS[args.preset]
    result = preset["apply"](buf)

    print(f"Preset: {preset['name']}")
    print(f"Applied: {result.applied}/{result.total}")
    for p in result.patches:
        icon = "✓" if p.success else "✗"
        print(f"  {icon} {p.name}: {p.old_value} → {p.new_value}  {p.notes}")

    if result.applied > 0:
        out_path = Path(args.file).stem + "_patched.bin"
        Path(out_path).write_bytes(bytes(buf))
        print(f"\nSaved: {out_path}")

    return 0


def cmd_extract_sgo(args):
    """Extract binary from SGO file."""
    from .sgo_unpack import unpack_sgo

    data = Path(args.file).read_bytes()
    result = unpack_sgo(data)
    if not result.success:
        print(f"Failed: {result.error}")
        return 1

    out_path = Path(args.file).stem + ".bin"
    Path(out_path).write_bytes(result.binary)
    print(f"Extracted: {result.compressed_size} → {result.uncompressed_size} bytes")
    print(f"Saved: {out_path}")
    return 0


def cmd_profile(args):
    """Profile all files in a directory."""
    from .identify import identify_rom
    from .scanner import find_speed_limiter
    from .sgo_unpack import is_sgo_file, unpack_sgo

    d = Path(args.directory)
    files = sorted(list(d.glob("*.sgo")) + list(d.glob("*.bin")))

    print(f"{'File':40s} {'PN':>15s} {'Variant':>8s} {'Size':>7s} {'Speed':>8s}")
    print("-" * 85)

    for f in files:
        try:
            data = f.read_bytes()
            if is_sgo_file(data):
                data = unpack_sgo(data).binary

            if len(data) < 0x10000:
                continue

            info = identify_rom(data)
            spd_hits = find_speed_limiter(data)
            spd = f"{spd_hits[0].value:.0f}" if spd_hits else "-"
            var = info.variant.name if info.variant else "?"

            print(f"{f.name:40s} {info.vag_part_number:>15s} {var:>8s} "
                  f"{len(data) // 1024:6d}K {spd:>8s}")
        except Exception as e:
            print(f"{f.name:40s} ERROR: {e}")

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="med9tool",
        description=f"MED9Tool v{__version__} — MED9.1/MED9.5 ECU editor",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_id = sub.add_parser("identify", help="Identify a MED9 ROM")
    p_id.add_argument("file")

    p_scan = sub.add_parser("scan", help="Scan for calibration data")
    p_scan.add_argument("file")

    p_patch = sub.add_parser("patch", help="Apply a preset patch")
    p_patch.add_argument("file")
    p_patch.add_argument("preset", choices=["speed_remove", "rev_raise"])

    p_ext = sub.add_parser("extract-sgo", help="Extract binary from SGO")
    p_ext.add_argument("file")

    p_prof = sub.add_parser("profile", help="Profile directory of files")
    p_prof.add_argument("directory")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0

    cmds = {
        "identify": cmd_identify,
        "scan": cmd_scan,
        "patch": cmd_patch,
        "extract-sgo": cmd_extract_sgo,
        "profile": cmd_profile,
    }
    return cmds[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
