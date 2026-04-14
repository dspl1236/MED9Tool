"""
MED9Tool command-line interface.

Usage:
    med9tool identify   <file>
    med9tool scan       <file>
    med9tool patch      <file> --preset <name>  [--out <outfile>]
    med9tool patch      <file> --json   <patch.json> [--no-verify] [--out <outfile>]
    med9tool extract    <file.sgo>
    med9tool profile    <directory>
    med9tool presets

Presets:
    speed_remove    Remove top speed limiter (VMAXNB KL)
    rev_raise       Raise rev limit to 8800 RPM
    emissions_full  Zero all CD diagnostic enable params
    immo_off        Brute-force immo bypass (NOP flag gates + poll loops)
    swap_full       All of the above combined
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__


def _load_binary(path: str) -> bytes:
    """Load binary, auto-unpacking SGO if needed."""
    from .sgo_unpack import is_sgo_file, unpack_sgo
    data = Path(path).read_bytes()
    if is_sgo_file(data):
        result = unpack_sgo(data)
        if not result.success:
            print(f"ERROR: SGO unpack failed: {result.error}", file=sys.stderr)
            sys.exit(1)
        print(f"  SGO: {result.compressed_size:,} → {result.uncompressed_size:,} bytes  (key={result.key!r})")
        return result.binary
    return data


def _save(data: bytes, out_path: str):
    Path(out_path).write_bytes(data)
    print(f"  Saved: {out_path}  ({len(data):,} bytes)")


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_identify(args):
    from .identify import identify_rom
    from .checksum import checksum_status
    data = _load_binary(args.file)
    info = identify_rom(data)
    print(f"File:       {args.file}")
    print(f"Size:       {info.file_size:,} bytes")
    print(f"CRC32:      0x{info.crc32:08X}")
    print(f"Variant:    {info.variant.name if info.variant else 'unknown'}")
    print(f"VAG PN:     {info.vag_part_number or 'not found'}")
    print(f"RTOS:       {info.rtos_version or 'not found'}")
    print(f"Cal area:   0x{info.cal_start:06X}–0x{info.cal_end:06X}")
    print(f"Checksum:   {checksum_status(data)}")
    return 0


def cmd_scan(args):
    from .scanner import find_speed_limiter, find_rev_limiter, annotate_hits
    data = _load_binary(args.file)
    spd = annotate_hits(find_speed_limiter(data), "speed_limiter")
    rev = annotate_hits(find_rev_limiter(data),   "rev_limiter")
    print(f"\nSpeed limiter hits ({len(spd)}):")
    for h in spd[:5]:
        print(f"  0x{h.offset:06X}  {h.value:7.1f} km/h  [{h.confidence}]  {h.notes}")
    print(f"\nRev limiter hits ({len(rev)}):")
    for h in rev[:5]:
        print(f"  0x{h.offset:06X}  {h.value:7.0f} RPM   [{h.confidence}]  {h.notes}")
    return 0


def cmd_patch(args):
    from .presets import apply_preset
    from .patch_format import apply_patch_file, PatchError

    data = _load_binary(args.file)
    stem = Path(args.file).stem

    if args.json:
        # Apply EliasTuning-format JSON patch file
        try:
            patched = apply_patch_file(data, args.json, verify=not args.no_verify)
        except PatchError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        changed = sum(a != b for a, b in zip(data, patched))
        print(f"  JSON patch applied: {changed} bytes changed")
        out = args.out or f"{stem}_patched.bin"
        _save(patched, out)
        return 0

    if not args.preset:
        print("ERROR: specify --preset or --json", file=sys.stderr)
        return 1

    try:
        patched, result = apply_preset(data, args.preset)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print(f"\nPreset: {result.preset_name}  ({result.bytes_changed} bytes changed)")
    for step in result.steps:
        print(f"  ✓ {step}")
    for warn in result.warnings:
        print(f"  ⚠ {warn}")

    out = args.out or f"{stem}_{result.preset_name}.bin"
    _save(patched, out)
    return 0


def cmd_extract(args):
    from .sgo_unpack import unpack_sgo
    data = Path(args.file).read_bytes()
    result = unpack_sgo(data)
    if not result.success:
        print(f"ERROR: {result.error}", file=sys.stderr)
        return 1
    out = args.out or (Path(args.file).stem + ".bin")
    Path(out).write_bytes(result.binary)
    print(f"  {result.compressed_size:,} → {result.uncompressed_size:,} bytes  key={result.key!r}")
    print(f"  Sections: {len(result.sections)}")
    for s in result.sections:
        print(f"    S{s.index}: 0x{s.base_address:06X} ({len(s.data):,} bytes)")
    _save(result.binary, out)
    return 0


def cmd_profile(args):
    from .identify import identify_rom
    from .scanner import find_speed_limiter, find_rev_limiter, annotate_hits
    from .sgo_unpack import is_sgo_file, unpack_sgo
    from .immo_patches import count_immo_patches

    d = Path(args.directory)
    files = sorted(d.glob("*.sgo")) + sorted(d.glob("*.bin"))

    hdr = f"{'File':38s} {'PN':>15s} {'kph':>6s} {'rpm':>6s} {'immo':>5s}"
    print(hdr)
    print("-" * len(hdr))

    for f in files:
        try:
            data = f.read_bytes()
            if is_sgo_file(data):
                r = unpack_sgo(data)
                if not r.success:
                    continue
                data = r.binary
            if len(data) < 0x10000:
                    continue
            info   = identify_rom(data)
            spd    = annotate_hits(find_speed_limiter(data), "speed")
            rev    = annotate_hits(find_rev_limiter(data),   "rev")
            immo   = count_immo_patches(data)
            pn     = info.vag_part_number or "?"
            spd_s  = f"{spd[0].value:.0f}" if spd else "—"
            rev_s  = f"{rev[0].value:.0f}" if rev else "—"
            print(f"{f.name:38s} {pn:>15s} {spd_s:>6s} {rev_s:>6s} {immo['total']:>5d}")
        except Exception as e:
            print(f"{f.name:38s} ERROR: {e}")
    return 0


def cmd_presets(_args):
    from .presets import list_presets
    print("Available presets:")
    for name, desc in list_presets().items():
        print(f"  {name:20s}  {desc}")
    return 0


def cmd_signatures(args):
    from .signatures import Signatures
    data = _load_binary(args.file)
    s = Signatures(data)
    print(f"Signatures for: {args.file}")
    for fn_name, label in [
        ("find_free_flash",   "Free flash (code cave)"),
        ("find_bfgren_var",   "BFGREN cruise flag"),
        ("find_ldrxn",        "LDRXN load table"),
        ("find_kwp_table",    "KWP dispatch table"),
        ("find_cd_block",     "CD diagnostic params"),
    ]:
        try:
            r = getattr(s, fn_name)()
            if isinstance(r, dict):
                for k, v in r.items():
                    print(f"  {k:25s}  phys=0x{v.physical:06X}  virt=0x{v.virtual:08X}  {v.note}")
            else:
                print(f"  {label:25s}  phys=0x{r.physical:06X}  virt=0x{r.virtual:08X}  {r.note}")
        except Exception as e:
            print(f"  {label:25s}  NOT FOUND: {e}")
    return 0


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        prog="med9tool",
        description=f"MED9Tool v{__version__} — Bosch MED9.x ECU editor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", metavar="command")

    # identify
    s = sub.add_parser("identify", help="Identify and summarise a MED9 binary")
    s.add_argument("file")

    # scan
    s = sub.add_parser("scan", help="Scan for speed/rev limiter values")
    s.add_argument("file")

    # patch
    s = sub.add_parser("patch", help="Apply a preset or JSON patch")
    s.add_argument("file")
    s.add_argument("--preset", choices=["speed_remove","rev_raise","emissions_full",
                                        "immo_off","swap_full"])
    s.add_argument("--json",   help="EliasTuning-format JSON patch file")
    s.add_argument("--no-verify", action="store_true",
                   help="Skip value_old verification (JSON patches)")
    s.add_argument("--out",  "-o", help="Output filename")

    # extract
    s = sub.add_parser("extract", help="Extract binary from SGO file")
    s.add_argument("file")
    s.add_argument("--out", "-o")

    # profile
    s = sub.add_parser("profile", help="Profile all files in a directory")
    s.add_argument("directory")

    # presets
    sub.add_parser("presets", help="List available presets")

    # signatures
    s = sub.add_parser("signatures", help="Find calibration table addresses")
    s.add_argument("file")

    args = p.parse_args()
    if not args.command:
        p.print_help()
        return 0

    cmds = {
        "identify":   cmd_identify,
        "scan":       cmd_scan,
        "patch":      cmd_patch,
        "extract":    cmd_extract,
        "profile":    cmd_profile,
        "presets":    cmd_presets,
        "signatures": cmd_signatures,
    }
    return cmds[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
