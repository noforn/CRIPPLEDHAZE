#!/usr/bin/env python3
"""Patch IMAGE_FILE_HEADER.TimeDateStamp (PE compile time).

MinGW/Rust ignore SOURCE_DATE_EPOCH for PE headers; patch after link instead.
"""
from __future__ import annotations

import argparse
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path


def patch_pe_timestamp(path: Path, timestamp: int) -> int:
    data = bytearray(path.read_bytes())
    if len(data) < 0x40 or data[0:2] != b"MZ":
        raise ValueError(f"{path}: not a PE image")

    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 12 > len(data) or data[pe_off : pe_off + 4] != b"PE\0\0":
        raise ValueError(f"{path}: invalid PE signature")

    ts_off = pe_off + 8
    old_ts = struct.unpack_from("<I", data, ts_off)[0]
    struct.pack_into("<I", data, ts_off, timestamp & 0xFFFFFFFF)
    path.write_bytes(data)
    return old_ts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pe", type=Path, help="PE file to patch in place")
    parser.add_argument(
        "--timestamp",
        type=lambda s: int(s, 0),
        default=None,
        help="Unix TimeDateStamp (decimal or 0x hex). Default: PE_TIMESTAMP env or 0.",
    )
    args = parser.parse_args()

    if not args.pe.is_file():
        print(f"error: not found: {args.pe}", file=sys.stderr)
        return 1

    ts = args.timestamp
    if ts is None:
        import os

        raw = os.environ.get("PE_TIMESTAMP", "0")
        ts = int(raw, 0)

    try:
        old = patch_pe_timestamp(args.pe, ts)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    when = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"{args.pe}: TimeDateStamp {old} -> {ts} ({when})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
