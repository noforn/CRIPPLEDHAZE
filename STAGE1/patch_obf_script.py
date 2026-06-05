#!/usr/bin/env python3
"""Replace the payload script block in index-obf.hta with obf.js."""

import argparse
from pathlib import Path

DIR = Path(__file__).resolve().parent
DEFAULT_HTA = DIR / "index-obf.hta"
DEFAULT_JS = DIR / "obf.js"
ENC_PLACEHOLDER = "B64_ENC_DATA"
KEY_PLACEHOLDER = "KEY_B64_DATA"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def replace_last_script_block(hta: str, js: str) -> str:
    start_marker = "<script>"
    end_marker = "</script>"

    start = hta.rfind(start_marker)
    if start == -1:
        raise ValueError("could not find a <script> block in index-obf.hta")

    end = hta.find(end_marker, start)
    if end == -1:
        raise ValueError("could not find matching </script> for the last <script> block")

    line_start = hta.rfind("\n", 0, start) + 1
    indent = hta[line_start:start]
    script_open = hta[start : start + len(start_marker)]
    script_close_end = end + len(end_marker)

    js = js.strip()
    replacement = f"{indent}{script_open}\n{indent}  {js}\n{indent}{end_marker}"

    return hta[:line_start] + replacement + hta[script_close_end:]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replace the last <script> block in index-obf.hta with obf.js.",
    )
    parser.add_argument(
        "--hta",
        type=Path,
        default=DEFAULT_HTA,
        help="HTA file to patch; defaults to index-obf.hta",
    )
    parser.add_argument(
        "--js",
        type=Path,
        default=DEFAULT_JS,
        help="Obfuscated JavaScript source; defaults to obf.js",
    )
    args = parser.parse_args()

    if not args.hta.exists():
        print(f"[!] File not found: {args.hta}")
        return 1
    if not args.js.exists():
        print(f"[!] File not found: {args.js}")
        return 1

    js = read_text(args.js)
    missing = [p for p in (ENC_PLACEHOLDER, KEY_PLACEHOLDER) if p not in js]
    if missing:
        print(f"[!] {args.js.name} is missing placeholder(s): {', '.join(missing)}")
        print("[!] Re-obfuscate from script.js before running img2bytes.py -O.")
        return 1

    hta = read_text(args.hta)
    try:
        updated = replace_last_script_block(hta, js)
    except ValueError as exc:
        print(f"[!] {exc}")
        return 1

    args.hta.write_text(updated, encoding="utf-8", newline="")
    print(f"[+] Replaced payload script in {args.hta.name} with {args.js.name}")
    print("[*] Next: python3 img2bytes.py -O")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
