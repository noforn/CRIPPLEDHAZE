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

from msal_peek import (
    ONENOTE_CLIENT,
    OWA_CLIENT,
    extract_credentials,
    fmt_expiry,
    pick_onenote_refresh,
    pick_owa_refresh,
)

TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "User.Read openid profile offline_access"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
ORIGIN = "https://outlook.live.com"
ONENOTE_ORIGIN = "https://onenote.cloud.microsoft"

CLIENTS = {
    "owa": {"id": OWA_CLIENT, "origin": ORIGIN, "label": "OWA"},
    "onenote": {"id": ONENOTE_CLIENT, "origin": ONENOTE_ORIGIN, "label": "OneNote"},
}

LIST_SEL = "id,subject,from,receivedDateTime,isRead,hasAttachments"
MSG_SEL = "id,subject,from,toRecipients,receivedDateTime,body,hasAttachments,bodyPreview"
DRIVE_SEL = "id,name,size,lastModifiedDateTime,folder,file,parentReference,@microsoft.graph.downloadUrl"
ONENOTE_BOOK_SEL = "id,displayName,createdDateTime,lastModifiedDateTime"
ONENOTE_PAGE_SEL = "id,title,createdDateTime,lastModifiedDateTime,contentUrl,links"


class _RedirectNoAuth(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return urllib.request.Request(newurl, headers={"User-Agent": UA})


def refresh_token(rt: str, *, client: str = "owa") -> dict[str, Any]:
    cfg = CLIENTS[client]
    body = urllib.parse.urlencode(
        {
            "client_id": cfg["id"],
            "grant_type": "refresh_token",
            "refresh_token": rt,
            "scope": GRAPH_SCOPE,
        }
    ).encode()
    req = urllib.request.Request(TOKEN_URL, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Origin", cfg["origin"])
    req.add_header("Referer", f"{cfg['origin']}/")
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

    def _request(self, url: str, *, accept: str = "application/json") -> urllib.request.Request:
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", accept)
        req.add_header("User-Agent", UA)
        return req

    def get(self, url: str) -> tuple[int, Any]:
        try:
            with urllib.request.urlopen(self._request(url), timeout=60) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode(errors="replace")
            try:
                return exc.code, json.loads(raw)
            except json.JSONDecodeError:
                return exc.code, raw[:500]

    def get_bytes(self, url: str, *, auth: bool = True) -> tuple[int, bytes]:
        req = self._request(url, accept="*/*") if auth else urllib.request.Request(url)
        if not auth:
            req.add_header("User-Agent", UA)
        try:
            opener = urllib.request.build_opener(_RedirectNoAuth) if auth else urllib.request.build_opener()
            with opener.open(req, timeout=120) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

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

    def _drive_children_url(self, *, path: str | None = None, item_id: str | None = None) -> str:
        q = urllib.parse.urlencode(
            {"$top": 200, "$select": DRIVE_SEL, "$orderby": "name"},
            quote_via=urllib.parse.quote,
        )
        if path is not None:
            enc = "/".join(urllib.parse.quote(p) for p in path.strip("/").split("/") if p)
            base = f"{GRAPH}/me/drive/root:/{enc}:/children" if enc else f"{GRAPH}/me/drive/root/children"
        elif item_id:
            enc = urllib.parse.quote(item_id, safe="")
            base = f"{GRAPH}/me/drive/items/{enc}/children"
        else:
            base = f"{GRAPH}/me/drive/root/children"
        return f"{base}?{q}"

    def drive_children(self, top: int = 25, *, path: str | None = None, item_id: str | None = None) -> list[dict]:
        url = self._drive_children_url(path=path, item_id=item_id)
        code, body = self.get(url)
        if code != 200 or not isinstance(body, dict):
            return []
        return (body.get("value") or [])[:top]

    def drive_item(self, item_id: str) -> dict | None:
        enc = urllib.parse.quote(item_id, safe="")
        q = urllib.parse.urlencode({"$select": DRIVE_SEL}, quote_via=urllib.parse.quote)
        code, body = self.get(f"{GRAPH}/me/drive/items/{enc}?{q}")
        return body if code == 200 and isinstance(body, dict) else None

    def drive_download(self, item_id: str) -> tuple[int, bytes]:
        enc = urllib.parse.quote(item_id, safe="")
        return self.get_bytes(f"{GRAPH}/me/drive/items/{enc}/content")

    def _onenote_list(
        self, path: str, top: int, *, orderby: str | None = None, select: str = ONENOTE_PAGE_SEL
    ) -> tuple[int, list[dict]]:
        params: dict[str, str | int] = {"$top": top, "$select": select}
        if orderby:
            params["$orderby"] = orderby
        q = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        code, body = self.get(f"{GRAPH}/me/onenote/{path}?{q}")
        if code != 200 or not isinstance(body, dict):
            return code, []
        return code, (body.get("value") or [])[:top]

    def onenote_ok(self) -> bool:
        code, _ = self._onenote_list("notebooks", 1, select=ONENOTE_BOOK_SEL)
        return code == 200

    def onenote_notebooks(self, top: int = 25) -> list[dict]:
        _, items = self._onenote_list(
            "notebooks", top, orderby="lastModifiedDateTime desc", select=ONENOTE_BOOK_SEL
        )
        return items

    def onenote_all_sections(self, top: int = 50) -> list[dict]:
        _, items = self._onenote_list(
            "sections", top, orderby="lastModifiedDateTime desc", select=ONENOTE_BOOK_SEL
        )
        return items

    def onenote_sections(self, notebook_id: str, top: int = 50) -> list[dict]:
        enc = urllib.parse.quote(notebook_id, safe="")
        _, items = self._onenote_list(
            f"notebooks/{enc}/sections", top, orderby="lastModifiedDateTime desc", select=ONENOTE_BOOK_SEL
        )
        return items

    def onenote_pages(self, top: int = 25, *, section_id: str | None = None) -> tuple[int, list[dict]]:
        if section_id:
            enc = urllib.parse.quote(section_id, safe="")
            path = f"sections/{enc}/pages"
        else:
            path = "pages"
        return self._onenote_list(path, top, orderby="lastModifiedDateTime desc", select=ONENOTE_PAGE_SEL)

    def onenote_page(self, page_id: str) -> dict | None:
        enc = urllib.parse.quote(page_id, safe="")
        q = urllib.parse.urlencode({"$select": ONENOTE_PAGE_SEL}, quote_via=urllib.parse.quote)
        code, body = self.get(f"{GRAPH}/me/onenote/pages/{enc}?{q}")
        return body if code == 200 and isinstance(body, dict) else None

    def onenote_page_content(self, page_id: str) -> tuple[int, str]:
        enc = urllib.parse.quote(page_id, safe="")
        code, data = self.get_bytes(f"{GRAPH}/me/onenote/pages/{enc}/content")
        if code != 200:
            detail = data[:200].decode(errors="replace") if isinstance(data, bytes) else str(data)[:200]
            return code, detail
        return code, data.decode(errors="replace")

    def probe(self) -> tuple[dict | None, bool, bool, bool]:
        me = self.me()
        inbox = bool(self.messages(1))
        drive = bool(self.drive_children(1))
        onenote = self.onenote_ok()
        return me, inbox, drive, onenote


def _pick_refresh(creds: list[dict], client: str) -> dict | None:
    if client == "onenote":
        return pick_onenote_refresh(creds)
    return pick_owa_refresh(creds)


def resolve_refresh_token(args: argparse.Namespace) -> str | None:
    if args.refresh_token:
        return args.refresh_token
    p = Path(args.source)
    if p.is_file() and p.suffix == ".json":
        blob = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(blob, dict) and blob.get("refresh_token"):
            return blob["refresh_token"]
        if isinstance(blob, list):
            return (_pick_refresh(blob, args.client) or {}).get("secret")
    if p.exists():
        creds, _ = extract_credentials(p.resolve())
        row = _pick_refresh(creds, args.client)
        if row:
            print(f"[*] {CLIENTS[args.client]['label']} refresh expires {fmt_expiry(row.get('expiresOn'))}")
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


def fmt_size(n: int | None) -> str:
    if n is None:
        return "?"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def drive_kind(item: dict) -> str:
    return "dir" if item.get("folder") else "file"


def print_drive_list(items: list[dict], *, path: str = "/") -> None:
    print(f"--- drive: {path} ({len(items)}) ---")
    for i, it in enumerate(items):
        print(
            f"  [{i}] {drive_kind(it):4}  {fmt_size(it.get('size')):>8}  "
            f"{(it.get('lastModifiedDateTime') or '?')[:19]}  {it.get('name', '')}"
        )


def print_drive_item(item: dict) -> None:
    parent = (item.get("parentReference") or {}).get("path", "?")
    print(f"name   : {item.get('name', '')}")
    print(f"kind   : {drive_kind(item)}")
    print(f"size   : {fmt_size(item.get('size'))}")
    print(f"modified: {item.get('lastModifiedDateTime', '?')}")
    print(f"path   : {parent}")
    print(f"id     : {item.get('id', '')}")
    if item.get("folder"):
        kids = item["folder"].get("childCount")
        if kids is not None:
            print(f"children: {kids}")


def save_drive_item(g: Graph, item: dict, path: Path) -> int:
    if item.get("folder"):
        raise RuntimeError(f"{item.get('name')} is a folder, not a file")
    path.parent.mkdir(parents=True, exist_ok=True)
    ext = path.suffix.lower()
    if ext == ".json":
        path.write_text(json.dumps(item, indent=2, ensure_ascii=False), encoding="utf-8")
        return 0
    code, data = g.drive_download(item["id"])
    if code != 200:
        detail = data[:200].decode(errors="replace") if isinstance(data, bytes) else str(data)[:200]
        raise RuntimeError(f"download failed ({code}): {detail}")
    path.write_bytes(data)
    return len(data)


def onenote_label(item: dict) -> str:
    return (item.get("displayName") or item.get("title") or "?")[:80]


def print_onenote_list(items: list[dict], *, label: str) -> None:
    print(f"--- onenote: {label} ({len(items)}) ---")
    for i, it in enumerate(items):
        print(
            f"  [{i}] {(it.get('lastModifiedDateTime') or '?')[:19]}  "
            f"{onenote_label(it)}"
        )
        if it.get("id"):
            print(f"       id: {it['id']}")


def print_onenote_pages_hint(code: int) -> None:
    if code == 403:
        print(
            "[-] onenote pages: 403 — token has Notes.Create but listing/reading pages "
            "needs Notes.Read (see https://learn.microsoft.com/en-us/graph/api/onenote-list-pages)"
        )
        print(
            "    fallback: --drive-path 'Documents/<notebook>' for synced .one files "
            "(e.g. Documents/List)"
        )


def print_onenote_page(page: dict, content: str, *, full: bool = False) -> None:
    print(f"title  : {page.get('title', '')}")
    print(f"created: {page.get('createdDateTime', '?')}")
    print(f"updated: {page.get('lastModifiedDateTime', '?')}")
    print(f"id     : {page.get('id', '')}")
    print("---")
    if full:
        print(content or "(empty)")
        return
    print(html_to_text(content) if content.lstrip().startswith("<") else content or "(empty)")


def save_onenote_page(page: dict, content: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    ext = path.suffix.lower()
    if ext == ".json":
        blob = dict(page)
        blob["contentHtml"] = content
        blob["contentText"] = html_to_text(content) if content.lstrip().startswith("<") else content
        path.write_text(json.dumps(blob, indent=2, ensure_ascii=False), encoding="utf-8")
    elif ext in (".html", ".htm"):
        path.write_text(content, encoding="utf-8")
    else:
        text = html_to_text(content) if content.lstrip().startswith("<") else content
        path.write_text(text, encoding="utf-8")


def dump_onenote_pages(g: Graph, outdir: Path, pages: list[dict]) -> int:
    outdir.mkdir(parents=True, exist_ok=True)
    manifest = []
    n = 0
    for page in pages:
        pid = page.get("id")
        if not pid:
            continue
        full = g.onenote_page(pid) or page
        code, content = g.onenote_page_content(pid)
        if code != 200:
            print(f"    skip {onenote_label(full)}: content ({code})")
            continue
        ts = (full.get("lastModifiedDateTime") or "unknown")[:19].replace(":", "-")
        base = f"{ts}_{safe_name(full.get('title') or 'page', 50)}"
        save_onenote_page(full, content, outdir / f"{base}.json")
        save_onenote_page(full, content, outdir / f"{base}.txt")
        save_onenote_page(full, content, outdir / f"{base}.html")
        manifest.append(
            {
                "file": f"{base}.json",
                "id": pid,
                "title": full.get("title"),
                "lastModifiedDateTime": full.get("lastModifiedDateTime"),
            }
        )
        n += 1
        print(f"    {base}")
    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return n


def dump_drive(g: Graph, outdir: Path, items: list[dict], *, path: str) -> int:
    outdir.mkdir(parents=True, exist_ok=True)
    manifest = []
    n = 0
    for it in items:
        if it.get("folder"):
            continue
        iid = it.get("id")
        name = it.get("name") or "file"
        if not iid:
            continue
        dest = outdir / safe_name(name, 120)
        try:
            size = save_drive_item(g, it, dest)
        except RuntimeError as exc:
            print(f"    skip {name}: {exc}")
            continue
        manifest.append(
            {
                "file": dest.name,
                "id": iid,
                "name": name,
                "size": it.get("size"),
                "lastModifiedDateTime": it.get("lastModifiedDateTime"),
                "path": path,
            }
        )
        n += 1
        print(f"    {dest.name} ({fmt_size(size)})")
    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return n


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
    ap = argparse.ArgumentParser(description="OWA refresh token -> Graph mail / OneDrive / OneNote")
    ap.add_argument("source", nargs="?", default=str(Path(__file__).resolve().parent))
    ap.add_argument("--json", help="msal_peek export path")
    ap.add_argument("--refresh-token")
    ap.add_argument(
        "--client",
        choices=("owa", "onenote"),
        default="owa",
        help="token client: owa=mail/drive (default), onenote=OneNote Graph",
    )
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
    ap.add_argument("--drive", type=int, metavar="N", help="list N items in OneDrive folder")
    ap.add_argument("--drive-path", metavar="PATH", default="", help="OneDrive path under root (e.g. Documents)")
    ap.add_argument("--file", metavar="ID", help="OneDrive item metadata by Graph id")
    ap.add_argument("--drive-index", type=int, metavar="N", help="show/download OneDrive item by list index")
    ap.add_argument("--save-file", metavar="PATH", help="save OneDrive file or item JSON (.json)")
    ap.add_argument("--drive-dump", metavar="DIR", help="download files from OneDrive folder")
    ap.add_argument("--notebooks", type=int, metavar="N", help="list N OneNote notebooks")
    ap.add_argument("--notebook", metavar="ID", help="list sections in a notebook (Graph id, not index)")
    ap.add_argument("--notebook-index", type=int, metavar="N", help="list sections in notebook [N] from --notebooks")
    ap.add_argument("--sections", type=int, metavar="N", help="list N OneNote sections (all notebooks)")
    ap.add_argument("--onenote-pages", type=int, metavar="N", help="list N recent OneNote pages")
    ap.add_argument("--onenote-section", metavar="ID", help="list pages in a section (Graph id)")
    ap.add_argument("--section-index", type=int, metavar="N", help="use section [N] from last notebook/sections list")
    ap.add_argument("--onenote-page", metavar="ID", help="read OneNote page by Graph id")
    ap.add_argument("--onenote-index", type=int, metavar="N", help="read page from last --onenote-pages list")
    ap.add_argument("--save-onenote", metavar="PATH", help="save OneNote page (.json, .html, .txt)")
    ap.add_argument("--onenote-dump", metavar="DIR", help="exfil OneNote pages as json/html/txt")
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
            payload = refresh_token(rt, client=args.client)
        except RuntimeError as exc:
            print(f"[-] refresh failed: {exc}")
            return 1
        access = payload["access_token"]
        print(f"[*] Refresh token: live ({CLIENTS[args.client]['label']})")
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
    me, inbox_ok, drive_ok, onenote_ok = g.probe()
    if not me:
        print("[-] graph: dead")
        return 1

    upn = me.get("userPrincipalName", "?")
    print(f"\n[+] MS Graph: live")
    print(f"    Graph mail for {upn}")
    print(
        f"    /me=200 inbox={200 if inbox_ok else 'err'} "
        f"drive={200 if drive_ok else 'err'} onenote={200 if onenote_ok else 'err'}"
    )
    if not onenote_ok and args.client != "onenote" and any(
        (
            args.notebooks,
            args.notebook,
            args.notebook_index is not None,
            args.sections,
            args.onenote_pages,
            args.onenote_section,
            args.section_index is not None,
            args.onenote_page,
            args.onenote_index is not None,
            args.onenote_dump,
        )
    ):
        print("[-] onenote: token lacks Notes.Read (AADSTS90023 if requested on refresh)")
        print("    fallback: --drive-path 'Documents/OneNote Notebooks' for synced .one files")
        return 1

    drive_path = args.drive_path.strip() or None
    drive_label = f"/{drive_path}" if drive_path else "/"

    need_msgs = args.inbox or args.msg_index is not None or args.dump
    list_n = max(
        args.inbox or 0,
        (args.msg_index + 1) if args.msg_index is not None else 0,
        args.top if args.dump else 0,
    )
    msgs = g.messages(list_n) if need_msgs else []

    need_drive = args.drive or args.drive_index is not None or args.drive_dump
    drive_n = max(
        args.drive or 0,
        (args.drive_index + 1) if args.drive_index is not None else 0,
        args.top if args.drive_dump else 0,
    )
    drive_items = g.drive_children(drive_n, path=drive_path) if need_drive else []

    need_onenote = (
        args.notebooks
        or args.notebook
        or args.notebook_index is not None
        or args.sections
        or args.onenote_pages
        or args.onenote_section
        or args.section_index is not None
        or args.onenote_page
        or args.onenote_index is not None
        or args.onenote_dump
    )
    onenote_n = max(
        args.notebooks or 0,
        args.sections or 0,
        args.onenote_pages or 0,
        args.top if args.onenote_dump else 0,
        (args.onenote_index + 1) if args.onenote_index is not None else 0,
        (args.notebook_index + 1) if args.notebook_index is not None else 0,
        (args.section_index + 1) if args.section_index is not None else 0,
    )
    onenote_items: list[dict] = []
    onenote_list_label = ""
    onenote_pages_code = 200
    notebook_id = args.notebook
    notebook_name = ""
    section_id = args.onenote_section
    section_name = ""
    if need_onenote and onenote_ok:
        notebooks = g.onenote_notebooks(onenote_n or 25) if (
            args.notebooks or args.notebook_index is not None
        ) else []
        if args.notebook_index is not None:
            if args.notebook_index < 0 or args.notebook_index >= len(notebooks):
                print(
                    f"[-] notebook-index {args.notebook_index} out of range "
                    f"(have {len(notebooks)}; run --notebooks first)"
                )
                return 1
            notebook_id = notebooks[args.notebook_index]["id"]
            notebook_name = onenote_label(notebooks[args.notebook_index])
        sections: list[dict] = []
        if notebook_id:
            sections = g.onenote_sections(notebook_id, onenote_n or 50)
        elif args.sections:
            sections = g.onenote_all_sections(args.sections)
        if args.section_index is not None:
            if not sections:
                print("[-] section-index needs --notebook/--notebook-index or --sections first")
                return 1
            if args.section_index < 0 or args.section_index >= len(sections):
                print(f"[-] section-index {args.section_index} out of range (have {len(sections)})")
                return 1
            section_id = sections[args.section_index]["id"]
            section_name = onenote_label(sections[args.section_index])
        elif section_id and sections:
            for sec in sections:
                if sec.get("id") == section_id:
                    section_name = onenote_label(sec)
                    break
        if section_id:
            onenote_pages_code, onenote_items = g.onenote_pages(onenote_n or 50, section_id=section_id)
            onenote_list_label = f"section:{section_name or section_id[:24]}"
        elif notebook_id:
            onenote_items = sections or g.onenote_sections(notebook_id, onenote_n or 50)
            onenote_list_label = f"notebook:{notebook_name or notebook_id[:24]}"
        elif args.sections:
            onenote_items = sections or g.onenote_all_sections(args.sections)
            onenote_list_label = "sections"
        elif args.notebooks:
            onenote_items = notebooks or g.onenote_notebooks(args.notebooks)
            onenote_list_label = "notebooks"
        else:
            onenote_pages_code, onenote_items = g.onenote_pages(onenote_n or args.top)
            onenote_list_label = "recent pages"

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

    def show_drive_item(item: dict | None) -> int:
        if not item:
            return 1
        if args.save_file:
            try:
                size = save_drive_item(g, item, Path(args.save_file))
            except RuntimeError as exc:
                print(f"[-] {exc}")
                return 1
            if item.get("folder"):
                print(f"    saved metadata -> {args.save_file}")
            else:
                print(f"    saved {fmt_size(size)} -> {args.save_file}")
        print()
        print_drive_item(item)
        return 0

    if args.file:
        if show_drive_item(g.drive_item(args.file)):
            print(f"[-] drive item not found: {args.file[:40]}...")
            return 1

    if args.drive_index is not None:
        if args.drive_index < 0 or args.drive_index >= len(drive_items):
            print(f"[-] drive-index {args.drive_index} out of range (have {len(drive_items)})")
            return 1
        item = drive_items[args.drive_index]
        if not args.save_file and not item.get("folder"):
            item = g.drive_item(item["id"]) or item
        if show_drive_item(item):
            return 1

    if args.drive_dump:
        to_dump = drive_items if drive_items else g.drive_children(args.top, path=drive_path)
        print(f"\n--- drive-dump {drive_label} ---")
        n = dump_drive(g, Path(args.drive_dump), to_dump[: args.top], path=drive_label)
        print(f"    wrote {n} -> {args.drive_dump}/")

    if args.drive:
        show = drive_items[: args.drive] if drive_items else g.drive_children(args.drive, path=drive_path)
        print()
        print_drive_list(show, path=drive_label)

    def show_onenote_page(page: dict | None, content: str | None = None) -> int:
        if not page:
            return 1
        pid = page.get("id")
        if content is None and pid:
            code, content = g.onenote_page_content(pid)
            if code != 200:
                print(f"[-] page content failed ({code}): {content[:200]}")
                return 1
        content = content or ""
        if args.save_onenote:
            save_onenote_page(page, content, Path(args.save_onenote))
            print(f"    saved -> {args.save_onenote}")
        print()
        print_onenote_page(page, content, full=args.full)
        return 0

    if args.onenote_page:
        page = g.onenote_page(args.onenote_page)
        if show_onenote_page(page):
            print(f"[-] onenote page not found: {args.onenote_page[:40]}...")
            return 1

    if args.onenote_index is not None:
        if args.onenote_index < 0 or args.onenote_index >= len(onenote_items):
            print(f"[-] onenote-index {args.onenote_index} out of range (have {len(onenote_items)})")
            return 1
        picked = onenote_items[args.onenote_index]
        page_list = onenote_list_label == "recent pages" or onenote_list_label.startswith("section:")
        if page_list:
            if show_onenote_page(g.onenote_page(picked["id"]) or picked):
                return 1
        else:
            print()
            print_onenote_list([picked], label=onenote_list_label)
            print(f"    id: {picked.get('id', '')}")

    if args.onenote_dump:
        if onenote_list_label.startswith("section:"):
            _, pages = g.onenote_pages(args.top, section_id=section_id)
        else:
            _, pages = g.onenote_pages(args.top)
        print(f"\n--- onenote-dump ---")
        n = dump_onenote_pages(g, Path(args.onenote_dump), pages[: args.top])
        print(f"    wrote {n} -> {args.onenote_dump}/")

    if args.notebooks and args.notebook_index is None and not notebook_id:
        show = onenote_items[: args.notebooks] if onenote_list_label == "notebooks" else g.onenote_notebooks(args.notebooks)
        print()
        print_onenote_list(show, label="notebooks")

    if notebook_id and not section_id:
        show = onenote_items if onenote_list_label.startswith("notebook:") else g.onenote_sections(notebook_id, 50)
        print()
        print_onenote_list(show, label=f"notebook {notebook_name or notebook_id[:32]}")

    if args.sections and not notebook_id and not section_id:
        show = onenote_items if onenote_list_label == "sections" else g.onenote_all_sections(args.sections)
        print()
        print_onenote_list(show, label="sections")

    if section_id:
        show = onenote_items if onenote_list_label.startswith("section:") else g.onenote_pages(50, section_id=section_id)[1]
        print()
        print_onenote_list(show, label=f"section {section_name or section_id[:32]}")
        if not show and onenote_pages_code != 200:
            print_onenote_pages_hint(onenote_pages_code)

    if args.onenote_pages and not section_id and args.onenote_index is None:
        if onenote_list_label == "recent pages":
            show = onenote_items[: args.onenote_pages]
            code = onenote_pages_code
        else:
            code, show = g.onenote_pages(args.onenote_pages)
        print()
        print_onenote_list(show, label="recent pages")
        if not show and code != 200:
            print_onenote_pages_hint(code)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
