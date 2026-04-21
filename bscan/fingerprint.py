from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .http import Client, Response


OnStep = Optional[Callable[[str], None]]


CONFIDENCE_SIGNALS = {
    "cookie_bitrix_sm": 40,
    "header_powered": 40,
    "meta_generator": 35,
    "path_bitrix_admin": 25,
    "path_bitrix_js": 20,
    "html_comment": 15,
    "robots_bitrix": 10,
}


@dataclass
class Fingerprint:
    is_bitrix: bool = False
    confidence: int = 0
    signals: List[str] = field(default_factory=list)
    core_version: Optional[str] = None
    main_module_version: Optional[str] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    generator: Optional[str] = None

    def add(self, signal: str) -> None:
        if signal in self.signals:
            return
        self.signals.append(signal)
        self.confidence += CONFIDENCE_SIGNALS.get(signal, 5)
        self.is_bitrix = self.confidence >= 20


_META_GEN_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)
_BITRIX_COMMENT_RE = re.compile(r"<!--\s*(?:BX|Bitrix)[^>]*-->", re.I)
_VERSION_IN_JS_RE = re.compile(r"BX\.message\(\s*\{\s*[^}]*VERSION\s*:\s*['\"]([0-9.]+)['\"]", re.I)
_CORE_JS_VERSION_RE = re.compile(r"['\"]?version['\"]?\s*:\s*['\"]([0-9.]+)['\"]", re.I)


def _scan_headers(resp: Response, fp: Fingerprint) -> None:
    h = {k.lower(): v for k, v in resp.headers.items()}
    if "server" in h:
        fp.server = h["server"]
    for key in ("x-powered-cms", "x-powered-by"):
        if key in h and "bitrix" in h[key].lower():
            fp.powered_by = h[key]
            fp.add("header_powered")
    set_cookie = h.get("set-cookie", "")
    if "BITRIX_SM_" in set_cookie:
        fp.add("cookie_bitrix_sm")


def _scan_html(resp: Response, fp: Fingerprint) -> None:
    if not resp.text:
        return
    m = _META_GEN_RE.search(resp.text)
    if m and "bitrix" in m.group(1).lower():
        fp.generator = m.group(1).strip()
        fp.add("meta_generator")
        vm = re.search(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", fp.generator)
        if vm and not fp.core_version:
            fp.core_version = vm.group(1)
    if _BITRIX_COMMENT_RE.search(resp.text):
        fp.add("html_comment")
    if "/bitrix/js/" in resp.text or "/bitrix/templates/" in resp.text:
        fp.add("path_bitrix_js")


def _probe_admin(client: Client, fp: Fingerprint) -> None:
    r = client.get("/bitrix/admin/index.php")
    if r.status in (200, 401, 403) or "bitrix" in r.text.lower()[:4096]:
        fp.add("path_bitrix_admin")


def _probe_core_js(client: Client, fp: Fingerprint) -> None:
    r = client.get("/bitrix/js/main/core/core.js")
    if r.status != 200 or len(r.text) < 1024:
        return
    fp.add("path_bitrix_js")
    for rx in (_VERSION_IN_JS_RE, _CORE_JS_VERSION_RE):
        m = rx.search(r.text[:50_000])
        if m:
            fp.main_module_version = m.group(1)
            break


def _probe_robots(client: Client, fp: Fingerprint) -> None:
    r = client.get("/robots.txt")
    if r.ok and "/bitrix/" in r.text.lower():
        fp.add("robots_bitrix")


def fingerprint(client: Client, on_step: OnStep = None) -> Fingerprint:
    fp = Fingerprint()

    def step(name: str) -> None:
        if on_step:
            on_step(name)

    step("GET /")
    root = client.get("/")
    _scan_headers(root, fp)
    if root.is_html:
        _scan_html(root, fp)

    step("GET /bitrix/js/main/core/core.js")
    _probe_core_js(client, fp)

    step("GET /bitrix/admin/index.php")
    _probe_admin(client, fp)

    step("GET /robots.txt")
    _probe_robots(client, fp)

    step("fingerprint done")
    return fp
