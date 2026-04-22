from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional

from .http import Client, Response


OnProbe = Optional[Callable[[str, bool], None]]


COMMON_MODULES = [
    "main", "iblock", "catalog", "sale", "search", "forum", "blog",
    "socialnetwork", "bitrix24", "seo", "landing", "vote", "subscribe",
    "advertising", "statistic", "translate", "highloadblock", "crm",
    "tasks", "calendar", "im", "pull", "rest", "disk", "ui",
]

DEEP_MODULES = [
    "fileman", "perfmon", "security", "sender", "lists", "learning",
    "mobile", "voximplant", "intranet", "bizproc", "clouds", "mail",
]

_VERSION_IN_PHP_RE = re.compile(r"['\"]VERSION['\"]\s*=>\s*['\"]([0-9.]+)['\"]")
_VERSION_IN_JS_QS_RE = re.compile(r"/bitrix/js/([^/]+)/[^?\s]+\?v=([0-9.]+)", re.I)
_VERSION_IN_CSS_QS_RE = re.compile(r"/bitrix/css/([^/]+)/[^?\s]+\?v=([0-9.]+)", re.I)
_ASSET_MODULE_RE = re.compile(r"/bitrix/(?:js|css|modules)/([^/\"'?\\\s]+)/", re.I)

SOURCE_PRIORITY = {
    "version.php": 50,
    "js_qs": 40,
    "css_qs": 35,
    "asset_path": 30,
    "path_listing": 20,
    "path_403": 10,
    "": 0,
}


@dataclass
class Module:
    name: str
    version: Optional[str] = None
    source: str = ""
    evidence_url: Optional[str] = None


@dataclass
class ModuleScan:
    modules: List[Module] = field(default_factory=list)
    templates: List[str] = field(default_factory=list)
    components: List[str] = field(default_factory=list)

    def add(self, m: Module) -> None:
        for existing in self.modules:
            if existing.name == m.name:
                if _should_replace(existing, m):
                    existing.version = m.version
                    existing.source = m.source
                    existing.evidence_url = m.evidence_url
                return
        self.modules.append(m)


def _source_priority(name: str) -> int:
    return SOURCE_PRIORITY.get(name, 0)


def _should_replace(existing: Module, new: Module) -> bool:
    if bool(new.version) != bool(existing.version):
        return bool(new.version)
    if _source_priority(new.source) != _source_priority(existing.source):
        return _source_priority(new.source) > _source_priority(existing.source)
    return bool(new.evidence_url) and not existing.evidence_url


def _probe_module(client: Client, name: str) -> Optional[Module]:
    paths = [
        f"/bitrix/modules/{name}/install/version.php",
        f"/bitrix/modules/{name}/install/index.php",
        f"/bitrix/modules/{name}/",
    ]
    for p in paths:
        r = client.get(p)
        if r.status == 200:
            m = _VERSION_IN_PHP_RE.search(r.text or "")
            if m:
                return Module(name=name, version=m.group(1), source="version.php", evidence_url=r.url)
            return Module(name=name, source="path_listing", evidence_url=r.url)
        if r.status == 403:
            return Module(name=name, source="path_403", evidence_url=r.url)
    return None


def _scan_root_html(resp: Response, scan: ModuleScan) -> None:
    if not resp.text:
        return
    for m in _VERSION_IN_JS_QS_RE.finditer(resp.text):
        scan.add(Module(name=m.group(1), version=m.group(2), source="js_qs"))
    for m in _VERSION_IN_CSS_QS_RE.finditer(resp.text):
        scan.add(Module(name=m.group(1), version=m.group(2), source="css_qs"))
    for m in _ASSET_MODULE_RE.finditer(resp.text):
        scan.add(Module(name=m.group(1), source="asset_path"))
    for m in re.finditer(r"/bitrix/templates/([^/\"'?\s]+)/", resp.text):
        name = m.group(1)
        if name not in scan.templates and name != ".default":
            scan.templates.append(name)
    for m in re.finditer(r"/bitrix/components/([^/\"'?\s]+)/([^/\"'?\s]+)/", resp.text):
        ident = f"{m.group(1)}:{m.group(2)}"
        if ident not in scan.components:
            scan.components.append(ident)


def _candidate_names(scan: ModuleScan, candidates: Optional[Iterable[str]]) -> List[str]:
    names = set(candidates if candidates is not None else COMMON_MODULES)
    names.update(module.name for module in scan.modules)
    return sorted(names)


def scan_modules(
    client: Client,
    root_html: Optional[Response] = None,
    candidates: Optional[Iterable[str]] = None,
    workers: int = 8,
    on_probe: OnProbe = None,
) -> ModuleScan:
    scan = ModuleScan()
    if root_html is not None:
        _scan_root_html(root_html, scan)

    names = _candidate_names(scan, candidates)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_probe_module, client, n): n for n in names}
        for fut in as_completed(futures):
            name = futures[fut]
            m = fut.result()
            if m:
                scan.add(m)
            if on_probe:
                on_probe(name, m is not None)
    return scan
