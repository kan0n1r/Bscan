from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml


@dataclass
class Vuln:
    id: str
    title: str
    target: str
    severity: str = "unknown"
    cve: Optional[str] = None
    fixed_in: Optional[str] = None
    affected: Optional[str] = None
    refs: List[str] = field(default_factory=list)


@dataclass
class Match:
    vuln: Vuln
    detected_version: Optional[str]


def _parse_version(v: str) -> tuple:
    parts = []
    for chunk in v.split("."):
        try:
            parts.append(int(chunk))
        except ValueError:
            digits = "".join(ch for ch in chunk if ch.isdigit())
            parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _cmp(a: str, b: str) -> int:
    ta, tb = _parse_version(a), _parse_version(b)
    length = max(len(ta), len(tb))
    ta = ta + (0,) * (length - len(ta))
    tb = tb + (0,) * (length - len(tb))
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


def _in_range(version: str, spec: str) -> bool:
    spec = spec.strip()
    if spec in ("*", ""):
        return True
    for part in [p.strip() for p in spec.split(",") if p.strip()]:
        for op in ("<=", ">=", "<", ">", "==", "="):
            if part.startswith(op):
                other = part[len(op):].strip()
                c = _cmp(version, other)
                if op == "<" and not c < 0:
                    return False
                if op == "<=" and not c <= 0:
                    return False
                if op == ">" and not c > 0:
                    return False
                if op == ">=" and not c >= 0:
                    return False
                if op in ("==", "=") and c != 0:
                    return False
                break
        else:
            if _cmp(version, part) != 0:
                return False
    return True


class VulnDB:
    def __init__(self, vulns: List[Vuln]) -> None:
        self._by_target: Dict[str, List[Vuln]] = {}
        for v in vulns:
            self._by_target.setdefault(v.target, []).append(v)

    @classmethod
    def load(cls, path: Path) -> "VulnDB":
        if not path.exists():
            return cls([])
        data = yaml.safe_load(path.read_text()) or {}
        items = data.get("vulns", [])
        vulns = [Vuln(**item) for item in items]
        return cls(vulns)

    def match(self, target: str, version: Optional[str]) -> List[Match]:
        out: List[Match] = []
        for v in self._by_target.get(target, []):
            if version is None:
                continue
            if v.affected and _in_range(version, v.affected):
                out.append(Match(vuln=v, detected_version=version))
                continue
            if v.fixed_in and _cmp(version, v.fixed_in) < 0:
                out.append(Match(vuln=v, detected_version=version))
        return out
