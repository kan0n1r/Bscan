from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .version import cmp as _cmp, in_range as _in_range


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
