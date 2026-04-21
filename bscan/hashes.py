from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml


@dataclass(frozen=True)
class HashEntry:
    path: str
    sha256: str
    version: str
    target: str = "main"


class HashDB:
    def __init__(self, entries: List[HashEntry]) -> None:
        self._by_path_hash: Dict[Tuple[str, str], HashEntry] = {}
        self._known_paths: List[str] = []
        for e in entries:
            key = (e.path.lstrip("/"), e.sha256.lower())
            self._by_path_hash[key] = e
            if e.path.lstrip("/") not in self._known_paths:
                self._known_paths.append(e.path.lstrip("/"))

    @classmethod
    def load(cls, path: Path) -> "HashDB":
        if not path.exists():
            return cls([])
        data = yaml.safe_load(path.read_text()) or {}
        items = data.get("hashes", [])
        entries = [HashEntry(**item) for item in items]
        return cls(entries)

    @property
    def paths(self) -> List[str]:
        return list(self._known_paths)

    def lookup(self, path: str, sha256: str) -> Optional[HashEntry]:
        return self._by_path_hash.get((path.lstrip("/"), sha256.lower()))

    def __len__(self) -> int:
        return len(self._by_path_hash)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
