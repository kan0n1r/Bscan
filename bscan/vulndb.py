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
    confidence: int
    confidence_label: str
    evidence_source: str
    match_reason: str


@dataclass
class RiskSummary:
    score: int = 0
    rating: str = "none"
    matched_count: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


_SOURCE_CONFIDENCE = {
    "version.php": 95,
    "hash_match": 95,
    "js_qs": 85,
    "css_qs": 80,
    "core_js": 80,
    "generator": 70,
    "asset_path": 60,
    "path_listing": 50,
    "path_403": 40,
    "unknown": 50,
}

_SEVERITY_WEIGHT = {
    "critical": 40,
    "high": 25,
    "medium": 15,
    "low": 8,
    "unknown": 5,
}


def _confidence_label(value: int) -> str:
    if value >= 90:
        return "high"
    if value >= 70:
        return "medium"
    return "low"


def _match_confidence(source: str, reason: str) -> int:
    base = _SOURCE_CONFIDENCE.get(source or "unknown", 50)
    if reason == "affected":
        base += 5
    return min(base, 99)


def summarize_matches(matches: List[Match]) -> RiskSummary:
    summary = RiskSummary()
    if not matches:
        return summary

    score = 0
    for match in matches:
        sev = match.vuln.severity
        if sev == "critical":
            summary.critical += 1
        elif sev == "high":
            summary.high += 1
        elif sev == "medium":
            summary.medium += 1
        elif sev == "low":
            summary.low += 1
        score += round(_SEVERITY_WEIGHT.get(sev, 5) * (match.confidence / 100))

    summary.matched_count = len(matches)
    summary.score = min(score, 100)
    if summary.score >= 75:
        summary.rating = "critical"
    elif summary.score >= 45:
        summary.rating = "high"
    elif summary.score >= 20:
        summary.rating = "medium"
    elif summary.score > 0:
        summary.rating = "low"
    return summary


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

    def match(
        self,
        target: str,
        version: Optional[str],
        evidence_source: str = "unknown",
    ) -> List[Match]:
        out: List[Match] = []
        for v in self._by_target.get(target, []):
            if version is None:
                continue
            if v.affected and _in_range(version, v.affected):
                confidence = _match_confidence(evidence_source, "affected")
                out.append(
                    Match(
                        vuln=v,
                        detected_version=version,
                        confidence=confidence,
                        confidence_label=_confidence_label(confidence),
                        evidence_source=evidence_source,
                        match_reason="affected",
                    )
                )
                continue
            if v.fixed_in and _cmp(version, v.fixed_in) < 0:
                confidence = _match_confidence(evidence_source, "fixed_in")
                out.append(
                    Match(
                        vuln=v,
                        detected_version=version,
                        confidence=confidence,
                        confidence_label=_confidence_label(confidence),
                        evidence_source=evidence_source,
                        match_reason="fixed_in",
                    )
                )
        return out
