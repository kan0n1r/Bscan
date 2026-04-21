from __future__ import annotations

import re
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml

from .http import Client, Response
from .version import Range


OnProbe = Optional[Callable[[str, bool], None]]


@dataclass
class EndpointProbe:
    id: str
    path: str
    implies: str
    when_status: Optional[int] = None
    when_status_any: List[int] = field(default_factory=list)
    when_body_contains: Optional[str] = None


@dataclass
class ErrorPageMatcher:
    markers: List[str]
    implies: str


@dataclass
class CookieRule:
    id: str
    cookie: str
    implies: str


@dataclass
class HeaderRule:
    id: str
    header: str
    value_regex: Optional[str] = None
    value_contains: Optional[str] = None
    implies: str = ""


@dataclass
class BehaviorConfig:
    probes: List[EndpointProbe] = field(default_factory=list)
    errorpage_path: str = "/bitrix/__bscan_${rand}"
    errorpage_matchers: List[ErrorPageMatcher] = field(default_factory=list)
    cookie_rules: List[CookieRule] = field(default_factory=list)
    header_rules: List[HeaderRule] = field(default_factory=list)

    @property
    def total_probes(self) -> int:
        return len(self.probes) + (1 if self.errorpage_matchers else 0)


@dataclass
class BehaviorResult:
    range: Optional[str] = None
    constraints: List[Dict[str, str]] = field(default_factory=list)
    matched_probes: List[str] = field(default_factory=list)
    errorpage_markers: List[str] = field(default_factory=list)
    is_empty: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def load_config(path: Path) -> BehaviorConfig:
    if not path.exists():
        return BehaviorConfig()
    data = yaml.safe_load(path.read_text()) or {}

    probes = [EndpointProbe(**p) for p in data.get("probes", [])]
    ep = data.get("errorpage") or {}
    ep_path = ep.get("path", "/bitrix/__bscan_${rand}")
    ep_matchers = [ErrorPageMatcher(**m) for m in ep.get("fingerprints", [])]
    cookie_rules = [CookieRule(**c) for c in data.get("cookies", [])]
    header_rules = [HeaderRule(**h) for h in data.get("headers", [])]
    return BehaviorConfig(
        probes=probes,
        errorpage_path=ep_path,
        errorpage_matchers=ep_matchers,
        cookie_rules=cookie_rules,
        header_rules=header_rules,
    )


def _probe_matches(probe: EndpointProbe, resp: Response) -> bool:
    if probe.when_status is not None:
        if resp.status != probe.when_status:
            return False
    if probe.when_status_any:
        if resp.status not in probe.when_status_any:
            return False
    if probe.when_body_contains:
        if probe.when_body_contains not in (resp.text or ""):
            return False
    return probe.when_status is not None or probe.when_status_any or probe.when_body_contains is not None


def _check_cookie_rules(root: Response, rules: List[CookieRule]) -> List[tuple[str, str]]:
    set_cookie = next((v for k, v in root.headers.items() if k.lower() == "set-cookie"), "")
    out: List[tuple[str, str]] = []
    for r in rules:
        if r.cookie in set_cookie:
            out.append((r.id, r.implies))
    return out


def _check_header_rules(root: Response, rules: List[HeaderRule]) -> List[tuple[str, str]]:
    lowered = {k.lower(): v for k, v in root.headers.items()}
    out: List[tuple[str, str]] = []
    for r in rules:
        hv = lowered.get(r.header.lower())
        if hv is None:
            continue
        if r.value_contains and r.value_contains.lower() not in hv.lower():
            continue
        if r.value_regex and not re.search(r.value_regex, hv, re.I):
            continue
        out.append((r.id, r.implies))
    return out


def _match_errorpage(resp: Response, matchers: List[ErrorPageMatcher]) -> tuple[List[str], List[str]]:
    """Return (matched_marker_labels, implied_specs)."""
    labels: List[str] = []
    implies: List[str] = []
    body = resp.text or ""
    for m in matchers:
        if all(marker in body for marker in m.markers):
            labels.append(" + ".join(m.markers))
            implies.append(m.implies)
    return labels, implies


def run_behavior(
    client: Client,
    config: BehaviorConfig,
    root: Optional[Response] = None,
    on_probe: OnProbe = None,
) -> BehaviorResult:
    constraints: List[Dict[str, str]] = []
    matched: List[str] = []

    ranges: List[Range] = []

    for probe in config.probes:
        resp = client.get(probe.path)
        hit = _probe_matches(probe, resp)
        if on_probe:
            on_probe(probe.id, hit)
        if hit:
            matched.append(probe.id)
            constraints.append({"source": probe.id, "implies": probe.implies})
            ranges.append(Range.parse(probe.implies, source=probe.id))

    ep_markers: List[str] = []
    if config.errorpage_matchers:
        rand = secrets.token_hex(4)
        path = config.errorpage_path.replace("${rand}", rand)
        resp = client.get(path)
        if on_probe:
            on_probe("errorpage", resp.status in (404, 403, 500, 200))
        labels, implied = _match_errorpage(resp, config.errorpage_matchers)
        for label, spec in zip(labels, implied):
            ep_markers.append(label)
            constraints.append({"source": f"errorpage[{label}]", "implies": spec})
            ranges.append(Range.parse(spec, source="errorpage"))

    if root is not None:
        for rid, spec in _check_cookie_rules(root, config.cookie_rules):
            matched.append(rid)
            constraints.append({"source": rid, "implies": spec})
            ranges.append(Range.parse(spec, source=rid))
        for rid, spec in _check_header_rules(root, config.header_rules):
            matched.append(rid)
            constraints.append({"source": rid, "implies": spec})
            ranges.append(Range.parse(spec, source=rid))

    if not ranges:
        return BehaviorResult(
            range=None,
            constraints=constraints,
            matched_probes=matched,
            errorpage_markers=ep_markers,
            is_empty=False,
        )

    combined = ranges[0]
    for r in ranges[1:]:
        combined = combined.intersect(r)

    return BehaviorResult(
        range=combined.format(),
        constraints=constraints,
        matched_probes=matched,
        errorpage_markers=ep_markers,
        is_empty=combined.is_empty,
    )
