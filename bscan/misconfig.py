from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import yaml

from .http import Client, Response


OnCheck = Optional[Callable[[str, bool], None]]


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str = "misconfig"
    evidence: str = ""
    url: Optional[str] = None
    refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Check:
    id: str
    title: str
    severity: str
    path: str = "/"
    method: str = "GET"
    match_any: List[Dict[str, Any]] = field(default_factory=list)
    match_all: List[Dict[str, Any]] = field(default_factory=list)
    refs: List[str] = field(default_factory=list)


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def _cond_matches(cond: Dict[str, Any], resp: Response) -> tuple[bool, str]:
    """Return (matched, short evidence string)."""
    if "status" in cond:
        want = _as_list(cond["status"])
        if resp.status in [int(x) for x in want]:
            return True, f"status={resp.status}"
        return False, ""
    if "not_status" in cond:
        want = _as_list(cond["not_status"])
        if resp.status not in [int(x) for x in want] and resp.status != 0:
            return True, f"status={resp.status}"
        return False, ""
    if "body_contains" in cond:
        needle = cond["body_contains"]
        if needle and needle in (resp.text or ""):
            return True, f"body contains {needle!r}"
        return False, ""
    if "body_regex" in cond:
        rx = re.compile(cond["body_regex"], re.I | re.S)
        m = rx.search(resp.text or "")
        if m:
            snippet = m.group(0)[:80]
            return True, f"body matches /{cond['body_regex']}/ → {snippet!r}"
        return False, ""
    if "header" in cond:
        name = cond["header"].lower()
        hv = next((v for k, v in resp.headers.items() if k.lower() == name), None)
        if hv is None:
            return False, ""
        if "value_contains" in cond:
            if cond["value_contains"].lower() in hv.lower():
                return True, f"{name}: {hv}"
            return False, ""
        if "value_regex" in cond:
            if re.search(cond["value_regex"], hv, re.I):
                return True, f"{name}: {hv}"
            return False, ""
        return True, f"{name}: {hv}"
    return False, ""


def _evaluate(check: Check, resp: Response) -> Optional[Finding]:
    evidence_bits: List[str] = []

    for cond in check.match_all:
        ok, ev = _cond_matches(cond, resp)
        if not ok:
            return None
        if ev:
            evidence_bits.append(ev)

    if check.match_any:
        any_ok = False
        for cond in check.match_any:
            ok, ev = _cond_matches(cond, resp)
            if ok:
                any_ok = True
                if ev:
                    evidence_bits.append(ev)
                break
        if not any_ok:
            return None

    return Finding(
        id=check.id,
        title=check.title,
        severity=check.severity,
        evidence="; ".join(evidence_bits) or f"matched on {check.path}",
        url=resp.url,
        refs=list(check.refs),
    )


def load_checks(path: Path) -> List[Check]:
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text()) or {}
    items = data.get("checks", [])
    return [Check(**item) for item in items]


def run_checks(
    client: Client,
    checks: List[Check],
    on_check: OnCheck = None,
) -> List[Finding]:
    findings: List[Finding] = []
    for c in checks:
        if c.method.upper() == "HEAD":
            resp = client.head(c.path)
        else:
            resp = client.get(c.path)
        fnd = _evaluate(c, resp)
        if on_check:
            on_check(c.id, fnd is not None)
        if fnd:
            findings.append(fnd)
    return findings


# ------------------ header + cookie audit ------------------

REQUIRED_HEADERS = {
    "strict-transport-security": ("BX-HDR-HSTS", "Strict-Transport-Security missing", "medium"),
    "content-security-policy":   ("BX-HDR-CSP",  "Content-Security-Policy missing",   "medium"),
    "x-frame-options":           ("BX-HDR-XFO",  "X-Frame-Options missing",           "low"),
    "x-content-type-options":    ("BX-HDR-XCTO", "X-Content-Type-Options missing",    "low"),
    "referrer-policy":           ("BX-HDR-REF",  "Referrer-Policy missing",           "low"),
}


def audit_headers(resp: Response) -> List[Finding]:
    findings: List[Finding] = []
    h = {k.lower(): v for k, v in resp.headers.items()}

    for name, (fid, title, sev) in REQUIRED_HEADERS.items():
        if name not in h:
            findings.append(Finding(
                id=fid, title=title, severity=sev, category="headers",
                evidence=f"no {name} on root response", url=resp.url,
            ))

    server = h.get("server", "")
    if re.search(r"\d", server):
        findings.append(Finding(
            id="BX-HDR-SERVER-VERSION",
            title=f"Server header leaks version: {server}",
            severity="low", category="headers",
            evidence=f"server: {server}", url=resp.url,
        ))

    if "x-powered-by" in h:
        findings.append(Finding(
            id="BX-HDR-POWERED-BY",
            title=f"X-Powered-By exposed: {h['x-powered-by']}",
            severity="low", category="headers",
            evidence=f"x-powered-by: {h['x-powered-by']}", url=resp.url,
        ))

    return findings


COOKIE_RX = re.compile(
    r"(?i)(?P<name>[A-Z0-9_]+)=[^;,]+(?P<attrs>[^,]*?)(?=,\s*[A-Z0-9_]+=|$)"
)


def audit_cookies(resp: Response) -> List[Finding]:
    """Audit Set-Cookie headers for Secure/HttpOnly/SameSite flags.

    Only flags cookies that look like Bitrix/PHP session cookies.
    """
    findings: List[Finding] = []
    raw = next(
        (v for k, v in resp.headers.items() if k.lower() == "set-cookie"),
        "",
    )
    if not raw:
        return findings

    for m in COOKIE_RX.finditer(raw):
        name = m.group("name")
        attrs = m.group("attrs").lower()
        if not (name.startswith("BITRIX_SM_") or name.upper() == "PHPSESSID"):
            continue
        missing = []
        if "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if missing:
            findings.append(Finding(
                id=f"BX-COOKIE-{name}",
                title=f"Cookie {name} missing: {', '.join(missing)}",
                severity="medium" if "Secure" in missing or "HttpOnly" in missing else "low",
                category="cookies",
                evidence=f"set-cookie: {name}; attrs={attrs.strip()}",
                url=resp.url,
            ))
    return findings
