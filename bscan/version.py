from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


VerTuple = Tuple[int, ...]

NEG_INF: VerTuple = (-1,)
POS_INF: VerTuple = (10**9,)


def parse_version(v: str) -> VerTuple:
    parts: List[int] = []
    for chunk in v.strip().split("."):
        try:
            parts.append(int(chunk))
        except ValueError:
            digits = "".join(ch for ch in chunk if ch.isdigit())
            parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _pad(a: VerTuple, b: VerTuple) -> Tuple[VerTuple, VerTuple]:
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)), b + (0,) * (n - len(b))


def cmp(a: str, b: str) -> int:
    ta, tb = _pad(parse_version(a), parse_version(b))
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


def in_range(version: str, spec: str) -> bool:
    spec = spec.strip()
    if spec in ("*", ""):
        return True
    for part in [p.strip() for p in spec.split(",") if p.strip()]:
        for op in ("<=", ">=", "<", ">", "==", "="):
            if part.startswith(op):
                other = part[len(op):].strip()
                c = cmp(version, other)
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
            if cmp(version, part) != 0:
                return False
    return True


@dataclass
class Range:
    """Inclusive version range. `lower`/`upper` as VerTuple, None = unbounded."""

    lower: Optional[VerTuple] = None
    upper: Optional[VerTuple] = None
    lower_inclusive: bool = True
    upper_inclusive: bool = True
    sources: List[str] = field(default_factory=list)

    @classmethod
    def parse(cls, spec: str, source: str = "") -> "Range":
        r = cls(sources=[source] if source else [])
        for part in [p.strip() for p in spec.split(",") if p.strip()]:
            for op in ("<=", ">=", "<", ">", "==", "="):
                if part.startswith(op):
                    v = parse_version(part[len(op):].strip())
                    if op == ">=":
                        r.lower, r.lower_inclusive = _merge_lower(
                            r.lower, r.lower_inclusive, v, True
                        )
                    elif op == ">":
                        r.lower, r.lower_inclusive = _merge_lower(
                            r.lower, r.lower_inclusive, v, False
                        )
                    elif op == "<=":
                        r.upper, r.upper_inclusive = _merge_upper(
                            r.upper, r.upper_inclusive, v, True
                        )
                    elif op == "<":
                        r.upper, r.upper_inclusive = _merge_upper(
                            r.upper, r.upper_inclusive, v, False
                        )
                    elif op in ("=", "=="):
                        r.lower = v
                        r.upper = v
                        r.lower_inclusive = True
                        r.upper_inclusive = True
                    break
        return r

    def intersect(self, other: "Range") -> "Range":
        out = Range(
            lower=self.lower,
            upper=self.upper,
            lower_inclusive=self.lower_inclusive,
            upper_inclusive=self.upper_inclusive,
            sources=list(self.sources) + list(other.sources),
        )
        if other.lower is not None:
            if out.lower is None or _gt(other.lower, out.lower):
                out.lower = other.lower
                out.lower_inclusive = other.lower_inclusive
            elif _eq(other.lower, out.lower):
                out.lower_inclusive = out.lower_inclusive and other.lower_inclusive
        if other.upper is not None:
            if out.upper is None or _lt(other.upper, out.upper):
                out.upper = other.upper
                out.upper_inclusive = other.upper_inclusive
            elif _eq(other.upper, out.upper):
                out.upper_inclusive = out.upper_inclusive and other.upper_inclusive
        return out

    @property
    def is_empty(self) -> bool:
        if self.lower is None or self.upper is None:
            return False
        if _gt(self.lower, self.upper):
            return True
        if _eq(self.lower, self.upper) and not (self.lower_inclusive and self.upper_inclusive):
            return True
        return False

    def format(self) -> str:
        if self.is_empty:
            return "<empty>"
        lo = _fmt(self.lower) if self.lower is not None else None
        hi = _fmt(self.upper) if self.upper is not None else None
        if lo is not None and hi is not None and _eq(self.lower, self.upper):
            return lo
        parts: List[str] = []
        if lo is not None:
            parts.append(f"{'>=' if self.lower_inclusive else '>'}{lo}")
        if hi is not None:
            parts.append(f"{'<=' if self.upper_inclusive else '<'}{hi}")
        return ",".join(parts) if parts else "*"


def _fmt(t: VerTuple) -> str:
    return ".".join(str(x) for x in t)


def _eq(a: VerTuple, b: VerTuple) -> bool:
    pa, pb = _pad(a, b)
    return pa == pb


def _lt(a: VerTuple, b: VerTuple) -> bool:
    pa, pb = _pad(a, b)
    return pa < pb


def _gt(a: VerTuple, b: VerTuple) -> bool:
    pa, pb = _pad(a, b)
    return pa > pb


def _merge_lower(
    current: Optional[VerTuple],
    current_inclusive: bool,
    candidate: VerTuple,
    candidate_inclusive: bool,
) -> tuple[VerTuple, bool]:
    if current is None or _gt(candidate, current):
        return candidate, candidate_inclusive
    if _eq(candidate, current):
        return current, current_inclusive and candidate_inclusive
    return current, current_inclusive


def _merge_upper(
    current: Optional[VerTuple],
    current_inclusive: bool,
    candidate: VerTuple,
    candidate_inclusive: bool,
) -> tuple[VerTuple, bool]:
    if current is None or _lt(candidate, current):
        return candidate, candidate_inclusive
    if _eq(candidate, current):
        return current, current_inclusive and candidate_inclusive
    return current, current_inclusive
