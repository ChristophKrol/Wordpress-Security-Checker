"""Version comparison for the range notation VulLink stores (">=1.0 <2.3", "<=4.1", "*").

Tolerant by design: WordPress plugin versions are not strict semver ("1.2", "1.2.3.4", "2.0-beta").
Numeric parts compare numerically; a text suffix sorts before the plain release (1.0-beta < 1.0).
"""
from __future__ import annotations

import re
from typing import Iterable, List, Optional, Tuple

_TOKEN = re.compile(r"\d+|[A-Za-z]+")


def _key(version: str) -> Tuple:
    nums: List[int] = []
    rest = version.strip().lower()
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", rest)
    if m:
        nums = [int(x) for x in m.group(1).split(".")]
        rest = m.group(2)
    while len(nums) < 4:
        nums.append(0)
    suffix = tuple(int(t) if t.isdigit() else t for t in _TOKEN.findall(rest))
    # (0, suffix) for pre-releases sorts before (1,) for a plain release
    return tuple(nums) + ((0,) + suffix if suffix else (1,),)


def compare(a: str, b: str) -> int:
    ka, kb = _key(a), _key(b)
    try:
        return (ka > kb) - (ka < kb)
    except TypeError:  # mixed int/str suffix tokens: fall back to string comparison
        sa, sb = str(ka), str(kb)
        return (sa > sb) - (sa < sb)


def in_range(version: str, range_expr: str) -> bool:
    expr = range_expr.strip()
    if expr in ("*", ""):
        return True
    for cond in expr.split():
        m = re.match(r"^(>=|<=|>|<|=)?(.+)$", cond)
        if not m:
            return False
        op, bound = m.group(1) or "=", m.group(2)
        c = compare(version, bound)
        ok = {">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0, "=": c == 0}[op]
        if not ok:
            return False
    return True


def is_affected(version: str, ranges: Iterable[str], exact: Iterable[str]) -> Optional[bool]:
    """True/False when the data allows a decision, None when there is no version data at all."""
    ranges, exact = list(ranges or []), list(exact or [])
    if not ranges and not exact:
        return None
    return any(compare(version, e) == 0 for e in exact) or any(in_range(version, r) for r in ranges)
