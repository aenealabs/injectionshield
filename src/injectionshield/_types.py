"""Core types for injectionshield: risk levels, patterns, matches, and results."""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import List, Tuple


class RiskLevel(enum.IntEnum):
    """Ordered severity levels. Higher is more dangerous.

    Being an ``IntEnum`` means levels compare naturally::

        result.risk_level >= RiskLevel.HIGH
    """

    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# Map each level to a 0.0–1.0 score used for ``ScanResult.risk_score``.
SEVERITY_SCORE = {
    RiskLevel.SAFE: 0.0,
    RiskLevel.LOW: 0.25,
    RiskLevel.MEDIUM: 0.5,
    RiskLevel.HIGH: 0.75,
    RiskLevel.CRITICAL: 1.0,
}


@dataclass
class Pattern:
    """A single detection rule.

    Attributes:
        name: Unique identifier for the rule (e.g. ``"ignore_previous"``).
        pattern: The regular expression (matched case-insensitively by default).
        category: The threat category this rule belongs to.
        severity: How dangerous a match is.
        redact: Whether matched spans are replaced in ``ScanResult.sanitized``.
        flags: ``re`` flags used to compile ``pattern``.
    """

    name: str
    pattern: str
    category: str
    severity: RiskLevel
    redact: bool = True
    flags: int = re.IGNORECASE
    regex: "re.Pattern" = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.regex = re.compile(self.pattern, self.flags)


@dataclass
class Match:
    """A single rule match within scanned text."""

    name: str
    category: str
    severity: RiskLevel
    snippet: str
    span: Tuple[int, int]


@dataclass
class ScanResult:
    """The outcome of scanning a piece of text."""

    risk_score: float          # 0.0 (safe) → 1.0 (critical)
    risk_level: RiskLevel
    threats: List[str]         # distinct threat categories, sorted
    matched: List[Match]       # every individual rule match
    safe: bool                 # True if risk_level is below the threshold
    sanitized: str             # input with redactable matches replaced

    def __bool__(self) -> bool:
        # Truthy when the text is safe, so `if scan(x):` reads naturally.
        return self.safe

    def __repr__(self) -> str:
        return (
            f"ScanResult(safe={self.safe}, risk_level={self.risk_level.name}, "
            f"score={self.risk_score:.2f}, threats={self.threats})"
        )


class PatternSet:
    """An ordered, iterable collection of :class:`Pattern` rules."""

    def __init__(self, patterns: "List[Pattern] | None" = None) -> None:
        self._patterns: List[Pattern] = list(patterns) if patterns else []

    def add(self, pattern: Pattern) -> "PatternSet":
        self._patterns.append(pattern)
        return self

    def __iter__(self):
        return iter(self._patterns)

    def __len__(self) -> int:
        return len(self._patterns)

    def __add__(self, other: "PatternSet") -> "PatternSet":
        return PatternSet(self._patterns + list(other))
