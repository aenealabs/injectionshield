"""The scanner: match patterns, score risk, and sanitize.

``scan`` is stateless and thread-safe — all patterns are pre-compiled and the
function holds no mutable state.
"""

from __future__ import annotations

from typing import List, Optional

from ._patterns import DEFAULT_PATTERNS
from ._types import Match, PatternSet, RiskLevel, ScanResult, SEVERITY_SCORE


def _redact(text: str, matches: List[Match]) -> str:
    """Replace redactable match spans with ``[REDACTED: <category>]``.

    Overlapping spans are merged; the merged region is labeled with the
    highest-severity category it contains.
    """
    spans = [(m.span[0], m.span[1], m.category, m.severity) for m in matches]
    if not spans:
        return text
    spans.sort()

    merged: List[list] = []
    for start, end, category, severity in spans:
        if merged and start <= merged[-1][1]:
            prev = merged[-1]
            prev[1] = max(prev[1], end)
            if severity > prev[3]:
                prev[2], prev[3] = category, severity
        else:
            merged.append([start, end, category, severity])

    out: List[str] = []
    cursor = 0
    for start, end, category, _severity in merged:
        out.append(text[cursor:start])
        out.append(f"[REDACTED: {category}]")
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def scan(
    text: str,
    threshold: RiskLevel = RiskLevel.MEDIUM,
    extra_patterns: "Optional[PatternSet]" = None,
) -> ScanResult:
    """Scan ``text`` for prompt-injection patterns.

    Args:
        text: The input to scan.
        threshold: The text is considered unsafe when its risk level reaches
            (or exceeds) this level. Defaults to ``RiskLevel.MEDIUM``.
        extra_patterns: Additional rules to apply on top of the built-ins.

    Returns:
        A :class:`ScanResult`. ``risk_score`` reflects the highest-severity
        match (worst-match-wins — a security detector should not dilute a
        critical finding by averaging).
    """
    if not text:
        return ScanResult(0.0, RiskLevel.SAFE, [], [], True, text)

    patterns = DEFAULT_PATTERNS if extra_patterns is None else DEFAULT_PATTERNS + extra_patterns

    matches: List[Match] = []
    for pattern in patterns:
        for m in pattern.regex.finditer(text):
            snippet = m.group(0)
            matches.append(
                Match(
                    name=pattern.name,
                    category=pattern.category,
                    severity=pattern.severity,
                    snippet=snippet,
                    span=m.span(),
                )
            )

    if not matches:
        return ScanResult(0.0, RiskLevel.SAFE, [], [], True, text)

    risk_level = max(m.severity for m in matches)
    risk_score = SEVERITY_SCORE[risk_level]
    threats = sorted({m.category for m in matches})
    safe = risk_level < threshold

    # Only redactable patterns contribute to the sanitized output.
    redactable = [m for m in matches if _pattern_redacts(patterns, m.name)]
    sanitized = _redact(text, redactable)

    return ScanResult(
        risk_score=risk_score,
        risk_level=risk_level,
        threats=threats,
        matched=matches,
        safe=safe,
        sanitized=sanitized,
    )


def _pattern_redacts(patterns: PatternSet, name: str) -> bool:
    for p in patterns:
        if p.name == name:
            return p.redact
    return True


def scan_batch(
    texts: List[str],
    threshold: RiskLevel = RiskLevel.MEDIUM,
    extra_patterns: "Optional[PatternSet]" = None,
) -> List[ScanResult]:
    """Scan many texts, returning one :class:`ScanResult` per input (in order)."""
    return [scan(t, threshold=threshold, extra_patterns=extra_patterns) for t in texts]


def scan_tool_result(
    tool_name: str,
    content: str,
    threshold: RiskLevel = RiskLevel.MEDIUM,
    extra_patterns: "Optional[PatternSet]" = None,
) -> ScanResult:
    """Scan untrusted content returned by a tool (web page, document, DB row).

    A thin convenience wrapper around :func:`scan` for the indirect-injection
    case — where the risk is adversarial text embedded in fetched content. The
    ``tool_name`` is accepted for call-site clarity and future per-tool rules.
    """
    return scan(content, threshold=threshold, extra_patterns=extra_patterns)
