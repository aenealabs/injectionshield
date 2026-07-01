# Changelog

All notable changes to injectionshield are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-01

### Added
- `scan(text, threshold=RiskLevel.MEDIUM, extra_patterns=None)` — rule-based prompt-injection scan returning a `ScanResult`
- `scan_batch(texts, ...)` and `scan_tool_result(tool_name, content, ...)` convenience wrappers
- `ScanResult` — `risk_score` (worst-match-wins), `risk_level`, `threats`, `matched`, `safe`, `sanitized`
- `RiskLevel` ordered enum (SAFE/LOW/MEDIUM/HIGH/CRITICAL) and `Match`, `Pattern`, `PatternSet` for custom rules
- Built-in `DEFAULT_PATTERNS` library across six threat categories: `instruction_override`, `data_exfiltration`, `role_confusion`, `jailbreak_persona`, `pii_extraction`, `indirect_injection` (HTML-comment injection, `system:` role prefixes, zero-width obfuscation)
- Redaction: matched spans replaced with `[REDACTED: <category>]` in `ScanResult.sanitized`
- Zero external dependencies — pure Python stdlib (3.9+), no ML, no network
- 18 unit tests covering per-category detection, false-positive resistance, scoring, thresholds, redaction, and custom patterns

[Unreleased]: https://github.com/aenealabs/injectionshield/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/aenealabs/injectionshield/releases/tag/v0.1.0
