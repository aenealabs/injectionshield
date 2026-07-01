# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| Older   | No        |

We support only the most recent released version. Please upgrade before reporting a vulnerability.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues privately through GitHub's [private vulnerability reporting](https://github.com/aenealabs/injectionshield/security/advisories/new): go to the repository's **Security** tab and click **Report a vulnerability**. This keeps the report confidential until a fix is released.

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- The injectionshield version and Python version affected

You can expect an acknowledgment within 48 hours and a resolution or mitigation plan within 14 days. We will credit you in the release notes unless you request otherwise.

## Scope and expectations

injectionshield is a **heuristic, rule-based first line of defense**, not a complete guarantee against prompt injection. Static regex rules catch known injection phrasings; a determined attacker can paraphrase around any fixed ruleset. Do not rely on it as your only control — combine it with least-privilege tool design and, for high-stakes flows, a model-based classifier.

Relevant reports include:
- **Bypasses** — realistic injection phrasings the default patterns miss (with a minimal example)
- **Catastrophic false positives** — benign inputs flagged as CRITICAL in a way that breaks real applications
- **ReDoS** — inputs that cause pathological regex backtracking in `_patterns.py`
- Supply-chain attacks via the package itself (we maintain zero dependencies to minimize this risk)
