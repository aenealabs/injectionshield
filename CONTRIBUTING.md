# Contributing to injectionshield

Thank you for taking the time to contribute.

## Ground rules

- **Zero external dependencies.** injectionshield must remain pure Python stdlib. PRs that introduce any third-party import will not be merged.
- **Python 3.9+.** All code must run on Python 3.9 through the latest stable release.
- **Tests required.** Every new feature or bug fix must include a corresponding test. The CI matrix runs on 3 operating systems × 5 Python versions — please run tests locally before opening a PR.
- **Keep it focused.** injectionshield does one thing: detect prompt injection with rules. Feature requests outside that scope belong in a separate package.

## Setting up a development environment

```bash
git clone https://github.com/aenealabs/injectionshield
cd injectionshield
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running tests

```bash
pytest tests/ -v
```

To run against a specific Python version, use `hatch`:

```bash
pip install hatch
hatch run test
```

## Architecture

injectionshield is small and layered — read the modules in this order:

1. `src/injectionshield/_types.py` — `RiskLevel`, `Pattern`, `Match`, `ScanResult`, `PatternSet`.
2. `src/injectionshield/_patterns.py` — the built-in pattern library (grouped by category).
3. `src/injectionshield/_scanner.py` — `scan`, `scan_batch`, `scan_tool_result`, scoring, and redaction.
4. `src/injectionshield/__init__.py` — the public surface.

## Adding a pattern

1. Add the `Pattern` to the right category block in `_patterns.py`, with a unique `name`, an appropriate `severity`, and `redact` set correctly.
2. **Add two tests** in `tests/test_patterns.py`: a true positive (a realistic malicious phrasing it should catch) **and** a benign near-miss it must *not* flag. False-positive resistance matters as much as detection.
3. Prefer specific rules over broad ones — require activation/roleplay framing rather than matching a bare noun (e.g. "enable developer mode", not any mention of "developer mode").
4. Watch for catastrophic backtracking (ReDoS): avoid nested quantifiers over the same class.

## Submitting a pull request

1. Fork the repository and create a branch: `git checkout -b fix/my-fix` or `feat/my-feature`.
2. Make your changes and add tests.
3. Run `pytest tests/ -v` — all tests must pass.
4. Open a pull request against `main` with a clear description of what changed and why.

## Reporting bugs

Open an issue using the **Bug report** template. Include the Python version, OS, and the exact text that was (or wasn't) flagged.

## Suggesting features

Open an issue using the **Feature request** template. Explain the use case, not just the solution.

## Code style

injectionshield uses no formatter or linter by choice to keep contributor setup minimal. Please follow the style of the surrounding code: 4-space indentation, descriptive variable names, module-level docstrings on every file.
