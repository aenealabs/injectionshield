## Summary

What does this PR do? Reference any related issues: `Fixes #123`

## Changes

- 
- 

## Testing

- [ ] New tests added (or existing tests updated) for all changed behavior
- [ ] `pytest tests/ -v` passes locally
- [ ] No third-party imports introduced (zero-dependency contract)
- [ ] Tested on Python 3.9 (lowest supported version)

## Pattern changes (if applicable)

If this PR adds or changes a detection pattern, confirm:

- [ ] A true-positive test (realistic malicious phrasing it catches)
- [ ] A benign near-miss test (similar text it must NOT flag)
- [ ] No catastrophic backtracking (ReDoS) risk in the regex

## Notes for reviewers

Anything that needs extra attention or context?
