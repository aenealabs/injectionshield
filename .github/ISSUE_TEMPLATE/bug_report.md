---
name: Bug report
about: A missed injection, a false positive, or something else not working
labels: bug
---

## Type

- [ ] Bypass — malicious text the scanner missed
- [ ] False positive — benign text flagged as unsafe
- [ ] Other

## The text

```
Paste the exact input you scanned.
```

## What happened vs. expected

```python
from injectionshield import scan
r = scan("...")
r.safe        # what you got:
r.threats     # what you got:
# what you expected:
```

## Environment

- injectionshield version:
- Python version:
- OS:
