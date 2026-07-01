---
name: Feature request
about: Suggest a new pattern, category, or behavior
labels: enhancement
---

## What problem does this solve?

Describe the use case, not the solution. What injection can't you catch today?

## Proposed solution

If you have a concrete idea, describe it. Include an example malicious input and a benign near-miss it must NOT flag:

```python
from injectionshield import scan
scan("malicious example")   # should be flagged
scan("benign near-miss")    # must stay safe
```

## Notes

- Does this require a new dependency? (It shouldn't — injectionshield has zero dependencies by design.)
- Is this a new pattern, a new category, or a scanner behavior change?
