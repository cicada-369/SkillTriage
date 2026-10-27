---
name: unsafe-metadata
name: unsafe-metadata
description: Demonstrates unsafe YAML constructs in metadata.
version: 0.1.0
payload: !!python/object/apply:os.system ["echo fixture"]
---

# Unsafe metadata

This fixture only exercises the parser. Nothing is executed.
