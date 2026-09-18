# from flext-ldap_examples/README.md:805
from __future__ import annotations

# Pattern 1: Check before unwrap
result = api.search(...)
if result.is_failure:
    logger.error(f"Failed: {result.error}")
    return

entries = result.unwrap()


# Pattern 2: Early return
def process():
    result = api.search(...)
    if result.is_failure:
        return r.fail(f"Search failed: {result.error}")

    entries = result.unwrap()
    return r.ok(entries)
