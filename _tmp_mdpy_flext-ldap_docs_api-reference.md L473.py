# from flext-ldap/docs/api-reference.md:473
from flext_ldap import e

try:
    result = api.search_entries(request)
    if result.failure:
        # Handle r error
        print(f"Search failed: {result.error}")
except e.ConnectionError as e:
    print(f"Connection error: {e.message}")```
______________________________________________________________________

## 🔄 r Usage

All API methods return `r[T]` for consistent error handling.

### Success Handling

