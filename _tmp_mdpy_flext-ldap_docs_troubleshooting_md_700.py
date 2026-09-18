# from flext-ldap_docs/troubleshooting.md:700
from __future__ import annotations

import cProfile
import pstats
from flext_ldap import FlextLdapEntities
from flext_ldap.api import ldap


def profile_ldap_operations():
    """Profile LDAP operations for performance analysis."""
    api = ldap

    # Create multiple search requests
    search_request = FlextLdapEntities.SearchRequest(
        base_dn="dc=example,dc=com",
        filter_str="(objectClass=person)",
        scope="subtree",
        attributes=["uid", "cn", "mail"],
        size_limit=100,
    )

    # Perform multiple operations
    for _ in range(10):
        result = api.search_entries(search_request)
        if result.failure:
            print(f"Search failed: {result.error}")


def run_profiling():
    profiler = cProfile.Profile()
    profiler.enable()

    run(profile_ldap_operations())

    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats("cumulative")
    stats.print_stats(20)  # Top 20 functions


# Run profiling
run_profiling()```
______________________________________________________________________

## Getting Help

### Information to Include in Bug Reports

When reporting issues, include:

1. **Environment details:**

   - Python version
   - flext-ldap version
   - Operating system
   - LDAP server type and version

1. **Configuration:**

   - Sanitized configuration (no passwords)
   - Environment variables
   - Network setup (Docker, Kubernetes, etc.)

1. **Error details:**

   - Complete error messages
   - Stack traces
   - Relevant log output

1. **Reproduction steps:**

   - Minimal code example
   - Steps to reproduce
   - Expected vs actual behavior

### Diagnostic Information Collection

