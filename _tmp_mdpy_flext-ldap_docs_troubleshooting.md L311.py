# from flext-ldap/docs/troubleshooting.md:311
from __future__ import annotations

from flext_ldap import FlextLdapEntities
from flext_ldap.api import ldap


def diagnose_base_dn():
    api = ldap

    # Search from root to find available bases
    search_request = FlextLdapEntities.SearchRequest(
        base_dn="dc=example,dc=com",
        filter_str="(objectClass=*)",
        scope="onelevel",  # Only immediate children
        attributes=["dn", "objectClass"],
    )

    result = api.search_entries(search_request)
    if result.success:
        entries = result.unwrap()
        print("Available organizational units:")
        for entry in entries:
            print(f"  {entry.dn}")
    else:
        print(f"Root search failed: {result.error}")


run(diagnose_base_dn())```
______________________________________________________________________

## Performance Issues

### Slow Search Operations

**Symptoms:**

- Long response times for directory searches
- Timeout errors on large result sets

**Diagnosis:**

