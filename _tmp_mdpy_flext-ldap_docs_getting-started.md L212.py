# from flext-ldap/docs/getting-started.md:212
from __future__ import annotations

from flext_ldap import FlextLdapEntities
from flext_ldap.api import ldap


def basic_search():
    """Perform a basic directory search."""
    api = ldap

    search_request = FlextLdapEntities.SearchRequest(
        base_dn="dc=example,dc=com",
        filter_str="(objectClass=organizationalUnit)",
        scope="subtree",
        attributes=["ou", "description"],
    )

    result = api.search_entries(search_request)
    if result.success:
        entries = result.unwrap()
        print(f"Found {len(entries)} organizational units:")
        for entry in entries:
            print(f"  - {entry.ou}: {entry.description}")
    else:
        print(f"Search failed: {result.error}")


run(basic_search())```
### **User Authentication**

