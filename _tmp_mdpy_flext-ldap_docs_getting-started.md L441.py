# from flext-ldap/docs/getting-started.md:441
from __future__ import annotations

from flext_ldap import OpenLDAP2Operations
import ldap3


def paged_search():
    """Execute paged search with automatic pagination."""
    ops = OpenLDAP2Operations()

    connection = ldap3.Connection(
        ldap3.Server("ldap://server:389"),
        user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        password="password",
        auto_bind=True,
    )

    result = ops.search_with_paging(
        connection,
        base_dn="ou=users,dc=example,dc=com",
        search_filter="(objectClass=person)",
        attributes=["uid", "cn", "mail"],
        page_size=100,
    )

    if result.success:
        entries = result.unwrap()
        print(f"Found {len(entries)} entries")
        for entry in entries:
            print(f"  DN: {entry.dn}")


run(paged_search())```
______________________________________________________________________

## Development Environment

### **Test LDAP Server Setup**

For development and testing, use Docker:

