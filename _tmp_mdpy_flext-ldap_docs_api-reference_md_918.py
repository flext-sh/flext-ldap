# from flext-ldap_docs/api-reference.md:918
from flext_ldap import OpenLDAP2Operations

ops = OpenLDAP2Operations()

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
        print(f"DN: {entry.dn}")```
______________________________________________________________________

### Server-Specific Implementations

#### OpenLDAP2Operations

Complete implementation for OpenLDAP 2.x (cn=settings style).

**Import:**

