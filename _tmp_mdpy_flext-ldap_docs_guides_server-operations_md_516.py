# from flext-ldap_docs/guides/server-operations.md:516
from flext_ldap import GenericServerOperations

ops = GenericServerOperations()

# Works with any RFC-compliant LDAP server
connection = ldap3.Connection(
    ldap3.Server("ldap://unknown-ldap-server:389"),
    user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    password="password",
    auto_bind=True,
)

# Basic schema discovery
schema_result = ops.discover_schema(connection)
if schema_result.success:
    schema = schema_result.unwrap()
    print(f"Server type: {schema['server_type']}")  # "generic"

# Basic entry operations (should work on any server)
entry = FlextLdifModels.Entry(...)
add_result = ops.add_entry(connection, entry)

# Paged search (if supported by server)
search_result = ops.search_with_paging(
    connection,
    base_dn="dc=example,dc=com",
    search_filter="(objectClass=*)",
    page_size=100,
)```
### **Limitations**

- ACL operations return minimal support
- Schema discovery provides basic info only
- No server-specific optimizations
- Conservative capability detection

##

## 🔄 Entry Adapter Integration

All server operations integrate with the Entry Adapter for ldap3 ↔ ldif conversion:

