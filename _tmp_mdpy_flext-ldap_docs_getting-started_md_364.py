# from flext-ldap_docs/getting-started.md:364
from __future__ import annotations

from flext_ldap import OpenLDAP2Operations
import ldap3


def discover_schema():
    """Discover schema from OpenLDAP 2.x server."""
    ops = OpenLDAP2Operations()

    connection = ldap3.Connection(
        ldap3.Server("ldap://server:389"),
        user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        password="password",
        auto_bind=True,
    )

    schema_result = ops.discover_schema(connection)
    if schema_result.success:
        schema = schema_result.unwrap()

        print(f"Object Classes: {len(schema['object_classes'])}")
        print(f"Attribute Types: {len(schema['attribute_types'])}")
        print(f"Syntaxes: {len(schema['syntaxes'])}")
        print(f"Server Type: {schema['server_type']}")


run(discover_schema())```
### **ACL Management**

Manage server-specific ACLs:

