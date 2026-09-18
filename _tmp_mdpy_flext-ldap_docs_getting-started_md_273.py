# from flext-ldap_docs/getting-started.md:273
from __future__ import annotations

import ldap3
from flext_ldap import FlextLdapEntryAdapter
from flext_ldap import FlextLdapServersAdapter
from flext_ldap import OpenLDAP2Operations, OracleOIDOperations


def server_specific_operations():
    """Use server-specific operations with automatic detection."""
    # Connect to LDAP server
    connection = ldap3.Connection(
        ldap3.Server("ldap://server:389"),
        user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        password="password",
        auto_bind=True,
    )

    # Initialize adapters
    adapter = FlextLdapEntryAdapter()
    servers = FlextLdapServersAdapter()

    # Search for entries
    connection.search("dc=example,dc=com", "(objectClass=*)", attributes=["*"])

    # Convert to ldif
    entries = []
    for ldap3_entry in connection.entries:
        result = adapter.ldap3_to_ldif_entry(ldap3_entry)
        if result.success:
            entries.append(result.unwrap())

    # Detect server type
    server_type_result = servers.detect_server_type_from_entries(entries)
    if server_type_result.success:
        server_type = server_type_result.unwrap()
        print(f"Detected server: {server_type}")

        # Select appropriate operations
        if server_type == "openldap2":
            ops = OpenLDAP2Operations()
        elif server_type == "oid":
            ops = OracleOIDOperations()
        else:
            from flext_ldap import GenericServerOperations

            ops = GenericServerOperations()

        # Discover schema
        schema_result = ops.discover_schema(connection)
        if schema_result.success:
            schema = schema_result.unwrap()
            print(f"Object classes: {len(schema['object_classes'])}")


run(server_specific_operations())```
### **Entry Conversion (ldap3 ↔ ldif)**

Convert between ldap3 and ldif entry formats:

