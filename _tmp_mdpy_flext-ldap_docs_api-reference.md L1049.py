# from flext-ldap/docs/api-reference.md:1049
from __future__ import annotations

import ldap3
from flext_ldap import FlextLdapEntryAdapter
from flext_ldap import FlextLdapServersAdapter
from flext_ldap import OpenLDAP2Operations, OracleOIDOperations, OracleOUDOperations


def universal_ldap_example():
    """Complete example using universal LDAP interface."""
    # Setup connection
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
        elif server_type == "oud":
            ops = OracleOUDOperations()
        else:
            from flext_ldap import GenericServerOperations

            ops = GenericServerOperations()

        # Discover schema
        schema_result = ops.discover_schema(connection)
        if schema_result.success:
            schema = schema_result.unwrap()
            print(f"Schema: {len(schema['object_classes'])} object classes")

        # Get ACLs
        acl_attr = servers.get_acl_attribute_name(server_type).unwrap()
        print(f"ACL attribute: {acl_attr}")

        # Paged search
        paged_result = ops.search_with_paging(
            connection,
            base_dn="dc=example,dc=com",
            search_filter="(objectClass=person)",
            page_size=100,
        )
        if paged_result.success:
            paged_entries = paged_result.unwrap()
            print(f"Paged search: {len(paged_entries)} entries")


run(universal_ldap_example())```
______________________________________________________________________

For more examples and advanced usage patterns, see:

- **Examples** - Working code examples
- **Server Operations Guide** - Server-specific usage
- **Integration Guide** - FLEXT ecosystem integration
- **Architecture Guide** - Understanding the design

## Related Documentation

**Within Project**:

- Getting Started - Installation and basic usage
- Architecture - Architecture and design patterns
- Configuration - Configuration options
- Examples - Working code examples

**Across Projects**:

- [flext-core Foundation](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-core/docs/api-reference/foundation.md) - Core APIs and patterns
- [flext-ldif Processing](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-ldif/docs/api-reference.md) - LDIF processing API
- [flext-meltano Pipelines](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-meltano/AGENTS.md) - Data integration and ELT orchestration

**External Resources**:

- [RFC 4511 - LDAP: The Protocol](https://www.rfc-editor.org/rfc/rfc4511.html)
- [RFC 4512 - LDAP: Technical Specification Road Map](https://www.rfc-editor.org/rfc/rfc4512.html)

______________________________________________________________________

**Next:** Configuration Guide →
