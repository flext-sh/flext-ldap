# from flext-ldap/docs/guides/integration.md:837
from __future__ import annotations

from flext_ldap import FlextLdapEntryAdapter
from flext_ldap import FlextLdapServersAdapter
from flext_ldap import OpenLDAP2Operations, OracleOIDOperations, OracleOUDOperations
import ldap3


def detect_and_configure():
    """Detect server type and configure operations accordingly."""
    connection = ldap3.Connection(
        ldap3.Server("ldap://server:389"),
        user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        password="password",
        auto_bind=True,
    )

    adapter = FlextLdapEntryAdapter()
    servers = FlextLdapServersAdapter()

    # Get root DSE and schema entries
    connection.search("", "(objectClass=*)", search_scope="BASE", attributes=["*", "+"])
    connection.search("cn=subschema", "(objectClass=*)", attributes=["*"])

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

        # Get server-specific configuration
        acl_attr_result = servers.get_acl_attribute_name(server_type)
        schema_dn_result = servers.get_schema_subentry(server_type)
        max_page_size_result = servers.get_max_page_size(server_type)

        if all(
            r.success for r in [acl_attr_result, schema_dn_result, max_page_size_result]
        ):
            print(f"ACL attribute: {acl_attr_result.unwrap()}")
            print(f"Schema DN: {schema_dn_result.unwrap()}")
            print(f"Max page size: {max_page_size_result.unwrap()}")

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

        return ops


run(detect_and_configure())```
### Universal LDAP Processor

Complete example combining ldif with server operations:

