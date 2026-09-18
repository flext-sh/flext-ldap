# from flext-ldap/docs/guides/integration.md:790
from __future__ import annotations

from flext_ldap import FlextLdapEntryAdapter
from flext_ldap import OpenLDAP2Operations
import ldap3


def export_to_ldif():
    """Export LDAP entries to LDIF file."""
    adapter = FlextLdapEntryAdapter()
    ops = OpenLDAP2Operations()

    # Connect and search
    connection = ldap3.Connection(
        ldap3.Server("ldap://server:389"),
        user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        password="password",
        auto_bind=True,
    )

    # Paged search for large result sets
    search_result = ops.search_with_paging(
        connection,
        base_dn="ou=users,dc=example,dc=com",
        search_filter="(objectClass=person)",
        page_size=100,
    )

    if search_result.success:
        entries = search_result.unwrap()
        print(f"Found {len(entries)} entries")

        # Write to LDIF file
        write_result = adapter.write_entries_to_ldif_file(entries, "export.ldif")

        if write_result.success:
            print("Export completed successfully")
        else:
            print(f"Export failed: {write_result.error}")


run(export_to_ldif())```
### Server Servers Detection

Use ldif servers system for automatic server detection:

