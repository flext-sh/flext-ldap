# from flext-ldap_docs/guides/integration.md:747
from __future__ import annotations

from flext_ldap import FlextLdapEntryAdapter
from flext_ldap import OpenLDAP2Operations


def process_ldif_file():
    """Process LDIF file and import to LDAP server."""
    adapter = FlextLdapEntryAdapter()
    ops = OpenLDAP2Operations()

    # Load LDIF file
    result = adapter.convert_ldif_file_to_entries("users.ldif")
    if result.failure:
        print(f"Failed to load LDIF: {result.error}")
        return

    entries = result.unwrap()
    print(f"Loaded {len(entries)} entries from LDIF")

    # Connect to LDAP server
    connection = ldap3.Connection(
        ldap3.Server("ldap://server:389"),
        user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        password="password",
        auto_bind=True,
    )

    # Import entries
    for entry in entries:
        add_result = ops.add_entry(connection, entry)
        if add_result.success:
            print(f"Added: {entry.dn}")
        else:
            print(f"Failed to add {entry.dn}: {add_result.error}")


run(process_ldif_file())```
### Export to LDIF

Export LDAP entries to LDIF format:

