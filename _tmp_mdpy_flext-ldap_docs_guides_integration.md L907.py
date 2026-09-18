# from flext-ldap/docs/guides/integration.md:907
from __future__ import annotations

from flext_ldap import FlextLdapEntryAdapter
from flext_ldap import FlextLdapServersAdapter
from flext_ldap import (
    OpenLDAP2Operations,
    OracleOIDOperations,
    OracleOUDOperations,
    GenericServerOperations,
)
import ldap3


class UniversalLdapProcessor:
    """Universal LDAP processor with ldif integration."""

    def __init__(self, host: str, bind_dn: str, bind_password: str):
        self.host = host
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.adapter = FlextLdapEntryAdapter()
        self.servers = FlextLdapServersAdapter()
        self.ops = None
        self.connection = None

    def connect(self):
        """Connect and detect server type."""
        self.connection = ldap3.Connection(
            ldap3.Server(self.host),
            user=self.bind_dn,
            password=self.bind_password,
            auto_bind=True,
        )

        # Detect server type
        self.connection.search(
            "", "(objectClass=*)", search_scope="BASE", attributes=["*"]
        )

        entries = []
        for ldap3_entry in self.connection.entries:
            result = self.adapter.ldap3_to_ldif_entry(ldap3_entry)
            if result.success:
                entries.append(result.unwrap())

        server_type_result = self.servers.detect_server_type_from_entries(entries)
        if server_type_result.success:
            server_type = server_type_result.unwrap()

            # Select operations
            if server_type == "openldap2":
                self.ops = OpenLDAP2Operations()
            elif server_type == "oid":
                self.ops = OracleOIDOperations()
            elif server_type == "oud":
                self.ops = OracleOUDOperations()
            else:
                self.ops = GenericServerOperations()

            return server_type

    def search_and_export(self, base_dn: str, filter_str: str, output_file: str):
        """Search LDAP and export to LDIF."""
        if not self.ops:
            raise Exception("Not connected")

        # Paged search
        search_result = self.ops.search_with_paging(
            self.connection, base_dn=base_dn, search_filter=filter_str, page_size=100
        )

        if search_result.failure:
            raise Exception(f"Search failed: {search_result.error}")

        entries = search_result.unwrap()

        # Write to LDIF
        write_result = self.adapter.write_entries_to_ldif_file(entries, output_file)

        if write_result.failure:
            raise Exception(f"Export failed: {write_result.error}")

        return len(entries)

    def import_ldif(self, ldif_file: str, base_dn: str):
        """Import LDIF file to LDAP."""
        if not self.ops:
            raise Exception("Not connected")

        # Load LDIF
        load_result = self.adapter.convert_ldif_file_to_entries(ldif_file)
        if load_result.failure:
            raise Exception(f"Load failed: {load_result.error}")

        entries = load_result.unwrap()

        # Import entries
        success_count = 0
        for entry in entries:
            add_result = self.ops.add_entry(self.connection, entry)
            if add_result.success:
                success_count += 1

        return success_count


# Usage
def main():
    processor = UniversalLdapProcessor(
        host="ldap://server:389",
        bind_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        bind_password="password",
    )

    server_type = processor.connect()
    print(f"Connected to {server_type} server")

    # Export to LDIF
    count = processor.search_and_export(
        base_dn="ou=users,dc=example,dc=com",
        filter_str="(objectClass=person)",
        output_file="users_export.ldif",
    )
    print(f"Exported {count} entries")

    # Import from LDIF
    imported = processor.import_ldif(
        ldif_file="users_import.ldif", base_dn="ou=users,dc=example,dc=com"
    )
    print(f"Imported {imported} entries")


run(main())```
______________________________________________________________________

## Monitoring and Observability

### Prometheus Metrics

