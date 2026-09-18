# from flext-ldap_docs/guides/universal-ldap-guide.md:259
from __future__ import annotations

from flext_ldap import ldap
from flext_ldif import ldif


def migrate_openldap1_to_openldap2():
    # Parse OpenLDAP 1.x LDIF file
        parse_result = ldif.parse_file("openldap1_backup.ldif")

    if parse_result.failure:
        print(f"Parse failed: {parse_result.error}")
        return

    openldap1_entries = parse_result.unwrap()

    # Convert each entry to OpenLDAP 2.x format
    api = ldap()
    openldap2_entries = []

    for entry in openldap1_entries:
        convert_result = api.convert_entry_between_servers(
            entry=entry, source_server_type="openldap1", target_server_type="openldap2"
        )

        if convert_result.success:
            openldap2_entries.append(convert_result.unwrap())
        else:
            print(f"Conversion failed for {entry.dn}: {convert_result.error}")

    # Write converted entries to new LDIF
    write_result = ldif.write_file(openldap2_entries, "openldap2_converted.ldif")
    if write_result.success:
        print(f"Successfully converted {len(openldap2_entries)} entries")```
### Oracle OID → Oracle OUD Migration

