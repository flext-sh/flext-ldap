# from flext-ldap_docs/guides/universal-ldap-guide.md:296
from __future__ import annotations


def migrate_oid_to_oud():
    api = ldap()

    # Load OID entries
    oid_entries = ldif.parse_file("oid_export.ldif").unwrap()

    # Convert to OUD format
    oud_entries = []
    for entry in oid_entries:
        # Convert orclaci ACLs to ds-privilege-name
        convert_result = api.convert_entry_between_servers(
            entry=entry, source_server_type="oid", target_server_type="oud"
        )

        if convert_result.success:
            oud_entry = convert_result.unwrap()

            # Validate for OUD
            validation_result = api.validate_entry_for_server(oud_entry, "oud")
            if validation_result.success and validation_result.unwrap():
                oud_entries.append(oud_entry)
            else:
                print(f"Validation failed: {validation_result.error}")

    # Export to OUD-compatible LDIF
    ldif.write_file(oud_entries, "oud_import.ldif")```
## Migration Scenarios

### Scenario 1: Multi-Server Environment

