# from flext-ldap/docs/guides/universal-ldap-guide.md:330
from __future__ import annotations

from flext_ldap import ldap


def sync_across_servers():
    """Sync entries across different LDAP server types."""
    # Source: OpenLDAP 2.x
    source_api = ldap()
    source_api.connect()  # Connects to OpenLDAP 2.x

    # Target: Oracle OUD
    target_api = ldap()
    target_api.connect()  # Connects to Oracle OUD

    # Search source
    search_result = source_api.search_universal(
        base_dn="ou=users,dc=company,dc=com", filter_str="(objectClass=inetOrgPerson)"
    )

    if search_result.success:
        source_entries = search_result.unwrap()

        for entry in source_entries:
            # Detect source server type
            source_type = source_api.get_detected_server_type().unwrap()

            # Detect target server type
            target_type = target_api.get_detected_server_type().unwrap()

            # Convert entry format
            convert_result = source_api.convert_entry_between_servers(
                entry=entry,
                source_server_type=source_type,
                target_server_type=target_type,
            )

            if convert_result.success:
                converted_entry = convert_result.unwrap()

                # Add to target server
                target_api.add_entry(
                    str(converted_entry.dn), converted_entry.attributes.attributes
                )```
### Scenario 2: Progressive Migration

