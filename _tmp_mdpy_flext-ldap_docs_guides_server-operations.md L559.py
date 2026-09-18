# from flext-ldap/docs/guides/server-operations.md:559
from flext_ldap import FlextLdapEntryAdapter
from flext_ldap import OpenLDAP2Operations

adapter = FlextLdapEntryAdapter()
ops = OpenLDAP2Operations()

# Search and convert to ldif
connection.search(base_dn, search_filter, attributes=attributes)
for ldap3_entry in connection.entries:
    # Convert ldap3 entry to ldif
    ldif_result = adapter.ldap3_to_ldif_entry(ldap3_entry)
    if ldif_result.success:
        ldif_entry = ldif_result.unwrap()

        # Process with ldif models
        print(f"DN: {ldif_entry.dn.value}")
        print(f"Attributes: {ldif_entry.attributes.attributes}")

# Create ldif entry and convert to ldap3
ldif_entry = FlextLdifModels.Entry(...)
attrs_result = adapter.ldif_entry_to_ldap3_attributes(ldif_entry)
if attrs_result.success:
    attributes = attrs_result.unwrap()
    # Use with server operations
    ops.add_entry(connection, ldif_entry)```
##

## 🔍 Servers Detection

Server type detection using ldif servers:

