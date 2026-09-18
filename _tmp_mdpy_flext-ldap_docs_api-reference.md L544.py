# from flext-ldap/docs/api-reference.md:544
from flext_ldap import FlextLdapEntryAdapter

adapter = FlextLdapEntryAdapter()

# Search with ldap3
connection.search("dc=example,dc=com", "(objectClass=person)")

for ldap3_entry in connection.entries:
    # Convert to ldif
    result = adapter.ldap3_to_ldif_entry(ldap3_entry)
    if result.success:
        ldif_entry = result.unwrap()
        print(f"DN: {ldif_entry.dn}")```
#### `ldap3_entries_to_ldif_entries(ldap3_entries) -> p.Result[List[FlextLdifModels.Entry]]`

Batch convert multiple ldap3 entries to ldif entries.

**Parameters:**

- `ldap3_entries`: List of ldap3.Entry objects

**Returns:** r containing list of FlextLdifModels.Entry

#### `ldif_entry_to_ldap3_attributes(ldif_entry) -> p.Result[Mapping[str, t.List]]`

Convert ldif entry to ldap3 attributes dictionary.

**Parameters:**

- `ldif_entry`: FlextLdifModels.Entry to convert

**Returns:** r containing attributes t.JsonMapping for ldap3 operations

**Example:**

