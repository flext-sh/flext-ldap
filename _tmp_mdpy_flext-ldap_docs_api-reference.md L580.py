# from flext-ldap/docs/api-reference.md:580
from flext_ldif import FlextLdifModels
from flext_ldap import FlextLdapEntryAdapter

adapter = FlextLdapEntryAdapter()

# Create ldif entry
ldif_entry = FlextLdifModels.Entry(
    dn=FlextLdifModels.DN(value="cn=test,dc=example,dc=com"),
    attributes=FlextLdifModels.Attributes(
        attributes={
            "objectClass": ["person", "organizationalPerson"],
            "cn": ["test"],
            "sn": ["Test User"],
        }
    ),
)

# Convert to ldap3 attributes
result = adapter.ldif_entry_to_ldap3_attributes(ldif_entry)
if result.success:
    attributes = result.unwrap()
    connection.add(str(ldif_entry.dn), attributes=attributes)```
#### `convert_ldif_file_to_entries(ldif_file_path) -> p.Result[List[FlextLdifModels.Entry]]`

Load and convert LDIF file to ldif entries.

**Parameters:**

- `ldif_file_path` (str): Path to LDIF file

**Returns:** r containing list of entries

#### `write_entries_to_ldif_file(entries, output_path) -> p.Result[bool]`

Write ldif entries to LDIF file.

**Parameters:**

- `entries`: List of FlextLdifModels.Entry
- `output_path` (str): Output file path

**Returns:** r indicating success

______________________________________________________________________

### FlextLdapServersAdapter

Server detection and servers system integration using ldif.

**Import:**

