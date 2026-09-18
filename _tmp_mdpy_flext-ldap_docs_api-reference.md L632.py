# from flext-ldap/docs/api-reference.md:632
#### `detect_server_type_from_entries(entries) -> p.Result[str]`

Detect LDAP server type from entry analysis.

**Parameters:**

- `entries`: List of FlextLdifModels.Entry objects

**Returns:** r containing server type string

**Server Types:**

- `"openldap2"` - OpenLDAP 2.x (cn=settings)
- `"openldap1"` - OpenLDAP 1.x (legacy)
- `"oid"` - Oracle Internet Directory
- `"oud"` - Oracle Unified Directory
- `"ad"` - Active Directory
- `"generic"` - Generic LDAP server

**Example:**

