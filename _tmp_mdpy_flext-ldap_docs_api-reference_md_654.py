# from flext-ldap_docs/api-reference.md:654
from flext_ldap import FlextLdapServersAdapter
from flext_ldap import OpenLDAP2Operations, OracleOIDOperations, OracleOUDOperations

servers = FlextLdapServersAdapter()

# Detect from entries
entries = [...]  # ldif entries from search
result = servers.detect_server_type_from_entries(entries)

if result.success:
    server_type = result.unwrap()

    # Select appropriate server operations
    if server_type == "openldap2":
        ops = OpenLDAP2Operations()
    elif server_type == "oid":
        ops = OracleOIDOperations()
    elif server_type == "oud":
        ops = OracleOUDOperations()```
#### `get_acl_attribute_name(server_type=None) -> p.Result[str]`

Get server-specific ACL attribute name.

**Parameters:**

- `server_type` (str, optional): Server type (uses detected if None)

**Returns:** r containing ACL attribute name

**ACL Attributes:**

- OpenLDAP 2.x: `"olcAccess"`
- OpenLDAP 1.x: `"access"`
- Oracle OID: `"orclaci"`
- Oracle OUD: `"ds-privilege-name"`
- Active Directory: `"nTSecurityDescriptor"`
- Generic: `"aci"`

#### `get_acl_format(server_type=None) -> p.Result[str]`

Get server-specific ACL format identifier.

#### `get_schema_subentry(server_type=None) -> p.Result[str]`

Get server-specific schema DN.

**Schema DNs:**

- OpenLDAP: `"cn=subschema"`
- Oracle OID: `"cn=subschemasubentry"`
- Oracle OUD: `"cn=schema"`
- Active Directory: `"cn=schema,cn=configuration"`

#### `get_max_page_size(server_type=None) -> p.Result[int]`

Get server-specific maximum page size for paged searches.

#### `normalize_entry_for_server(entry, server_type=None) -> p.Result[FlextLdifModels.Entry]`

Normalize entry for server-specific requirements.

______________________________________________________________________

## 🏗️ Server Operations

### BaseServerOperations

Abstract base class defining complete server operations interface.

**Import:**

