# from flext-ldap_docs/api-reference.md:726
**Server Implementations:**

- `OpenLDAP2Operations` - OpenLDAP 2.x (cn=settings, olcAccess ACLs)
- `OpenLDAP1Operations` - OpenLDAP 1.x (slapd.conf, access ACLs)
- `OracleOIDOperations` - Oracle Internet Directory (orclaci ACLs)
- `OracleOUDOperations` - Oracle Unified Directory (ds-privilege-name ACLs)
- `ActiveDirectoryOperations` - Active Directory (stub implementation)
- `GenericServerOperations` - Generic RFC-compliant LDAP server

#### Connection Operations

##### `get_default_port(use_ssl=False) -> int`

Get default port for server type.

**Returns:**

- 389 for standard LDAP
- 636 for LDAPS

##### `supports_start_tls() -> bool`

Check if server supports START_TLS.

##### `get_bind_mechanisms() -> t.StringList`

Get supported BIND mechanisms (SIMPLE, SASL/EXTERNAL, etc.).

#### Schema Operations

##### `get_schema_dn() -> str`

Get schema discovery DN for server type.

##### `discover_schema(connection) -> p.Result[m.Dict]`

Discover schema from server.

**Returns:** r containing schema data:

- `object_classes`: List of objectClass definitions
- `attribute_types`: List of attributeType definitions
- `syntaxes`: List of LDAP syntax definitions
- `server_type`: Detected server type

**Example:**

