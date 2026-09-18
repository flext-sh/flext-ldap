# from flext-ldap_docs/api-reference.md:774
from flext_ldap import OpenLDAP2Operations
import ldap3

ops = OpenLDAP2Operations()

connection = ldap3.Connection(
    ldap3.Server("ldap://server:389"),
    user="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
    password="password",
    auto_bind=True,
)

schema_result = ops.discover_schema(connection)
if schema_result.success:
    schema = schema_result.unwrap()
    print(f"Object classes: {len(schema['object_classes'])}")
    print(f"Attribute types: {len(schema['attribute_types'])}")```
##### `parse_object_class(object_class_def) -> p.Result[m.Dict]`

Parse objectClass definition string.

##### `parse_attribute_type(attribute_def) -> p.Result[m.Dict]`

Parse attributeType definition string.

#### ACL Operations

##### `get_acl_attribute_name() -> str`

Get ACL attribute name for server type.

##### `get_acl_format() -> str`

Get ACL format identifier.

##### `get_acls(connection, dn) -> p.Result[Sequence[m.Dict]]`

Retrieve ACLs from entry.

**Example:**

